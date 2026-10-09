package network

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/avhn/fortix/internal/session"
)

// TestNativePreLinkRecovery clears a resource-free native intent left before device
// creation. It does not require a process identity or execute any networking command.
func TestNativePreLinkRecovery(t *testing.T) {
	m, r := nativeManager(t, "linux")
	j := Journal{Profile: "work", Attempt: 1, Backend: "native"}
	if err := m.Recover(context.Background(), j); err != nil || len(r.base.calls) != 0 {
		t.Fatalf("pre-link native intent did not recover: %v", err)
	}
}

// TestNativePartialConfiguration resumes Linux activation after a successful address
// assignment, without issuing another address add or changing negotiated metadata.
func TestNativePartialConfiguration(t *testing.T) {
	m, r := nativeManager(t, "linux")
	p := nativeProfile("work")
	e, j := nativeAttempt(t, m, p, 0)
	r.base.fail = "link set"
	if err := m.ConfigureNative(context.Background(), e, &j, ignoreJournal); err == nil || r.links[e.Interface].local != e.LocalIP {
		t.Fatalf("partial configuration not modeled: %v", err)
	}
	r.base.fail = ""
	calls := len(r.base.calls)
	if err := m.ConfigureNative(context.Background(), e, &j, ignoreJournal); err != nil || r.links[e.Interface].mtu != e.MTU {
		t.Fatalf("partial configuration did not resume: %v", err)
	}
	for _, call := range r.base.calls[calls:] {
		if slices.Contains(call, "addr") {
			t.Fatalf("repeated native address add: %v", call)
		}
	}
}

// TestNativeAddressDiscoveryFailure retains cleanup ownership on a failed kernel read.
// Discovery failure must not be mistaken for a definite link replacement or deletion.
func TestNativeAddressDiscoveryFailure(t *testing.T) {
	m, r := nativeManager(t, "linux")
	p := nativeProfile("work")
	e, j := configuredNative(t, m, p, 0)
	if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
		t.Fatal(err)
	}
	fresh := freshNativeManager(t, m)
	fresh.verifyInterface = func(string, netip.Addr) error { return errors.New("kernel discovery unavailable") }
	before := slices.Clone(r.base.routes)
	if err := fresh.Recover(context.Background(), j); err == nil || !slices.Equal(before, r.base.routes) {
		t.Fatalf("kernel discovery failed open: %v", err)
	}
}

// TestNativeSameLinkRouteRace proves a rejected add cannot claim an externally added
// identical destination even when the racing route uses the registered native link.
func TestNativeSameLinkRouteRace(t *testing.T) {
	m, r := nativeManager(t, "linux")
	p := nativeProfile("work")
	p.Routes.Include = []string{"10.20.0.0/16"}
	e, j := configuredNative(t, m, p, 0)
	r.rejectCIDR, r.rejectErr = "10.20.0.0/16", &CommandError{Stderr: "permission denied"}
	r.racingRoute = JournalRoute{CIDR: r.rejectCIDR, Interface: e.Interface}
	var conflict *ConflictError
	if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); !errors.As(err, &conflict) || len(j.Routes) != 0 || !slices.Contains(r.base.routes, r.racingRoute) {
		t.Fatalf("failed add claimed same-link route: %v %+v", err, j)
	}
}

// TestNativePostAddConflict detects a competing live destination even after an add
// succeeded. Rollback removes the genuinely added native route, never the competitor
// or the kernel-connected peer route created by address configuration.
func TestNativePostAddConflict(t *testing.T) {
	m, r := nativeManager(t, "linux")
	p := nativeProfile("work")
	p.Routes.Include = []string{"10.20.0.0/16"}
	e, j := configuredNative(t, m, p, 0)
	foreign := JournalRoute{CIDR: "10.20.0.0/16", Interface: "en0"}
	inserted := false
	r.before = func(args []string) {
		if args[0] == "-j" && !inserted && slices.ContainsFunc(r.base.routes, func(route JournalRoute) bool { return route.CIDR == foreign.CIDR && route.Interface == e.Interface }) {
			r.base.routes = append(r.base.routes, foreign)
			inserted = true
		}
	}
	var conflict *ConflictError
	if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); !errors.As(err, &conflict) || len(j.Routes) != 0 || !slices.Contains(r.base.routes, foreign) || len(r.base.routes) != 3 {
		t.Fatalf("post-add route conflict escaped: %v %+v", err, r.base.routes)
	}
}

// FuzzNativeRoutePolicy exercises canonical-prefix validation and mode selection only.
// No manager, command runner or host network access is used by this fuzz target.
func FuzzNativeRoutePolicy(f *testing.F) {
	for _, prefix := range []string{"10.20.0.0/16", "0.0.0.0/0", "128.0.0.0/1", "10.20.1.2/16", "::/0", "invalid"} {
		f.Add(prefix, uint8(0))
		f.Add(prefix, uint8(1))
		f.Add(prefix, uint8(2))
	}
	f.Fuzz(func(t *testing.T, text string, mode uint8) {
		p := nativeProfile("work")
		p.Routes.Mode = []string{"custom", "gateway", "full"}[mode%3]
		if p.Routes.Mode != "custom" {
			p.Routes.Include = nil
		}
		prefix, _ := netip.ParsePrefix(text)
		prefixes, err := negotiatedPrefixes(p, session.Effect{PushedPrefixes: []netip.Prefix{prefix}})
		if err != nil {
			return
		}
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			t.Fatal("invalid negotiated prefix accepted")
		}
		for _, selected := range prefixes {
			if !selected.IsValid() || !selected.Addr().Is4() || selected != selected.Masked() || (p.Routes.Mode == "gateway" && selected.Bits() <= 1) {
				t.Fatal("invalid route selected")
			}
		}
	})
}
