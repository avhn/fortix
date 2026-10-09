package network

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// freshNativeManager models a restarted manager using the same injected kernel/table.
// No attempt reservations or in-memory gateway references survive construction.
func freshNativeManager(t *testing.T, m *Manager) *Manager {
	t.Helper()
	fresh, err := New(Options{OS: m.os, Paths: m.paths, Runner: m.runner, Subnets: m.subnets, VerifyInterface: m.verifyInterface, InterfaceIndex: m.interfaceIndex, LinkExists: m.linkExists})
	if err != nil {
		t.Fatal(err)
	}
	return fresh
}

// TestNativeFullRoutes checks owned /1 routes and a typed gateway host exception through
// the original physical next hop. Host intent and installation precede split defaults;
// cleanup preserves the physical default and kernel-connected peer route.
func TestNativeFullRoutes(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, r := nativeManager(t, platform)
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: "full"}
			e, j := configuredNative(t, m, p, 0)
			baseline := slices.Clone(r.base.routes)
			j.GatewayIP = "203.0.113.5"
			durable := journalSnapshot(t, j)
			r.before = func(args []string) {
				if !slices.Contains(args, "add") {
					return
				}
				if durable.GatewayException == nil || durable.GatewayException.Route.Interface != "en0" || durable.GatewayException.Route.Gateway != "192.0.2.1" || !durable.GatewayException.Owned {
					t.Fatalf("gateway missing durable physical path: %v %+v", args, durable)
				}
				if slices.Contains(args, "0.0.0.0/1") || slices.Contains(args, "128.0.0.0/1") {
					if !slices.ContainsFunc(r.base.routes, func(route JournalRoute) bool { return route.CIDR == "203.0.113.5/32" && route.Interface == "en0" }) {
						t.Fatal("split default preceded gateway exception")
					}
				}
			}
			if err := m.Apply(context.Background(), p, e, &j, func(updated Journal) error { durable = journalSnapshot(t, updated); return nil }); err != nil {
				t.Fatal(err)
			}
			r.before = nil
			if len(j.Routes) != 2 || j.Routes[0].CIDR != "0.0.0.0/1" || j.Routes[1].CIDR != "128.0.0.0/1" || j.GatewayException == nil || len(r.base.routes) != len(baseline)+3 {
				t.Fatalf("full route ownership: %+v table=%+v", j, r.base.routes)
			}
			if err := m.Teardown(context.Background(), j); err != nil || !slices.Equal(r.base.routes, baseline) {
				t.Fatalf("full route cleanup: %v %+v", err, r.base.routes)
			}
		})
	}
}

// TestGatewaySharing holds the physical host exception across a full tunnel and a split
// tunnel whose negotiated route contains the TLS peer. The first stop removes only its
// defaults; only the last reference deletes the host route.
// Kernel-connected peers on both links survive every helper-owned resource release.
func TestGatewaySharing(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, r := nativeManager(t, platform)
			full := nativeProfile("work")
			full.Routes = profile.Routes{Mode: "full"}
			e, first := configuredNative(t, m, full, 0)
			first.GatewayIP = "203.0.113.5"
			if err := m.Apply(context.Background(), full, e, &first, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			other := nativeProfile("other")
			other.Routes = profile.Routes{Mode: "gateway"}
			secondEffect, second := configuredNative(t, m, other, 1)
			baseline := []JournalRoute{r.base.routes[0], r.base.routes[1], r.base.routes[len(r.base.routes)-1]}
			secondEffect.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
			second.GatewayIP = first.GatewayIP
			if err := m.Apply(context.Background(), other, secondEffect, &second, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			if *first.GatewayException != *second.GatewayException || len(m.gateways["203.0.113.5/32"].owners) != 2 {
				t.Fatal("host exception was not shared")
			}
			if err := m.Teardown(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			if len(r.base.routes) != len(baseline)+2 || !slices.ContainsFunc(r.base.routes, func(route JournalRoute) bool { return route.CIDR == "203.0.113.5/32" }) {
				t.Fatalf("first stop removed shared host path: %+v", r.base.routes)
			}
			if err := m.Teardown(context.Background(), first); err != nil || len(r.base.routes) != len(baseline)+2 {
				t.Fatalf("repeated release lost another reference: %v", err)
			}
			if err := m.Teardown(context.Background(), second); err != nil || !slices.Equal(r.base.routes, baseline) || len(m.gateways) != 0 {
				t.Fatalf("last reference leaked: %v %+v", err, r.base.routes)
			}
		})
	}
}

// TestGatewayBorrowingAndReplacement preserves a preexisting physical host route and
// replacement routes or reused physical links. None can be claimed by a full tunnel.
func TestGatewayBorrowingAndReplacement(t *testing.T) {
	for _, scenario := range []string{"borrowed", "changed gateway", "reused physical index"} {
		t.Run(scenario, func(t *testing.T) {
			m, r := nativeManager(t, "linux")
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: "full"}
			e, j := configuredNative(t, m, p, 0)
			j.GatewayIP = "203.0.113.5"
			if scenario == "borrowed" {
				r.base.routes = append(r.base.routes, JournalRoute{CIDR: "203.0.113.5/32", Gateway: "192.0.2.1", Interface: "en0"})
			}
			if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			if scenario == "borrowed" && j.GatewayException.Owned {
				t.Fatal("preexisting host route claimed")
			}
			for i := range r.base.routes {
				if scenario == "changed gateway" && r.base.routes[i].CIDR == "203.0.113.5/32" {
					r.base.routes[i].Gateway = "192.0.2.99"
				}
			}
			if scenario == "reused physical index" {
				r.links["en0"].index++
			}
			if err := m.Teardown(context.Background(), j); err != nil || len(r.base.routes) != 3 {
				t.Fatalf("foreign physical path removed: %v %+v", err, r.base.routes)
			}
		})
	}
}

// TestNativeFullFailures exercises missing gateway metadata, competing defaults,
// gateway EEXIST races and partial default installation. Every rejected add stays unowned.
func TestNativeFullFailures(t *testing.T) {
	for _, scenario := range []string{"missing gateway", "competing split default", "gateway race", "partial defaults"} {
		t.Run(scenario, func(t *testing.T) {
			m, r := nativeManager(t, "linux")
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: "full"}
			e, j := configuredNative(t, m, p, 0)
			if scenario != "missing gateway" {
				j.GatewayIP = "203.0.113.5"
			}
			switch scenario {
			case "competing split default":
				r.base.routes = append(r.base.routes, JournalRoute{CIDR: "0.0.0.0/1", Interface: "en0"})
			case "gateway race":
				r.rejectCIDR = "203.0.113.5/32"
				r.racingRoute = JournalRoute{CIDR: r.rejectCIDR, Gateway: "192.0.2.99", Interface: "en0"}
				r.rejectErr = &CommandError{Stderr: "RTNETLINK answers: File exists"}
			case "partial defaults":
				r.rejectCIDR = "128.0.0.0/1"
				r.racingRoute = JournalRoute{CIDR: r.rejectCIDR, Interface: "en0"}
				r.rejectErr = &CommandError{Stderr: "File exists"}
			}
			err := m.Apply(context.Background(), p, e, &j, ignoreJournal)
			var conflict *ConflictError
			if err == nil || (scenario != "missing gateway" && !errors.As(err, &conflict)) || len(j.Routes) != 0 || j.GatewayException != nil {
				t.Fatalf("failed full tunnel claimed resources: %v %+v", err, j)
			}
			for _, route := range r.base.routes {
				if route.Interface == e.Interface && route.CIDR != netip.PrefixFrom(e.PeerIP, 32).String() {
					t.Fatalf("partial default leaked: %+v", r.base.routes)
				}
			}
			if r.racingRoute.CIDR != "" && !slices.Contains(r.base.routes, r.racingRoute) {
				t.Fatal("racing route removed by rollback")
			}
		})
	}
}

// TestNativeFullWithSplits preserves explicit negotiated split routes in full mode.
// Absence of split routes alone triggers the helper's two-default installation.
func TestNativeFullWithSplits(t *testing.T) {
	m, r := nativeManager(t, "linux")
	p := nativeProfile("work")
	p.Routes = profile.Routes{Mode: "full"}
	e, j := configuredNative(t, m, p, 0)
	e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}
	if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil || len(j.Routes) != 1 || j.Routes[0].CIDR != "10.40.0.0/16" || len(r.base.routes) != 3 {
		t.Fatalf("full splits replaced by defaults: %v %+v", err, j)
	}
}

// TestGatewayRecovery rebuilds shared references before startup cleanup. The physical
// exception survives until all recorded native routes have been removed, in either order.
func TestGatewayRecovery(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, reverse := range []bool{false, true} {
			t.Run(platform+map[bool]string{false: "forward", true: "reverse"}[reverse], func(t *testing.T) {
				m, r := nativeManager(t, platform)
				full := nativeProfile("work")
				full.Routes = profile.Routes{Mode: "full"}
				e, first := configuredNative(t, m, full, 0)
				first.GatewayIP = "203.0.113.5"
				if err := m.Apply(context.Background(), full, e, &first, ignoreJournal); err != nil {
					t.Fatal(err)
				}
				other := nativeProfile("other")
				other.Routes = profile.Routes{Mode: "gateway"}
				secondEffect, second := configuredNative(t, m, other, 1)
				secondEffect.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
				second.GatewayIP = first.GatewayIP
				if err := m.Apply(context.Background(), other, secondEffect, &second, ignoreJournal); err != nil {
					t.Fatal(err)
				}
				journals := []Journal{journalSnapshot(t, first), journalSnapshot(t, second)}
				if reverse {
					slices.Reverse(journals)
				}
				r.before = func(args []string) {
					if slices.Contains(args, "delete") && (slices.Contains(args, "203.0.113.5/32") || slices.Contains(args, "203.0.113.5")) {
						for _, route := range r.base.routes {
							if slices.Contains(first.Routes, route) || slices.Contains(second.Routes, route) {
								t.Fatalf("gateway removed before sharing tunnel cleanup: %+v", route)
							}
						}
					}
				}
				fresh := freshNativeManager(t, m)
				if err := fresh.RecoverAll(context.Background(), journals); err != nil || len(r.base.routes) != 3 {
					t.Fatalf("shared recovery: %v %+v", err, r.base.routes)
				}
				if err := fresh.RecoverAll(context.Background(), journals); err != nil || len(r.base.routes) != 3 {
					t.Fatalf("repeated recovery: %v %+v", err, r.base.routes)
				}
			})
		}
	}
}

// TestGatewayDeletionRetry retains the final lease when a deletion fails, preventing
// loss of recovery metadata. A bounded subsequent teardown removes the unchanged route.
func TestGatewayDeletionRetry(t *testing.T) {
	m, r := nativeManager(t, "linux")
	p := nativeProfile("work")
	p.Routes = profile.Routes{Mode: "full"}
	e, j := configuredNative(t, m, p, 0)
	j.GatewayIP = "203.0.113.5"
	if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
		t.Fatal(err)
	}
	r.base.fail, r.base.failOnce = "delete 203.0.113.5/32", true
	if err := m.Teardown(context.Background(), j); err == nil || len(m.gateways) != 1 || len(r.base.routes) != 3 {
		t.Fatalf("failed host deletion lost lease: %v %+v", err, r.base.routes)
	}
	if err := m.Teardown(context.Background(), j); err != nil || len(m.gateways) != 0 || len(r.base.routes) != 2 {
		t.Fatalf("host deletion retry: %v %+v", err, r.base.routes)
	}
}

// TestGatewayPathSelection chooses a more-specific physical path over ambiguous defaults,
// rejects equally specific paths, and never uses a native link as the original path.
func TestGatewayPathSelection(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.5")
	routes := make([]JournalRoute, 0, 5)
	routes = append(routes, JournalRoute{CIDR: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "en0"}, JournalRoute{CIDR: "0.0.0.0/0", Gateway: "192.0.2.2", Interface: "en1"}, JournalRoute{CIDR: "203.0.113.0/24", Interface: "en0"}, JournalRoute{CIDR: "203.0.113.5/32", Interface: "utun0"})
	route, borrowed, err := gatewayPath(ip, routes)
	if err != nil || borrowed || route.CIDR != "203.0.113.5/32" || route.Interface != "en0" || route.Gateway != "" {
		t.Fatalf("physical longest-prefix selection: %+v %v", route, err)
	}
	routes = append(routes, JournalRoute{CIDR: "203.0.113.0/24", Interface: "en1"})
	var conflict *ConflictError
	if _, _, err := gatewayPath(ip, routes); !errors.As(err, &conflict) {
		t.Fatalf("ambiguous physical path accepted: %v", err)
	}
	if physicalInterface("-en0") || physicalInterface("en0;id") || physicalInterface("utun0") || physicalInterface(strings.Repeat("x", 17)) {
		t.Fatal("unsafe physical interface name accepted")
	}
}
