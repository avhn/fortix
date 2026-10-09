package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// nativeKernelLink models a kernel-allocated interface without opening a TUN device.
// A changed index or local address represents interface reuse by an unrelated owner.
type nativeKernelLink struct {
	index int
	local netip.Addr
	peer  netip.Addr
	mtu   int
}

// nativeRunner extends the route fake with native address and link configuration.
// Darwin address assignment creates a local host route that is not helper-owned. Rejections
// can install a route before returning an error, while before observes durable intent.
type nativeRunner struct {
	base          *fakeRunner
	links         map[string]*nativeKernelLink
	before        func([]string)
	rejectCIDR    string
	rejectErr     error
	racingRoute   JournalRoute
	resolvedIndex int
}

// Run emulates fixed native commands and delegates route/DNS state to the shared fake.
// It never executes a host command, changes an actual interface, or uses privileges.
func (r *nativeRunner) Run(ctx context.Context, candidates []string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.before != nil {
		r.before(args)
	}
	rejectedDestination := slices.Contains(args, r.rejectCIDR) || (slices.Contains(args, "-host") && slices.Contains(args, strings.TrimSuffix(r.rejectCIDR, "/32")))
	if r.rejectCIDR != "" && slices.Contains(args, "add") && rejectedDestination {
		r.rejectCIDR = ""
		r.base.calls = append(r.base.calls, append(slices.Clone(candidates), args...))
		if r.racingRoute.CIDR != "" {
			r.base.routes = append(r.base.routes, r.racingRoute)
		}
		return nil, r.rejectErr
	}
	if args[0] == "addr" || args[0] == "link" || candidates[0] == "/sbin/ifconfig" {
		r.base.calls = append(r.base.calls, append(slices.Clone(candidates), args...))
		if r.base.fail != "" && strings.Contains(strings.Join(args, " "), r.base.fail) {
			return nil, errors.New("injected native configuration failure")
		}
		switch {
		case candidates[0] == "/sbin/ifconfig":
			link := r.links[args[0]]
			link.local, link.peer = netip.MustParseAddr(args[2]), netip.MustParseAddr(args[3])
			_, _ = fmt.Sscan(args[5], &link.mtu)
			r.connectPeer(args[0])
		case args[0] == "addr":
			link := r.links[args[4]]
			link.local, link.peer = netip.MustParsePrefix(args[2]).Addr(), netip.Addr{}
		default:
			_, _ = fmt.Sscan(args[5], &r.links[args[3]].mtu)
		}
		return nil, nil
	}
	data, err := r.base.Run(ctx, candidates, args...)
	if err == nil && (args[0] == "dns" || args[0] == "domain") && len(args) == 2 {
		index := r.links[args[1]].index
		if r.resolvedIndex != 0 {
			index = r.resolvedIndex
		}
		data = []byte(strings.Replace(string(data), "Link 12", fmt.Sprintf("Link %d", index), 1))
	}
	return data, err
}

// connectPeer models Darwin's kernel-connected local /32 for identical endpoints.
// Linux address assignment does not create a peer route in the main table; legacy
// recovery fixtures also use this method to restore an older distinct peer route.
// Reconfiguration replaces only this link's host route without duplicating it.
func (r *nativeRunner) connectPeer(name string) {
	link := r.links[name]
	route := JournalRoute{CIDR: netip.PrefixFrom(link.peer, 32).String(), Interface: name}
	if r.base.os == "darwin" {
		route.Gateway = link.local.String()
	}
	r.base.routes = slices.DeleteFunc(r.base.routes, func(existing JournalRoute) bool {
		return existing.CIDR == route.CIDR && existing.Interface == name
	})
	r.base.routes = append(r.base.routes, route)
}

// nativeManager creates a fully injected host with one physical path and two native
// devices. Kernel address verification uses mutable fake state, not a permissive stub.
func nativeManager(t *testing.T, platform string) (*Manager, *nativeRunner) {
	t.Helper()
	prefix := "fortix"
	if platform == "darwin" {
		prefix = "utun"
	}
	r := &nativeRunner{
		base:  &fakeRunner{os: platform, dns: make(map[string][]string), domains: make(map[string][]string)},
		links: map[string]*nativeKernelLink{"en0": {index: 2}, prefix + "0": {index: 12}, prefix + "1": {index: 13}},
	}
	r.base.routes = []JournalRoute{{CIDR: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "en0"}}
	m, err := New(Options{
		OS: platform, Paths: paths.Paths{ResolverDir: filepath.Join(t.TempDir(), "resolver"), SkipTrust: true}, Runner: r,
		InterfaceIndex: func(name string) (int, error) {
			if link := r.links[name]; link != nil {
				return link.index, nil
			}
			return 0, os.ErrNotExist
		},
		VerifyInterface: func(name string, ip netip.Addr) error {
			if link := r.links[name]; link != nil && link.local == ip {
				return nil
			}
			return &InterfaceError{}
		},
		LinkExists: func(name string) (bool, error) { return r.links[name] != nil, nil },
		Subnets: func() ([]InterfaceSubnet, error) {
			result := []InterfaceSubnet{{"en0", netip.MustParsePrefix("192.0.2.0/24")}}
			for name, link := range r.links {
				if link.local.IsValid() {
					result = append(result, InterfaceSubnet{name, netip.PrefixFrom(link.local, 32)})
				}
			}
			return result, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, r
}

// nativeProfile supplies explicit native, password-only configuration without DNS.
// Tests opt into split DNS or full routing individually to isolate their assertions.
func nativeProfile(id string) *profile.Profile {
	p := testProfile(id)
	p.Backend, p.MFA.Mode = "native", "none"
	p.DNS = profile.DNS{Mode: "none"}
	return p
}

// ignoreJournal acknowledges persistence for tests concerned only with command state.
// Durable-intent tests replace it with a snapshotting callback before mutation.
func ignoreJournal(Journal) error { return nil }

// journalSnapshot copies the wire record so later pointer and slice changes cannot
// alter a test's previously acknowledged write-ahead persistence snapshot.
func journalSnapshot(t *testing.T, j Journal) Journal {
	t.Helper()
	data, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var result Journal
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// nativeAttempt reserves policy and binds a fake allocated link before configuration.
// Returned effect includes unnumbered per-link local addresses and an unrelated DNS suffix.
func nativeAttempt(t *testing.T, m *Manager, p *profile.Profile, number int) (session.Effect, Journal) {
	t.Helper()
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("fortix%d", number)
	if m.os == "darwin" {
		name = fmt.Sprintf("utun%d", number)
	}
	e := session.Effect{Profile: p.ID, Attempt: 1, Interface: name, Link: backend.LinkIdentity{Interface: name, Index: 12 + number}, LocalIP: netip.MustParseAddr(fmt.Sprintf("10.99.0.%d", 2+number)), PeerIP: netip.MustParseAddr(fmt.Sprintf("10.99.0.%d", 2+number)), MTU: 1354, DNS: []netip.Addr{netip.MustParseAddr("10.20.0.1")}, Suffix: "pushed.example.net"}
	j := Journal{Profile: p.ID, Attempt: e.Attempt}
	if err := m.RegisterLink(context.Background(), p.ID, e.Attempt, e.Link, &j, ignoreJournal); err != nil {
		t.Fatal(err)
	}
	return e, j
}

// configuredNative configures a registered fake link for routing and recovery tests.
// Every command and local-address verification still goes through the injected host.
func configuredNative(t *testing.T, m *Manager, p *profile.Profile, number int) (session.Effect, Journal) {
	t.Helper()
	e, j := nativeAttempt(t, m, p, number)
	if err := m.ConfigureNative(context.Background(), e, &j, ignoreJournal); err != nil {
		t.Fatal(err)
	}
	return e, j
}

// TestNativeConfiguration proves registration precedes mutation and platform argv
// configures the negotiated local IP and MTU without an advertised peer. Repeated
// configuration only reads live routes, without duplicating persistence or mutations.
func TestNativeConfiguration(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, r := nativeManager(t, platform)
			p := nativeProfile("work")
			e, j := nativeAttempt(t, m, p, 0)
			durable := journalSnapshot(t, j)
			r.before = func(args []string) {
				if args[0] == "-j" || args[0] == "-rn" {
					return
				}
				if durable.Backend != "native" || durable.Link == nil || *durable.Link != e.Link || durable.LocalIP != e.LocalIP.String() || durable.MTU != e.MTU {
					t.Fatalf("configuration without durable identity/address intent: %v %+v", args, durable)
				}
			}
			if err := m.ConfigureNative(context.Background(), e, &j, func(updated Journal) error { durable = journalSnapshot(t, updated); return nil }); err != nil {
				t.Fatal(err)
			}
			r.before = nil
			wantCommands := [][]string{{"/sbin/ifconfig", e.Interface, "inet", e.LocalIP.String(), e.LocalIP.String(), "mtu", "1354", "up"}}
			if platform == "linux" {
				wantCommands = [][]string{
					{"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "addr", "add", e.LocalIP.String() + "/32", "dev", e.Interface},
					{"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "link", "set", "dev", e.Interface, "mtu", "1354", "up"},
				}
			}
			for _, command := range wantCommands {
				if !slices.ContainsFunc(r.base.calls, func(call []string) bool { return slices.Equal(call, command) }) {
					t.Fatalf("missing unnumbered command: %v calls=%v", command, r.base.calls)
				}
			}
			link := r.links[e.Interface]
			wantPeer := netip.Addr{}
			if platform == "darwin" {
				wantPeer = e.LocalIP
			}
			if link.local != e.LocalIP || link.peer != wantPeer || link.mtu != e.MTU || j.PeerIP != j.LocalIP {
				t.Fatalf("configuration mismatch: %+v", link)
			}
			calls := len(r.base.calls)
			if err := m.ConfigureNative(context.Background(), e, &j, ignoreJournal); err != nil || len(r.base.calls) != calls+1 {
				t.Fatalf("non-idempotent configuration: %v", err)
			}
			if call := r.base.calls[calls]; !slices.Contains(call, "-j") && !slices.Contains(call, "-rn") {
				t.Fatalf("retry mutated host: %v", call)
			}
			calls = len(r.base.calls)
			changed := e
			changed.MTU++
			if err := m.ConfigureNative(context.Background(), changed, &j, ignoreJournal); err == nil || len(r.base.calls) != calls {
				t.Fatal("changed negotiated configuration reached commands")
			}
		})
	}
}

// TestNativeIdentityRefusals checks name-only use, wrong platform/index/generation,
// forged process identity, duplicate registration, failed persistence and missing IP.
// Failed configuration persistence may inspect routes but never mutates the fake host.
func TestNativeIdentityRefusals(t *testing.T) {
	for _, scenario := range []string{"name only", "wrong platform", "wrong index", "wrong attempt", "process identity", "registration persistence", "configuration persistence", "kernel IP", "reused index"} {
		t.Run(scenario, func(t *testing.T) {
			m, r := nativeManager(t, "darwin")
			p := nativeProfile("work")
			e, j := nativeAttempt(t, m, p, 0)
			calls := len(r.base.calls)
			var err error
			switch scenario {
			case "name only":
				delete(m.active, p.ID)
				err = m.ConfigureNative(context.Background(), e, &j, ignoreJournal)
			case "wrong platform":
				link := e.Link
				link.Interface = "fortix0"
				err = m.RegisterLink(context.Background(), p.ID, 1, link, &j, ignoreJournal)
			case "wrong index":
				e.Link.Index++
				err = m.ConfigureNative(context.Background(), e, &j, ignoreJournal)
			case "wrong attempt":
				e.Attempt++
				err = m.ConfigureNative(context.Background(), e, &j, ignoreJournal)
			case "process identity":
				e.Link.PID = 99
				err = m.RegisterLink(context.Background(), p.ID, 1, e.Link, &j, ignoreJournal)
			case "registration persistence":
				delete(m.active, p.ID)
				m.active[p.ID] = tunnel{profile: *p}
				err = m.RegisterLink(context.Background(), p.ID, 1, e.Link, &j, func(Journal) error { return errors.New("persistence failed") })
				if m.active[p.ID].link != "" {
					t.Fatal("failed registration granted ownership")
				}
			case "configuration persistence":
				err = m.ConfigureNative(context.Background(), e, &j, func(Journal) error { return errors.New("persistence failed") })
			case "kernel IP":
				if err := m.ConfigureNative(context.Background(), e, &j, ignoreJournal); err != nil {
					t.Fatal(err)
				}
				calls = len(r.base.calls)
				r.links[e.Interface].local = netip.MustParseAddr("10.99.0.90")
				err = m.Apply(context.Background(), p, e, &j, ignoreJournal)
			case "reused index":
				r.links[e.Interface].index++
				err = m.ConfigureNative(context.Background(), e, &j, ignoreJournal)
			}
			if err == nil || (len(r.base.calls) != calls && scenario != "configuration persistence") {
				t.Fatalf("unsafe identity mutated fake host: %v calls=%v", err, r.base.calls)
			}
			if scenario == "configuration persistence" {
				for _, call := range r.base.calls[calls:] {
					if !slices.Contains(call, "-rn") {
						t.Fatalf("failed persistence mutated host: %v", call)
					}
				}
			}
		})
	}
	m, _ := nativeManager(t, "linux")
	p, other := nativeProfile("work"), nativeProfile("other")
	_, j := nativeAttempt(t, m, p, 0)
	other.Routes = profile.Routes{Mode: "gateway"}
	if err := m.CheckUp(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	otherJournal := Journal{Profile: other.ID, Attempt: 1}
	var conflict *ConflictError
	if err := m.RegisterLink(context.Background(), other.ID, 1, *j.Link, &otherJournal, ignoreJournal); !errors.As(err, &conflict) {
		t.Fatalf("duplicate link accepted: %v", err)
	}
}

// TestNativeReservations proves negotiated routes are rejected before mutation for
// active reservations, connected LANs, live routes and gateway default/split defaults.
func TestNativeReservations(t *testing.T) {
	for _, scenario := range []string{"active", "pending negotiated", "LAN", "table", "default", "low split default", "high split default", "malformed", "policy change", "late conflict"} {
		t.Run(scenario, func(t *testing.T) {
			m, r := nativeManager(t, "linux")
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: "gateway"}
			e, j := configuredNative(t, m, p, 0)
			e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
			switch scenario {
			case "active":
				other := nativeProfile("other")
				if err := m.CheckUp(context.Background(), other); err != nil {
					t.Fatal(err)
				}
			case "pending negotiated":
				other := nativeProfile("other")
				other.Routes = profile.Routes{Mode: "gateway"}
				second, _ := configuredNative(t, m, other, 1)
				second.PushedPrefixes = slices.Clone(e.PushedPrefixes)
				if err := m.ReserveNegotiated(context.Background(), other, second); err != nil {
					t.Fatal(err)
				}
			case "LAN":
				e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			case "table":
				r.base.routes = append(r.base.routes, JournalRoute{CIDR: "10.20.1.0/24", Interface: "en0"})
			case "default":
				e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
			case "low split default":
				e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")}
			case "high split default":
				e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("128.0.0.0/1")}
			case "malformed":
				e.PushedPrefixes = []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.20.1.2"), 16)}
			case "policy change":
				p.Routes = profile.Routes{Mode: "custom", Include: []string{"10.40.0.0/16"}}
			case "late conflict":
				if err := m.ReserveNegotiated(context.Background(), p, e); err != nil {
					t.Fatal(err)
				}
				r.base.routes = append(r.base.routes, JournalRoute{CIDR: "10.20.0.0/16", Interface: "en0"})
			}
			err := m.Apply(context.Background(), p, e, &j, ignoreJournal)
			var conflict *ConflictError
			if err == nil || (scenario != "malformed" && scenario != "policy change" && !errors.As(err, &conflict)) || len(j.Routes) != 0 {
				t.Fatalf("negotiated policy accepted: %v %+v", err, j)
			}
			for _, call := range r.base.calls {
				if slices.Contains(call, "add") && !slices.Contains(call, "addr") {
					t.Fatalf("conflict caused route mutation: %v", call)
				}
			}
		})
	}
}

// TestNativeRouteRace models both typed EEXIST stderr and an ordinary failed add with
// a competing route appearing in the live table. Neither route is claimed or deleted.
func TestNativeRouteRace(t *testing.T) {
	for _, diagnostic := range []string{"RTNETLINK answers: File exists", "permission denied"} {
		for _, platform := range []string{"darwin", "linux"} {
			t.Run(platform+diagnostic, func(t *testing.T) {
				m, r := nativeManager(t, platform)
				p := nativeProfile("work")
				p.Routes.Include = []string{"10.20.0.0/16"}
				e, j := configuredNative(t, m, p, 0)
				r.rejectCIDR, r.rejectErr = "10.20.0.0/16", &CommandError{Stderr: diagnostic}
				r.racingRoute = JournalRoute{CIDR: "10.20.0.0/16", Gateway: "192.0.2.1", Interface: "en0"}
				var conflict *ConflictError
				err := m.Apply(context.Background(), p, e, &j, ignoreJournal)
				if !errors.As(err, &conflict) || len(j.Routes) != 0 || !slices.Contains(r.base.routes, r.racingRoute) {
					t.Fatalf("racing route claimed: %v %+v %+v", err, j, r.base.routes)
				}
				if err := m.Teardown(context.Background(), j); err != nil || !slices.Contains(r.base.routes, r.racingRoute) {
					t.Fatalf("racing route deleted: %v", err)
				}
			})
		}
	}
}

// TestNativeRoutesAndDNS applies only the chosen custom or pushed routes and only
// profile DNS domains. Pushed suffixes never create resolver files or resolved domains.
// Cleanup leaves the physical default and kernel-connected peer route untouched.
func TestNativeRoutesAndDNS(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, mode := range []string{"custom", "gateway"} {
			t.Run(platform+mode, func(t *testing.T) {
				m, r := nativeManager(t, platform)
				p := nativeProfile("work")
				p.DNS = profile.DNS{Mode: "split", Domains: []string{"corp.example.com"}}
				if mode == "gateway" {
					p.Routes = profile.Routes{Mode: "gateway"}
				}
				e, j := configuredNative(t, m, p, 0)
				e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}
				if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
					t.Fatal(err)
				}
				want := []string{"10.20.0.0/16", "10.50.0.0/16"}
				if mode == "gateway" {
					want = []string{"10.40.0.0/16"}
				}
				got := make([]string, 0, len(j.Routes))
				for _, route := range j.Routes {
					got = append(got, route.CIDR)
				}
				if !slices.Equal(got, want) {
					t.Fatalf("route selection: %v want %v", got, want)
				}
				if platform == "darwin" {
					if len(j.ResolverFiles) != 1 || filepath.Base(j.ResolverFiles[0].Path) != "corp.example.com" {
						t.Fatalf("pushed DNS suffix applied: %+v", j)
					}
				} else if !slices.Equal(r.base.domains[e.Interface], []string{"~corp.example.com"}) {
					t.Fatalf("pushed DNS suffix applied: %+v", r.base.domains)
				}
				calls := len(r.base.calls)
				if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
					t.Fatalf("repeated apply: %v", err)
				}
				for _, call := range r.base.calls[calls:] {
					if slices.Contains(call, "add") {
						t.Fatalf("repeated route add: %v", call)
					}
				}
				wantRoutes := 1
				if platform == "darwin" {
					wantRoutes++
				}
				if err := m.Teardown(context.Background(), j); err != nil || len(r.base.routes) != wantRoutes || len(r.base.dns) != 0 {
					t.Fatalf("native cleanup: %v %+v", err, r.base)
				}
			})
		}
	}
}
