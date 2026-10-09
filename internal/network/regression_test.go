//go:build darwin || linux

// Package network tests owned resource matching and concurrent conflict reservations.
package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// TestDirectRouteOwnership checks real Darwin interface-route spelling and exact
// gateway matching. Write-ahead intents accept direct links, not routed replacements.
func TestDirectRouteOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, ownedGateway, actualGateway, link string
		want                                    bool
	}{
		{"interface intent", "", "ppp0", "ppp0", true},
		{"kernel link intent", "", "link#12", "ppp0", true},
		{"exact interface", "ppp0", "ppp0", "ppp0", true},
		{"exact kernel link", "link#12", "link#12", "ppp0", true},
		{"replaced link", "link#12", "link#13", "ppp0", false},
		{"replaced gateway", "", "10.20.0.1", "ppp0", false},
		{"other interface", "", "ppp1", "ppp1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owned := JournalRoute{"10.20.0.0/16", tc.ownedGateway, "ppp0"}
			actual := JournalRoute{"10.20.0.0/16", tc.actualGateway, tc.link}
			if sameRoute(owned, actual) != tc.want {
				t.Fatalf("owned=%+v actual=%+v want=%v", owned, actual, tc.want)
			}
		})
	}
	routes, err := parseDarwinRoutes([]byte("Destination Gateway Flags Netif Expire\n10.20/16 ppp0 USc ppp0\n"))
	want := []JournalRoute{{"10.20.0.0/16", "ppp0", "ppp0"}}
	if err != nil || !reflect.DeepEqual(routes, want) {
		t.Fatalf("interface route: %+v %v", routes, err)
	}
	m, f := testManager(t, "darwin")
	f.routes = routes
	j := Journal{Profile: "work", Attempt: 1, Interface: "ppp0", Routes: []JournalRoute{{CIDR: "10.20.0.0/16", Interface: "ppp0"}}}
	if err := m.Recover(context.Background(), j); err != nil || len(f.routes) != 0 {
		t.Fatalf("direct route intent recovery: %v %+v", err, f.routes)
	}
}

// TestMultipathRouteIdentities preserves each ECMP hop for ownership and conflict
// checks rather than rejecting unrelated routing tables or losing their destinations.
func TestMultipathRouteIdentities(t *testing.T) {
	routes, err := parseLinuxRoutes([]byte(`[{"dst":"10.20.0.0/16","nexthops":[{"gateway":"10.30.0.1","dev":"en0","weight":1},{"dev":"ppp0","weight":2}]}]`))
	want := []JournalRoute{{"10.20.0.0/16", "10.30.0.1", "en0"}, {"10.20.0.0/16", "", "ppp0"}}
	if err != nil || !reflect.DeepEqual(routes, want) {
		t.Fatalf("multipath identities: %+v %v", routes, err)
	}
	m, f := testManager(t, "linux")
	f.routes = routes
	var conflict *ConflictError
	if err := m.CheckUp(context.Background(), testProfile("work")); !errors.As(err, &conflict) {
		t.Fatalf("multipath overlap accepted: %v", err)
	}
}

// TestObservedDefaultConflicts checks configured and observed full tunnels, including
// gateway mode and split defaults. Only two active tunnel defaults conflict with each
// other; an ordinary LAN default and disjoint gateway routes remain acceptable.
func TestObservedDefaultConflicts(t *testing.T) {
	for _, tc := range []struct {
		name, firstMode, secondMode, firstPrefix, secondPrefix, firstLink string
		want                                                              bool
	}{
		{"configured full", "full", "gateway", "", "0.0.0.0/0", "ppp0", true},
		{"gateway defaults", "gateway", "gateway", "0.0.0.0/0", "0.0.0.0/0", "ppp0", true},
		{"gateway then full", "gateway", "full", "0.0.0.0/0", "0.0.0.0/0", "ppp0", true},
		{"gateway split defaults", "gateway", "gateway", "0.0.0.0/1", "128.0.0.0/1", "ppp0", true},
		{"split then ordinary default", "gateway", "full", "128.0.0.0/1", "0.0.0.0/0", "ppp0", true},
		{"disjoint gateway routes", "gateway", "gateway", "10.20.0.0/16", "10.30.0.0/16", "ppp0", false},
		{"one gateway default", "gateway", "gateway", "10.20.0.0/16", "0.0.0.0/0", "ppp0", true},
		{"LAN default", "gateway", "full", "0.0.0.0/0", "0.0.0.0/0", "en0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, f := testManager(t, "linux")
			first, second := testProfile("work"), testProfile("other")
			first.Routes, second.Routes = profile.Routes{Mode: tc.firstMode}, profile.Routes{Mode: tc.secondMode}
			first.DNS.Mode, second.DNS.Mode = "none", "none"
			first.DNS.Domains, second.DNS.Domains = nil, nil
			if err := m.CheckUp(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			j := Journal{Profile: "work", Attempt: 1}
			e := session.Effect{Profile: "work", Attempt: 1, Interface: "ppp0", LocalIP: netip.MustParseAddr("10.99.0.2")}
			if err := m.Apply(context.Background(), first, e, &j, func(Journal) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if err := m.CheckUp(context.Background(), second); err != nil {
				t.Fatal(err)
			}
			if tc.firstPrefix != "" {
				f.routes = append(f.routes, JournalRoute{CIDR: tc.firstPrefix, Interface: tc.firstLink})
			}
			f.routes = append(f.routes, JournalRoute{CIDR: tc.secondPrefix, Interface: "ppp1"})
			j = Journal{Profile: "other", Attempt: 1}
			e = session.Effect{Profile: "other", Attempt: 1, Interface: "ppp1", LocalIP: netip.MustParseAddr("10.99.0.3")}
			err := m.Apply(context.Background(), second, e, &j, func(Journal) error { return nil })
			var conflict *ConflictError
			if errors.As(err, &conflict) != tc.want || (!tc.want && err != nil) || len(j.Routes) != 0 {
				t.Fatalf("default conflict=%v want=%v journal=%+v", err, tc.want, j)
			}
			for _, call := range f.calls {
				if len(call) > 3 && call[3] == "route" {
					t.Fatal("default conflict check mutated host routes")
				}
			}
		})
	}
}

// blockedRunner pauses one selected fake command, making command contention observable
// without privileged execution. Cancellation or release wakes the blocked invocation.
type blockedRunner struct {
	base             *fakeRunner
	match            string
	entered, release chan struct{}
	once             sync.Once
}

// Run blocks the first argv containing match, then delegates to the in-memory runner.
// The wait honors ctx so failed transactions and cleanup retain finite deadlines.
func (r *blockedRunner) Run(ctx context.Context, candidates []string, args ...string) ([]byte, error) {
	if strings.Contains(strings.Join(args, " "), r.match) {
		r.once.Do(func() {
			close(r.entered)
			select {
			case <-r.release:
			case <-ctx.Done():
			}
		})
	}
	return r.base.Run(ctx, candidates, args...)
}

// TestReservationChecksDuringTransactions proves a slow apply, rollback or teardown
// cannot block address checks or another profile's CheckUp. Queued mutation deadlines
// expire without host changes, while reservations remain until cleanup succeeds.
func TestReservationChecksDuringTransactions(t *testing.T) {
	for _, operation := range []string{"apply", "rollback", "teardown"} {
		t.Run(operation, func(t *testing.T) {
			m, f := testManager(t, "linux")
			p := testProfile("work")
			j := Journal{Profile: "work", Attempt: 1}
			if operation == "teardown" {
				var err error
				j, _, err = applyFixture(t, m, f, p)
				if err != nil {
					t.Fatal(err)
				}
			} else if err := m.CheckUp(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			other := testProfile("other")
			other.Routes = profile.Routes{Mode: "gateway"}
			if err := m.CheckUp(context.Background(), other); err != nil {
				t.Fatal(err)
			}
			r := &blockedRunner{base: f, match: "route delete", entered: make(chan struct{}), release: make(chan struct{})}
			if operation == "apply" {
				r.match = "route add"
			}
			m.runner = r
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "teardown" {
					done <- m.Teardown(ctx, j)
					return
				}
				e := session.Effect{Profile: "work", Attempt: 1, Interface: "ppp0", LocalIP: netip.MustParseAddr("10.99.0.2")}
				if operation == "apply" {
					e.DNS = []netip.Addr{netip.MustParseAddr("10.20.0.1")}
				}
				done <- m.Apply(ctx, p, e, &j, func(Journal) error { return nil })
			}()
			// Always release and join the worker, including assertion failures.
			defer func() {
				close(r.release)
				err := <-done
				if (err != nil) != (operation == "rollback") {
					t.Errorf("transaction %s: %v", operation, err)
				}
			}()
			select {
			case <-r.entered:
			case <-ctx.Done():
				t.Fatal("transaction never reached selected command")
			}
			checked := make(chan error, 1)
			go func() {
				checked <- m.CheckAddresses("other", netip.MustParseAddr("10.99.0.2"))
			}()
			select {
			case err := <-checked:
				var conflict *ConflictError
				if !errors.As(err, &conflict) {
					t.Fatalf("duplicate address accepted during transaction: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("address check blocked on command transaction")
			}
			pending := testProfile("pending")
			pending.Routes.Include = []string{"10.40.0.0/16"}
			if err := m.CheckUp(ctx, pending); err != nil {
				t.Fatalf("disjoint reservation during transaction: %v", err)
			}
			queued, stop := context.WithTimeout(ctx, 20*time.Millisecond)
			defer stop()
			if err := m.Teardown(queued, Journal{Profile: "pending"}); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued teardown ignored deadline: %v", err)
			}
		})
	}
}

// TestPendingReservationRefresh verifies profile edits replace pending policy after
// revalidation, release is idempotent, and neither release nor refresh bypasses conflicts.
func TestPendingReservationRefresh(t *testing.T) {
	m, _ := testManager(t, "linux")
	p := testProfile("work")
	p.Routes = profile.Routes{Mode: "full"}
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p.Routes = profile.Routes{Mode: "custom", Include: []string{"10.40.0.0/16"}}
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	other := testProfile("other")
	other.Routes = profile.Routes{Mode: "full"}
	if err := m.CheckUp(context.Background(), other); err != nil {
		t.Fatalf("old full-mode reservation retained: %v", err)
	}
	p.Routes = profile.Routes{Mode: "full"}
	var conflict *ConflictError
	if err := m.CheckUp(context.Background(), p); !errors.As(err, &conflict) {
		t.Fatalf("pending refresh bypassed conflict: %v", err)
	}
	m.Release("work")
	m.Release("work")
	p.Routes = profile.Routes{Mode: "custom", Include: []string{"10.40.0.0/16"}}
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p.Routes.Include[0] = "10.50.0.0/16"
	if m.active["work"].profile.Routes.Include[0] != "10.40.0.0/16" {
		t.Fatal("pending reservation aliases caller profile")
	}
	m.active["work"] = tunnel{profile: m.active["work"].profile, link: "ppp0"}
	m.Release("work")
	if _, exists := m.active["work"]; !exists {
		t.Fatal("release discarded live ownership")
	}
}

// TestDarwinScopedDefaultIgnored verifies that the interface-scoped default route
// macOS adds for every new PPP link is not treated as a full-tunnel default, while
// an unscoped default through the tunnel still is.
func TestDarwinScopedDefaultIgnored(t *testing.T) {
	table := "Destination Gateway Flags Netif Expire\n" +
		"default 192.168.1.1 UGScg en0\n" +
		"default 192.168.1.1 UGS1cIg en0\n" +
		"default link#20 UCSIg ppp0\n" +
		"10.30.6/24 ppp0 USc ppp0\n"
	routes, err := parseDarwinRoutes([]byte(table))
	want := []JournalRoute{{"0.0.0.0/0", "192.168.1.1", "en0"}, {"10.30.6.0/24", "ppp0", "ppp0"}}
	if err != nil || !reflect.DeepEqual(routes, want) {
		t.Fatalf("scoped routes: %+v %v", routes, err)
	}
	routes, err = parseDarwinRoutes([]byte("Destination Gateway Flags Netif Expire\ndefault link#20 UCSg ppp0\n"))
	want = []JournalRoute{{"0.0.0.0/0", "link#20", "ppp0"}}
	if err != nil || !reflect.DeepEqual(routes, want) {
		t.Fatalf("unscoped tunnel default: %+v %v", routes, err)
	}
}

// TestPointToPointSubnet verifies that a PPP link's classful netmask does not
// claim a whole /8 for conflict checks, while broadcast links keep their subnet.
func TestPointToPointSubnet(t *testing.T) {
	addr := func(s string) net.Addr {
		ip, network, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return &net.IPNet{IP: ip, Mask: network.Mask}
	}
	got := linkSubnets("ppp0", net.FlagUp|net.FlagPointToPoint, []net.Addr{addr("10.212.118.104/8")})
	want := []InterfaceSubnet{{"ppp0", netip.MustParsePrefix("10.212.118.104/32")}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ppp subnet: %+v", got)
	}
	got = linkSubnets("en0", net.FlagUp|net.FlagBroadcast, []net.Addr{addr("192.168.1.6/24")})
	want = []InterfaceSubnet{{"en0", netip.MustParsePrefix("192.168.1.0/24")}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lan subnet: %+v", got)
	}
}

// TestInternalNameservers verifies that public resolvers pushed next to internal
// ones are dropped, and that an all-public list is kept rather than emptied.
func TestInternalNameservers(t *testing.T) {
	addrs := func(values ...string) []netip.Addr {
		result := make([]netip.Addr, 0, len(values))
		for _, value := range values {
			result = append(result, netip.MustParseAddr(value))
		}
		return result
	}
	cases := []struct{ in, want []netip.Addr }{
		{addrs("10.30.3.179", "8.8.8.8"), addrs("10.30.3.179")},
		{addrs("8.8.8.8", "100.100.1.1", "192.168.5.1"), addrs("100.100.1.1", "192.168.5.1")},
		{addrs("8.8.8.8", "1.1.1.1"), addrs("8.8.8.8", "1.1.1.1")},
	}
	for _, tc := range cases {
		if got := internalNameservers(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("internalNameservers(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
