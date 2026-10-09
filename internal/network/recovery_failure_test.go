//go:build darwin || linux

package network

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// TestFailedRollbackRetainsOwnership proves failed removal retains exact recovery data
// and the active reservation. A later successful teardown releases both routes and policy.
func TestFailedRollbackRetainsOwnership(t *testing.T) {
	m, f := testManager(t, "linux")
	p := testProfile("work")
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	f.fail = "delete"
	j := Journal{Profile: "work", Attempt: 1}
	e := session.Effect{Profile: "work", Attempt: 1, Interface: "ppp0", LocalIP: netip.MustParseAddr("10.99.0.2")}
	// Missing DNS addresses fail after both routes were installed.
	err := m.Apply(context.Background(), p, e, &j, func(Journal) error { return nil })
	if err == nil || len(j.Routes) != 2 || len(f.routes) != 2 {
		t.Fatalf("failed rollback lost ownership: %v %+v", err, j)
	}
	var conflict *ConflictError
	if err := m.CheckUp(context.Background(), testProfile("other")); !errors.As(err, &conflict) {
		t.Fatalf("leaked reservation released: %v", err)
	}
	f.fail = ""
	if err := m.Teardown(context.Background(), j); err != nil || len(f.routes) != 0 {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if err := m.CheckUp(context.Background(), testProfile("other")); err != nil {
		t.Fatalf("completed cleanup retained reservation: %v", err)
	}
}

// TestResolverMidApplyRollback leaves a foreign second domain file untouched while
// removing the first resolver and every custom route from the failed transaction.
func TestResolverMidApplyRollback(t *testing.T) {
	m, f := testManager(t, "darwin")
	p := testProfile("work")
	p.DNS.Domains = append(p.DNS.Domains, "other.example.com")
	if err := os.MkdirAll(m.paths.ResolverDir, 0755); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(m.paths.ResolverDir, "other.example.com")
	if err := os.WriteFile(foreign, []byte("nameserver 10.20.0.2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	j, _, err := applyFixture(t, m, f, p)
	if err == nil || len(f.routes) != 0 || len(j.ResolverFiles) != 0 {
		t.Fatalf("mid-resolver rollback failed: %v %+v", err, j)
	}
	if _, err := os.Stat(filepath.Join(m.paths.ResolverDir, "corp.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("first resolver leaked")
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "nameserver 10.20.0.2\n" {
		t.Fatal("foreign resolver changed")
	}
}

// TestIndependentTunnels applies disjoint owned transactions to two PPP links and
// verifies stopping either profile leaves the other profile's routes and DNS intact.
func TestIndependentTunnels(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, f := testManager(t, platform)
			first, _, err := applyFixture(t, m, f, testProfile("work"))
			if err != nil {
				t.Fatal(err)
			}
			p := testProfile("other")
			p.Routes = profile.Routes{Mode: "custom", Include: []string{"10.40.0.0/16"}}
			p.DNS.Domains = []string{"other.example.com"}
			if err := m.CheckUp(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			m.subnets = func() ([]InterfaceSubnet, error) {
				return []InterfaceSubnet{{"ppp0", netip.MustParsePrefix("10.99.0.2/32")}, {"ppp1", netip.MustParsePrefix("10.99.0.3/32")}}, nil
			}
			second := Journal{Profile: "other", Attempt: 1}
			e := session.Effect{Profile: "other", Attempt: 1, Interface: "ppp1", LocalIP: netip.MustParseAddr("10.99.0.3"), DNS: []netip.Addr{netip.MustParseAddr("10.40.0.1")}}
			if err := m.Apply(context.Background(), p, e, &second, func(Journal) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if err := m.Teardown(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			if len(f.routes) != 1 || f.routes[0].Interface != "ppp1" {
				t.Fatalf("stopping first changed second routes: %+v", f.routes)
			}
			if platform == "linux" {
				if len(f.dns["ppp0"]) != 0 || len(f.dns["ppp1"]) != 1 {
					t.Fatal("stopping first changed second DNS")
				}
			} else if _, err := os.Stat(second.ResolverFiles[0].Path); err != nil {
				t.Fatal("stopping first removed second resolver")
			}
			if err := m.Teardown(context.Background(), second); err != nil || len(f.routes) != 0 {
				t.Fatalf("stopping second leaked ownership: %v", err)
			}
		})
	}
}

// TestResolvedDownLinkCleanup distinguishes address loss from link deletion, so DNS
// ownership is removed even when a still-existing PPP link no longer has IPv4 subnets.
func TestResolvedDownLinkCleanup(t *testing.T) {
	m, f := testManager(t, "linux")
	j, _, err := applyFixture(t, m, f, testProfile("work"))
	if err != nil {
		t.Fatal(err)
	}
	m.subnets = func() ([]InterfaceSubnet, error) { return nil, nil }
	if err := m.Teardown(context.Background(), j); err != nil || len(f.dns) != 0 || len(f.domains) != 0 {
		t.Fatalf("addressless link retained DNS ownership: %v", err)
	}
	if present, err := InterfaceExists("fortix-nonexistent-link"); err != nil || present {
		t.Fatalf("missing link discovery: %v, %v", present, err)
	}
}
