package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// fakeRunner models routes and resolved settings entirely in memory, including failures.
// Each invocation records absolute candidates and argv; no command is ever executed.
type fakeRunner struct {
	os       string
	routes   []JournalRoute
	dns      map[string][]string
	domains  map[string][]string
	calls    [][]string
	fail     string
	failOnce bool
}

// Run emulates the fixed networking commands and rejects unknown argv immediately.
// Injected failures occur before mutation, except cancellation can model a completed add.
func (f *fakeRunner) Run(ctx context.Context, candidates []string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		if !filepath.IsAbs(candidate) {
			return nil, errors.New("relative executable candidate")
		}
	}
	f.calls = append(f.calls, append(slices.Clone(candidates), args...))
	command := strings.Join(args, " ")
	if f.fail != "" && strings.Contains(command, f.fail) {
		if f.failOnce {
			f.fail = ""
		}
		return nil, errors.New("injected command failure")
	}
	if args[0] == "-j" {
		entries := make([]map[string]string, 0, len(f.routes))
		for _, route := range f.routes {
			entries = append(entries, map[string]string{"dst": route.CIDR, "dev": route.Interface, "gateway": route.Gateway})
		}
		return json.Marshal(entries)
	}
	if args[0] == "-rn" {
		output := "Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n"
		for _, route := range f.routes {
			gateway := route.Gateway
			if gateway == "" {
				gateway = route.Interface
			}
			output += fmt.Sprintf("%s %s US %s\n", route.CIDR, gateway, route.Interface)
		}
		return []byte(output), nil
	}
	if args[0] == "route" || args[0] == "-n" {
		var operation, cidr, link string
		if args[0] == "route" {
			operation, cidr, link = args[1], args[2], args[4]
		} else {
			operation, cidr, link = args[1], args[3], args[5]
		}
		if operation == "add" {
			gateway := ""
			if f.os == "darwin" {
				gateway = link
			}
			f.routes = append(f.routes, JournalRoute{cidr, gateway, link})
		} else {
			f.routes = slices.DeleteFunc(f.routes, func(route JournalRoute) bool { return route.CIDR == cidr && route.Interface == link })
		}
		return nil, nil
	}
	if args[0] == "dns" || args[0] == "domain" {
		values := f.dns
		if args[0] == "domain" {
			values = f.domains
		}
		if len(args) > 2 {
			if len(args) == 3 && args[2] == "" {
				delete(values, args[1])
			} else {
				values[args[1]] = slices.Clone(args[2:])
			}
			return nil, nil
		}
		return []byte("Link 12 (" + args[1] + "): " + strings.Join(values[args[1]], " ") + "\n"), nil
	}
	return nil, errors.New("unexpected fake command")
}

// testManager creates an adapter with relocated paths and mutable fake host state.
// A connected PPP subnet is exposed only after negotiation, avoiding pre-up conflicts.
func testManager(t *testing.T, platform string) (*Manager, *fakeRunner) {
	t.Helper()
	f := &fakeRunner{os: platform, dns: make(map[string][]string), domains: make(map[string][]string)}
	m, err := New(Options{OS: platform, Paths: paths.Paths{ResolverDir: filepath.Join(t.TempDir(), "resolver"), SkipTrust: true}, Runner: f, VerifyInterface: func(string, netip.Addr) error { return nil }, LinkExists: func(name string) (bool, error) { return name == "ppp0" || name == "ppp1", nil }, Subnets: func() ([]InterfaceSubnet, error) {
		return []InterfaceSubnet{{"ppp0", netip.MustParsePrefix("10.99.0.2/32")}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return m, f
}

// testProfile returns a valid custom/split profile using documentation-only identities.
// The two disjoint destinations allow rollback to be tested between individual commands.
func testProfile(id string) *profile.Profile {
	p := &profile.Profile{SchemaVersion: 1, ID: id, Name: "Work", Backend: "openfortivpn", Gateway: profile.Gateway{Host: "vpn.example.com", Port: 443}, Username: "jane.doe", Routes: profile.Routes{Mode: "custom", Include: []string{"10.20.0.0/16", "10.30.0.0/16"}}, DNS: profile.DNS{Mode: "split", Domains: []string{"corp.example.com"}}}
	p.ApplyDefaults()
	return p
}

// applyFixture reserves a profile and records every persisted ownership snapshot.
// It verifies intent precedes host mutation by observing the fake's current state.
func applyFixture(t *testing.T, m *Manager, f *fakeRunner, p *profile.Profile) (Journal, []Journal, error) {
	t.Helper()
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	j := Journal{Profile: p.ID, Attempt: 1, Interface: "ppp0"}
	e := session.Effect{Profile: p.ID, Attempt: 1, Interface: "ppp0", LocalIP: netip.MustParseAddr("10.99.0.2"), DNS: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}
	var records []Journal
	err := m.Apply(context.Background(), p, e, &j, func(updated Journal) error {
		copy := updated
		copy.Routes, copy.ResolverFiles = slices.Clone(updated.Routes), slices.Clone(updated.ResolverFiles)
		copy.DNSServers, copy.DNSDomains = slices.Clone(updated.DNSServers), slices.Clone(updated.DNSDomains)
		records = append(records, copy)
		if len(updated.Routes) < len(f.routes) {
			t.Fatal("route created without journal intent")
		}
		return nil
	})
	return j, records, err
}

// TestApplyTeardown exercises route/DNS symmetry and durable intent on both platforms.
// Stopping one profile leaves unrelated host resources and edited resolver files intact.
func TestApplyTeardown(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, f := testManager(t, platform)
			j, records, err := applyFixture(t, m, f, testProfile("work"))
			if err != nil {
				t.Fatal(err)
			}
			if len(f.routes) != 2 || len(records) < 5 || len(j.Routes) != 2 {
				t.Fatalf("missing network ownership: %+v", j)
			}
			if platform == "darwin" {
				data, err := os.ReadFile(j.ResolverFiles[0].Path)
				if err != nil || !strings.HasPrefix(string(data), marker("work")) || string(data) != j.ResolverFiles[0].Content {
					t.Fatalf("resolver ownership: %q, %v", data, err)
				}
			} else if !reflect.DeepEqual(f.dns["ppp0"], []string{"10.20.0.1"}) || !reflect.DeepEqual(f.domains["ppp0"], []string{"~corp.example.com"}) {
				t.Fatal("missing routing-only DNS")
			}
			foreign := JournalRoute{"10.40.0.0/16", "", "ppp1"}
			f.routes = append(f.routes, foreign)
			if err := m.Teardown(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f.routes, []JournalRoute{foreign}) || len(f.dns) != 0 {
				t.Fatalf("teardown touched foreign state or leaked ownership: %+v", f)
			}
			for _, file := range j.ResolverFiles {
				if _, err := os.Stat(file.Path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("resolver leaked: %v", err)
				}
			}
			if err := m.Teardown(context.Background(), j); err != nil {
				t.Fatalf("repeated teardown: %v", err)
			}
		})
	}
}

// TestRollback injects route, DNS and journal failures in the middle of application.
// Successful rollback leaves no owned host resources; failed rollback retains the journal.
func TestRollback(t *testing.T) {
	for _, tc := range []struct{ platform, failure string }{{"darwin", "add -net 10.30"}, {"linux", "add 10.30"}, {"linux", "domain ppp0 ~"}, {"linux", "dns ppp0 10."}} {
		t.Run(tc.platform+tc.failure, func(t *testing.T) {
			m, f := testManager(t, tc.platform)
			f.fail, f.failOnce = tc.failure, true
			j, _, err := applyFixture(t, m, f, testProfile("work"))
			if err == nil || len(f.routes) != 0 || len(f.dns["ppp0"]) != 0 || len(j.Routes) != 0 || j.DNSConfigured {
				t.Fatalf("rollback failed: err=%v journal=%+v host=%+v", err, j, f)
			}
		})
	}
	m, f := testManager(t, "linux")
	p := testProfile("work")
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	j := Journal{Profile: p.ID, Attempt: 1}
	e := session.Effect{Profile: p.ID, Attempt: 1, Interface: "ppp0", LocalIP: netip.MustParseAddr("10.99.0.2")}
	writes := 0
	err := m.Apply(context.Background(), p, e, &j, func(Journal) error {
		writes++
		if writes == 2 {
			return errors.New("injected journal failure")
		}
		return nil
	})
	if err == nil || len(f.routes) != 0 || len(j.Routes) != 0 {
		t.Fatalf("journal failure did not roll back: %v %+v", err, j)
	}
}

// TestCrashRecovery reconstructs a fresh adapter from durable ownership snapshots,
// including a crash between intent persistence and publication or DNS domain setup.
func TestCrashRecovery(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, f := testManager(t, platform)
			j, records, err := applyFixture(t, m, f, testProfile("work"))
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := New(Options{OS: platform, Paths: m.paths, Runner: f, Subnets: m.subnets, LinkExists: m.linkExists})
			if err != nil {
				t.Fatal(err)
			}
			if platform == "linux" {
				delete(f.domains, "ppp0")
			}
			if err := fresh.Recover(context.Background(), j); err != nil || len(f.routes) != 0 || len(f.dns["ppp0"]) != 0 {
				t.Fatalf("crash recovery: %v %+v", err, f)
			}
			if err := fresh.Recover(context.Background(), records[0]); err != nil {
				t.Fatalf("unpublished intent recovery: %v", err)
			}
		})
	}
}

// TestResolverOwnership protects existing, unmarked, foreign and modified files.
// All paths are temporary; symlink targets and non-owned resolver bytes remain intact.
func TestResolverOwnership(t *testing.T) {
	for _, content := range []string{"nameserver 10.20.0.1\n", marker("other") + "nameserver 10.20.0.1\n", marker("work") + "nameserver 10.20.0.2\n"} {
		t.Run(strings.TrimSpace(content), func(t *testing.T) {
			m, f := testManager(t, "darwin")
			if err := os.MkdirAll(m.paths.ResolverDir, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.paths.ResolverDir, "corp.example.com")
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			j, _, err := applyFixture(t, m, f, testProfile("work"))
			if err == nil || len(f.routes) != 0 || len(j.ResolverFiles) != 0 {
				t.Fatalf("existing resolver overwritten: %v %+v", err, j)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != content {
				t.Fatal("existing resolver changed")
			}
		})
	}
	m, f := testManager(t, "darwin")
	j, _, err := applyFixture(t, m, f, testProfile("work"))
	if err != nil {
		t.Fatal(err)
	}
	path := j.ResolverFiles[0].Path
	changed := marker("work") + "nameserver 10.20.0.2\n"
	if err := os.WriteFile(path, []byte(changed), 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.Teardown(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != changed {
		t.Fatal("modified resolver removed")
	}
}

// TestConflicts covers custom-prefix overlap, active reservations, connected LANs,
// observed pushed routes, full-mode exclusivity, duplicate IPs and split DNS ownership.
func TestConflicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*profile.Profile, *Manager, *fakeRunner)
		want bool
	}{
		{"disjoint custom", func(p *profile.Profile, _ *Manager, _ *fakeRunner) {
			p.Routes.Include = []string{"10.40.0.0/16"}
			p.DNS.Domains = []string{"other.example.com"}
		}, false},
		{"same prefix", func(_ *profile.Profile, _ *Manager, _ *fakeRunner) {}, true},
		{"nested prefix", func(p *profile.Profile, _ *Manager, _ *fakeRunner) { p.Routes.Include = []string{"10.20.1.0/24"} }, true},
		{"connected LAN", func(p *profile.Profile, m *Manager, _ *fakeRunner) {
			p.Routes.Include = []string{"10.40.0.0/16"}
			m.subnets = func() ([]InterfaceSubnet, error) {
				return []InterfaceSubnet{{"en0", netip.MustParsePrefix("10.40.1.0/24")}}, nil
			}
		}, true},
		{"pushed route", func(p *profile.Profile, _ *Manager, f *fakeRunner) {
			p.Routes.Include = []string{"10.40.0.0/16"}
			f.routes = []JournalRoute{{"10.40.1.0/24", "", "ppp1"}}
		}, true},
		{"gateway host route", func(p *profile.Profile, _ *Manager, f *fakeRunner) {
			p.Routes.Include = []string{"10.40.0.0/16"}
			f.routes = []JournalRoute{{"10.40.0.1/32", "", "en0"}}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, f := testManager(t, "linux")
			first := testProfile("work")
			if err := m.CheckUp(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			p := testProfile("other")
			tc.edit(p, m, f)
			err := m.CheckUp(context.Background(), p)
			var conflict *ConflictError
			if errors.As(err, &conflict) != tc.want || (!tc.want && err != nil) {
				t.Fatalf("conflict=%v want=%v", err, tc.want)
			}
		})
	}
	m, _ := testManager(t, "linux")
	first, second := testProfile("work"), testProfile("other")
	first.Routes, second.Routes = profile.Routes{Mode: "full"}, profile.Routes{Mode: "full"}
	if err := m.CheckUp(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	var conflict *ConflictError
	if err := m.CheckUp(context.Background(), second); !errors.As(err, &conflict) {
		t.Fatalf("second full tunnel accepted: %v", err)
	}
	second.Routes.Mode = "gateway"
	if err := m.CheckUp(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("10.99.0.2")
	if err := m.CheckAddresses("work", address); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckAddresses("other", address); !errors.As(err, &conflict) {
		t.Fatalf("duplicate local address accepted: %v", err)
	}
}

// TestChangedRouteAndDNS preserves replacements with a different gateway or DNS values.
// A journal can authorize deletion of its exact bytes/settings, never a whole snapshot.
func TestChangedRouteAndDNS(t *testing.T) {
	m, f := testManager(t, "linux")
	j, _, err := applyFixture(t, m, f, testProfile("work"))
	if err != nil {
		t.Fatal(err)
	}
	f.routes[0].Gateway = "10.20.0.1"
	f.dns["ppp0"] = []string{"10.20.0.2"}
	if err := m.Teardown(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 1 || f.routes[0].Gateway == "" || !reflect.DeepEqual(f.dns["ppp0"], []string{"10.20.0.2"}) {
		t.Fatal("replacement route or DNS was removed")
	}
}
