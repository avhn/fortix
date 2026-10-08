package network

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// TestRunner verifies fixed absolute execution, cancellation, candidate fallback and
// bounded output using harmless system utilities. No route or DNS executable is run.
func TestRunner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), commandWait*5)
	defer cancel()
	output, err := (ExecRunner{}).Run(ctx, []string{filepath.Join(t.TempDir(), "missing"), "/usr/bin/printf"}, "%s", "fixture")
	if err != nil || string(output) != "fixture" {
		t.Fatalf("absolute candidate execution: %q %v", output, err)
	}
	if _, err := (ExecRunner{}).Run(ctx, []string{filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing executable accepted")
	}
	if _, err := (ExecRunner{}).Run(ctx, []string{"relative"}); err == nil {
		t.Fatal("relative executable accepted")
	}
	if _, err := (ExecRunner{}).Run(ctx, []string{"/usr/bin/false"}); err == nil {
		t.Fatal("command failure lost")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := (ExecRunner{}).Run(cancelled, []string{"/bin/cat"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := (ExecRunner{}).Run(ctx, []string{"/usr/bin/head"}, "-c", "1048577", "/dev/zero"); err == nil {
		t.Fatal("oversized command output accepted")
	}
	var buffer boundedOutput
	if _, err := buffer.Write([]byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write(make([]byte, 1<<20)); err == nil {
		t.Fatal("unbounded output accepted")
	}
	path := filepath.Join(t.TempDir(), "program")
	if err := os.WriteFile(path, []byte("fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := trustedExecutable(path); err == nil {
		t.Fatal("untrusted executable accepted")
	}
	if err := trustedExecutable("/usr/bin"); err == nil {
		t.Fatal("executable directory accepted")
	}
}

// TestConnectedSubnets checks read-only discovery and PPP-name validation boundaries.
// Host addresses are not recorded or exposed; only prefix validity is asserted.
func TestConnectedSubnets(t *testing.T) {
	subnets, err := ConnectedSubnets()
	if err != nil {
		t.Fatal(err)
	}
	for _, subnet := range subnets {
		if !subnet.Prefix.Addr().Is4() || subnet.Prefix != subnet.Prefix.Masked() || subnet.Interface == "" {
			t.Fatal("invalid discovered subnet")
		}
	}
	for _, tc := range []struct {
		name string
		want bool
	}{{"ppp0", true}, {"ppp123", true}, {"ppp", false}, {"en0", false}, {"ppp-1", false}, {"ppp0;id", false}, {"ppp00000000000000000", false}} {
		if validInterface(tc.name) != tc.want {
			t.Fatalf("interface %q", tc.name)
		}
	}
}

// TestInvalidOptionsAndInputs ensures construction and cancelled conflict checks fail
// before command execution, including unreserved addresses and invalid profile fields.
func TestInvalidOptionsAndInputs(t *testing.T) {
	for _, options := range []Options{{OS: "unsupported"}, {OS: "darwin"}, {OS: "darwin", Paths: paths.Paths{ResolverDir: "relative"}}, {OS: "darwin", Paths: paths.Paths{ResolverDir: "/tmp/../resolver"}}} {
		if _, err := New(options); err == nil {
			t.Fatal("unsafe options accepted")
		}
	}
	if _, err := New(Options{Paths: paths.Paths{ResolverDir: filepath.Join(t.TempDir(), "resolver")}}); err != nil {
		t.Fatal(err)
	}
	m, f := testManager(t, "linux")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.CheckUp(ctx, testProfile("work")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled check accepted: %v", err)
	}
	if err := m.CheckUp(context.Background(), nil); err == nil {
		t.Fatal("nil profile accepted")
	}
	if err := m.CheckAddresses("unknown", netip.MustParseAddr("10.20.0.2")); err == nil {
		t.Fatal("unreserved address accepted")
	}
	if err := m.Apply(context.Background(), nil, session.Effect{}, nil, nil); err == nil || len(f.calls) != 0 {
		t.Fatal("invalid attempt reached host commands")
	}
	if err := (&ConflictError{Detail: "another full tunnel is active"}).Error(); !strings.Contains(err, "full tunnel") {
		t.Fatal("conflict explanation lost")
	}
	m.subnets = func() ([]InterfaceSubnet, error) { return nil, errors.New("injected enumeration failure") }
	if err := m.CheckUp(context.Background(), testProfile("work")); err == nil {
		t.Fatal("interface discovery failed open")
	}
}

// TestUnsafeJournals rejects every resource escape before invoking a host command.
// Invalid records remain available for inspection rather than targeting unrelated state.
func TestUnsafeJournals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Journal, *Manager)
	}{
		{"profile", func(j *Journal, _ *Manager) { j.Profile = "../work" }},
		{"CIDR", func(j *Journal, _ *Manager) { j.Routes = []JournalRoute{{CIDR: "invalid", Interface: "ppp0"}} }},
		{"interface", func(j *Journal, _ *Manager) { j.Routes = []JournalRoute{{CIDR: "10.20.0.0/16", Interface: "en0"}} }},
		{"gateway", func(j *Journal, _ *Manager) {
			j.Routes = []JournalRoute{{CIDR: "10.20.0.0/16", Gateway: "10.20.0.1", Interface: "ppp0"}}
		}},
		{"resolver traversal", func(j *Journal, _ *Manager) {
			j.ResolverFiles = []JournalResolver{{Path: "/unrelated/file", Content: marker("work")}}
		}},
		{"unmarked resolver", func(j *Journal, m *Manager) {
			j.ResolverFiles = []JournalResolver{{Path: filepath.Join(m.paths.ResolverDir, "corp.example.com"), Content: "nameserver 10.20.0.1"}}
		}},
		{"temporary traversal", func(j *Journal, m *Manager) {
			j.ResolverFiles = []JournalResolver{{Path: filepath.Join(m.paths.ResolverDir, "corp.example.com"), Content: marker("work"), Temporary: "../unrelated"}}
		}},
		{"missing DNS values", func(j *Journal, m *Manager) { m.os = "linux"; j.DNSConfigured = true }},
		{"invalid DNS server", func(j *Journal, m *Manager) {
			m.os = "linux"
			j.DNSConfigured = true
			j.DNSServers = []string{"invalid"}
			j.DNSDomains = []string{"~corp.example.com"}
		}},
		{"invalid DNS domain", func(j *Journal, m *Manager) {
			m.os = "linux"
			j.DNSConfigured = true
			j.DNSServers = []string{"10.20.0.1"}
			j.DNSDomains = []string{"corp.example.com"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, f := testManager(t, "darwin")
			j := Journal{Profile: "work", Attempt: 1, Interface: "ppp0"}
			tc.edit(&j, m)
			if err := m.Recover(context.Background(), j); err == nil || len(f.calls) != 0 {
				t.Fatal("unsafe journal reached command runner")
			}
		})
	}
}

// TestResolverUnsafeEntries covers symlinks, FIFOs, writable/oversized files and
// resolver-directory substitution. No target outside a temporary root is modified.
func TestResolverUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "writable", "oversized", "directory symlink", "directory writable", "production ancestors"} {
		t.Run(kind, func(t *testing.T) {
			m, f := testManager(t, "darwin")
			if err := os.MkdirAll(m.paths.ResolverDir, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.paths.ResolverDir, "corp.example.com")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(filepath.Join(t.TempDir(), "untouched"), path)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "writable":
				err = os.WriteFile(path, []byte("foreign"), 0666)
				if err == nil {
					err = os.Chmod(path, 0666)
				}
			case "oversized":
				err = os.WriteFile(path, make([]byte, 64*1024+1), 0644)
			case "directory symlink":
				m.paths.ResolverDir = filepath.Join(filepath.Dir(m.paths.ResolverDir), "link")
				err = os.Symlink(t.TempDir(), m.paths.ResolverDir)
			case "directory writable":
				err = os.Chmod(m.paths.ResolverDir, 0777)
			case "production ancestors":
				m.paths.SkipTrust = false
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := applyFixture(t, m, f, testProfile("work")); err == nil || len(f.routes) != 0 {
				t.Fatalf("unsafe resolver accepted: %v", err)
			}
		})
	}
}

// TestResolverInterruptedPublication recovers journalled empty, partial and completed
// private staging writes, including a crash before the final atomic publication.
func TestResolverInterruptedPublication(t *testing.T) {
	for _, bytes := range []string{"", "# managed", marker("work") + "nameserver 10.20.0.1\n"} {
		t.Run(bytes, func(t *testing.T) {
			m, _ := testManager(t, "darwin")
			if err := os.MkdirAll(m.paths.ResolverDir, 0755); err != nil {
				t.Fatal(err)
			}
			entry := JournalResolver{Path: filepath.Join(m.paths.ResolverDir, "corp.example.com"), Content: marker("work") + "nameserver 10.20.0.1\n", Temporary: ".fortix-work-" + rand.Text()}
			temp := filepath.Join(m.paths.ResolverDir, entry.Temporary)
			if err := os.WriteFile(temp, []byte(bytes), 0600); err != nil {
				t.Fatal(err)
			}
			if err := m.Recover(context.Background(), Journal{Profile: "work", Attempt: 1, ResolverFiles: []JournalResolver{entry}}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(temp); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staging file leaked: %v", err)
			}
		})
	}
	for _, name := range []string{"../file", ".fortix-other-" + rand.Text(), ".fortix-work-short", ".fortix-work-" + strings.Repeat("!", 26)} {
		if validTemporary("work", name) {
			t.Fatal("invalid staging basename accepted")
		}
	}
}

// TestNegotiatedConflicts checks default routes, gateway-route overlaps and routes
// that appear after Up. Conflict failures occur before any new route or DNS mutation.
func TestNegotiatedConflicts(t *testing.T) {
	for _, scenario := range []string{"default", "pushed overlap", "late LAN", "late route"} {
		t.Run(scenario, func(t *testing.T) {
			m, f := testManager(t, "linux")
			first, second := testProfile("work"), testProfile("other")
			second.Routes = profile.Routes{Mode: "gateway"}
			if scenario == "default" {
				first.Routes = profile.Routes{Mode: "full"}
			}
			if scenario == "late LAN" || scenario == "late route" {
				second.Routes = profile.Routes{Mode: "custom", Include: []string{"10.40.0.0/16"}}
			}
			if err := m.CheckUp(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			if err := m.CheckUp(context.Background(), second); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "default":
				f.routes = []JournalRoute{{"0.0.0.0/0", "", "ppp1"}}
			case "pushed overlap":
				f.routes = []JournalRoute{{"10.20.1.0/24", "", "ppp1"}}
			case "late LAN":
				m.subnets = func() ([]InterfaceSubnet, error) {
					return []InterfaceSubnet{{"en0", netip.MustParsePrefix("10.40.0.0/24")}}, nil
				}
			case "late route":
				f.routes = []JournalRoute{{"10.40.1.0/24", "", "en0"}}
			}
			j := Journal{Profile: "other", Attempt: 1}
			e := session.Effect{Profile: "other", Attempt: 1, Interface: "ppp1", LocalIP: netip.MustParseAddr("10.99.0.3")}
			err := m.Apply(context.Background(), second, e, &j, func(Journal) error { return nil })
			var conflict *ConflictError
			if !errors.As(err, &conflict) || len(j.Routes) != 0 {
				t.Fatalf("negotiated conflict accepted: %v %+v", err, j)
			}
		})
	}
}
