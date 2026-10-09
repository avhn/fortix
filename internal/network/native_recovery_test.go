package network

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// TestNativeLegacyPeerJournalRecovery reconciles an older numbered native link whose
// peer_ip differs from local_ip. Wire round trips retain the old peer, but cleanup uses
// only link identity and local IP, leaving its kernel peer route and physical path intact.
func TestNativeLegacyPeerJournalRecovery(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, r := nativeManager(t, platform)
			p := nativeProfile("work")
			p.DNS = profile.DNS{Mode: "split", Domains: []string{"corp.example.com"}}
			e, j := configuredNative(t, m, p, 0)
			legacyPeer := netip.MustParseAddr("10.99.0.1")
			j.PeerIP = legacyPeer.String()
			r.links[e.Interface].peer = legacyPeer
			r.base.routes = slices.DeleteFunc(r.base.routes, func(route JournalRoute) bool { return route.Interface == e.Interface })
			r.connectPeer(e.Interface)
			baseline := slices.Clone(r.base.routes)
			if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			legacy := journalSnapshot(t, j)
			if legacy.PeerIP != legacyPeer.String() || legacy.PeerIP == legacy.LocalIP {
				t.Fatalf("legacy wire metadata changed: %+v", legacy)
			}
			fresh := freshNativeManager(t, m)
			for range 2 {
				if err := fresh.Recover(context.Background(), legacy); err != nil || !slices.Equal(r.base.routes, baseline) || len(r.base.dns) != 0 {
					t.Fatalf("legacy cleanup failed: %v routes=%+v", err, r.base.routes)
				}
			}
			for _, file := range legacy.ResolverFiles {
				if _, err := os.Stat(file.Path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("legacy resolver survived cleanup: %v", err)
				}
			}
		})
	}
}

// TestNativeReusedLinkRecovery protects routes and DNS when a native name has been
// reused, disappeared, or lost its recorded local IP. Independent resolver files still
// reconcile by exact bytes; recovery never issues a link deletion command.
func TestNativeReusedLinkRecovery(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, scenario := range []string{"index", "IP", "missing"} {
			t.Run(platform+scenario, func(t *testing.T) {
				m, r := nativeManager(t, platform)
				p := nativeProfile("work")
				p.DNS = profile.DNS{Mode: "split", Domains: []string{"corp.example.com"}}
				e, j := configuredNative(t, m, p, 0)
				if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "index":
					r.links[e.Interface].index++
				case "IP":
					r.links[e.Interface].local = netip.MustParseAddr("10.99.0.90")
				case "missing":
					delete(r.links, e.Interface)
				}
				before := slices.Clone(r.base.routes)
				fresh := freshNativeManager(t, m)
				if err := fresh.Recover(context.Background(), j); err != nil || !slices.Equal(before, r.base.routes) {
					t.Fatalf("reused native route removed: %v %+v", err, r.base.routes)
				}
				if platform == "linux" && !slices.Equal(r.base.dns[e.Interface], j.DNSServers) {
					t.Fatal("reused native DNS settings removed")
				}
				for _, file := range j.ResolverFiles {
					if _, err := os.Stat(file.Path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("independent resolver ownership leaked: %v", err)
					}
				}
				for _, call := range r.base.calls {
					if slices.Contains(call, "delete") || slices.Contains(call, "del") {
						t.Fatalf("recovery mutated reused link: %v", call)
					}
				}
			})
		}
	}
}

// TestNativeStaleJournal refuses an old attempt even when a new tunnel has the same
// interface name and local IP after transport closure removes the old connected route.
// Neither the new attempt's resources nor its reservation are released.
func TestNativeStaleJournal(t *testing.T) {
	m, r := nativeManager(t, "linux")
	p := nativeProfile("work")
	e, old := configuredNative(t, m, p, 0)
	if err := m.Apply(context.Background(), p, e, &old, ignoreJournal); err != nil {
		t.Fatal(err)
	}
	if err := m.Teardown(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	// Device closure, not manager teardown, removes this kernel-connected route.
	r.base.routes = slices.DeleteFunc(r.base.routes, func(route JournalRoute) bool { return route.Interface == e.Interface })
	r.links[e.Interface].local, r.links[e.Interface].peer = netip.Addr{}, netip.Addr{}
	r.links[e.Interface].index++
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	e.Attempt, e.Link.Index = 2, r.links[e.Interface].index
	current := Journal{Profile: p.ID, Attempt: e.Attempt}
	if err := m.RegisterLink(context.Background(), p.ID, e.Attempt, e.Link, &current, ignoreJournal); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureNative(context.Background(), e, &current, ignoreJournal); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background(), p, e, &current, ignoreJournal); err != nil {
		t.Fatal(err)
	}
	calls := len(r.base.calls)
	if err := m.Teardown(context.Background(), old); err == nil || len(r.base.calls) != calls || m.active[p.ID].attempt != 2 {
		t.Fatalf("stale journal changed current attempt: %v", err)
	}
}

// TestNativeJournalValidation refuses missing, mixed-backend and forged link ownership
// before any read or mutation command. Omitted backend records remain PPP-only.
func TestNativeJournalValidation(t *testing.T) {
	for _, scenario := range []string{"legacy native name", "unknown backend", "missing link", "process PID", "wrong link name", "no local address", "invalid local address", "physical route", "nonhost gateway exception"} {
		t.Run(scenario, func(t *testing.T) {
			m, r := nativeManager(t, "linux")
			p := nativeProfile("work")
			e, j := configuredNative(t, m, p, 0)
			switch scenario {
			case "legacy native name":
				j.Backend, j.Link = "", nil
			case "unknown backend":
				j.Backend = "unknown"
			case "missing link":
				j.Link = nil
			case "process PID":
				j.PID, j.StartTime = 99, "birth"
			case "wrong link name":
				j.Interface = "fortix1"
			case "no local address":
				j.LocalIP = ""
				j.Routes = []JournalRoute{{CIDR: "10.20.0.0/16", Interface: e.Interface}}
			case "invalid local address":
				j.LocalIP = "0.0.0.0"
			case "physical route":
				j.Routes = []JournalRoute{{CIDR: "10.20.0.0/16", Interface: "en0"}}
			case "nonhost gateway exception":
				j.GatewayIP = "203.0.113.5"
				j.GatewayException = &JournalGateway{Route: JournalRoute{CIDR: "0.0.0.0/0", Interface: "en0"}, Index: 2, Owned: true}
			}
			calls := len(r.base.calls)
			if err := freshNativeManager(t, m).Recover(context.Background(), j); err == nil || len(r.base.calls) != calls {
				t.Fatalf("invalid native journal reached commands: %v", err)
			}
		})
	}
	legacy := Journal{Profile: "work", Attempt: 1, Interface: "ppp0"}
	if legacy.backendName() != "openfortivpn" {
		t.Fatal("legacy backend changed")
	}
}

// TestResolvedNativeIndex validates the kernel index returned by resolvectl, not merely
// its device name. A mismatched reply cannot authorize configuring or clearing DNS.
func TestResolvedNativeIndex(t *testing.T) {
	m, r := nativeManager(t, "linux")
	p := nativeProfile("work")
	p.DNS = profile.DNS{Mode: "split", Domains: []string{"corp.example.com"}}
	e, j := configuredNative(t, m, p, 0)
	r.resolvedIndex = 99
	var identity *InterfaceError
	if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); !errors.As(err, &identity) || j.DNSConfigured {
		t.Fatalf("mismatched resolved index accepted: %v %+v", err, j)
	}
	for _, call := range r.base.calls {
		if slices.Contains(call, "~corp.example.com") || slices.Contains(call, "10.20.0.1") {
			t.Fatalf("mismatched index mutated DNS: %v", call)
		}
	}
}

// TestCommandDiagnostics bounds retained stderr and verifies collision classification
// remains typed and private. A harmless failing file listing exercises the real runner.
func TestCommandDiagnostics(t *testing.T) {
	var output boundedDiagnostic
	payload := []byte("RTNETLINK answers: File exists\n" + strings.Repeat("x", 16000))
	if n, err := output.Write(payload); err != nil || n != len(payload) || output.buffer.Len() != 4096 {
		t.Fatalf("stderr bound: n=%d err=%v size=%d", n, err, output.buffer.Len())
	}
	failure := &CommandError{Stderr: output.buffer.String()}
	if !routeExistsError(failure) || strings.Contains(failure.Error(), "RTNETLINK") || routeExistsError(errors.New("File exists")) {
		t.Fatal("typed private route classification failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*commandWait)
	defer cancel()
	_, err := (ExecRunner{}).Run(ctx, []string{"/bin/ls"}, "/fortix-network-test-missing-directory")
	var diagnostic *CommandError
	if !errors.As(err, &diagnostic) || diagnostic.Stderr == "" || len(diagnostic.Stderr) > 4096 || diagnostic.Error() != "network command failed" {
		t.Fatalf("runner discarded or exposed classification stderr: %v", err)
	}
}

// TestNativeFullPushedDefaults normalizes accepted full-mode gateway defaults to two
// owned /1 routes with an original-path host exception, never replacing the LAN default
// or taking ownership of the kernel-connected peer route.
func TestNativeFullPushedDefaults(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"} {
		t.Run(cidr, func(t *testing.T) {
			m, r := nativeManager(t, "linux")
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: "full"}
			e, j := configuredNative(t, m, p, 0)
			e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix(cidr)}
			j.GatewayIP = "203.0.113.5"
			if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil || len(j.Routes) != 2 || len(r.base.routes) != 4 {
				t.Fatalf("full pushed default: %v %+v", err, j)
			}
		})
	}
}
