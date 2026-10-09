//go:build darwin || linux

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// integrationRunner emulates a Linux route table for real helper actor/socket tests.
// A mutex protects observations from asynchronous apply and teardown workers.
type integrationRunner struct {
	mu       sync.Mutex
	routes   []JournalRoute
	failAdds bool
}

// Run accepts only route-table reads and custom-route mutations from the adapter.
// No system command runs; injected add failures leave the fake table unchanged.
func (r *integrationRunner) Run(ctx context.Context, _ []string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if args[0] == "-j" {
		entries := make([]map[string]string, 0, len(r.routes))
		for _, route := range r.routes {
			entries = append(entries, map[string]string{"dst": route.CIDR, "dev": route.Interface})
		}
		return json.Marshal(entries)
	}
	if args[0] != "route" || len(args) != 5 {
		return nil, errors.New("unexpected integration network command")
	}
	if args[1] == "add" {
		if r.failAdds {
			return nil, errors.New("injected route add failure")
		}
		r.routes = append(r.routes, JournalRoute{CIDR: args[2], Interface: args[4]})
	} else {
		r.routes = slices.DeleteFunc(r.routes, func(route JournalRoute) bool { return route.CIDR == args[2] && route.Interface == args[4] })
	}
	return nil, nil
}

// adapterOptions returns an owned-network adapter backed solely by the fake runner.
// Empty interface discovery isolates the tests from actual connected host subnets.
func adapterOptions(t *testing.T, runner *integrationRunner) func(*Options) {
	t.Helper()
	return func(o *Options) {
		adapter, err := network.New(network.Options{Paths: o.Paths, OS: "linux", Runner: runner, VerifyInterface: func(string, netip.Addr) error { return nil }, Subnets: func() ([]network.InterfaceSubnet, error) { return nil, nil }})
		if err != nil {
			t.Fatal(err)
		}
		o.Network = adapter
	}
}

// TestOwnedNetworkIntegration proves the helper invokes journalled apply/teardown,
// reports apply failure, rejects overlapping Up before spawn, and rejects duplicate
// negotiated addresses before touching the second attempt's network resources.
func TestOwnedNetworkIntegration(t *testing.T) {
	for _, scenario := range []string{"symmetry", "apply failure", "overlap", "duplicate IP"} {
		t.Run(scenario, func(t *testing.T) {
			runner := &integrationRunner{failAdds: scenario == "apply failure"}
			h := startHarness(t, nil, adapterOptions(t, runner))
			c := h.client(t)
			if scenario == "apply failure" {
				c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "")})
				c.success(t, protocol.Request{Op: "subscribe"})
				c.success(t, protocol.Request{Op: "up", Profile: "work"})
				challenge := c.event(t, "challenge", "work", "")
				c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
				failed := c.event(t, "state", "work", "failed")
				if !strings.Contains(failed.Detail, "route or split DNS") {
					t.Fatalf("missing network failure explanation: %+v", failed)
				}
			} else {
				connectFixture(t, c, "work", "", "fixture-password")
				file, err := openDirectory(h.paths.State)
				if err != nil {
					t.Fatal(err)
				}
				j, err := readJournalAt(file, "work")
				_ = file.Close()
				if err != nil || len(j.Routes) != 1 || j.Routes[0].Interface != "ppp0" {
					t.Fatalf("missing durable route ownership: %+v %v", j, err)
				}
				if scenario != "symmetry" {
					data := profileJSON("other", "")
					if scenario == "duplicate IP" {
						data = []byte(strings.ReplaceAll(string(data), "10.20.0.0/16", "10.30.0.0/16"))
					}
					c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: data})
					result := c.request(t, protocol.Request{Op: "up", Profile: "other"})
					if scenario == "overlap" {
						if result.OK || result.Error.Code != protocol.Conflict || !strings.Contains(result.Error.Message, "is already using") {
							t.Fatalf("overlapping up accepted: %+v", result)
						}
					} else {
						if !result.OK {
							t.Fatalf("disjoint up refused early: %+v", result)
						}
						challenge := c.event(t, "challenge", "other", "")
						c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
					}
					if scenario == "duplicate IP" {
						stopping := c.event(t, "state", "other", "stopping")
						if stopping.Code != "" {
							t.Fatalf("conflict code on stopping event: %+v", stopping)
						}
					}
					failed := c.event(t, "state", "other", "failed")
					if failed.Code != protocol.Conflict || failed.Detail == "" {
						t.Fatalf("missing conflict code/detail: %+v", failed)
					}
					c.success(t, protocol.Request{Op: "down", Profile: "other"})
					disconnected := c.event(t, "state", "other", "disconnected")
					if disconnected.Code != "" {
						t.Fatalf("conflict code on disconnected event: %+v", disconnected)
					}
				}
				c.success(t, protocol.Request{Op: "down", Profile: "work"})
				c.event(t, "state", "work", "disconnected")
			}
			runner.mu.Lock()
			count := len(runner.routes)
			runner.mu.Unlock()
			if count != 0 {
				t.Fatal("owned route leaked")
			}
			if _, err := os.Stat(filepath.Join(h.paths.State, "work.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed cleanup retained journal: %v", err)
			}
		})
	}
}

// TestOwnedNetworkStartupRecovery recovers a durable route journal with a nonexistent
// process PID and clears it only after matching owned route removal has completed.
func TestOwnedNetworkStartupRecovery(t *testing.T) {
	dir := t.TempDir()
	j := Journal{Profile: "work", Attempt: 1, PID: 1 << 30, StartTime: "missing", Interface: "ppp0", Routes: []JournalRoute{{CIDR: "10.20.0.0/16", Interface: "ppp0"}}}
	if err := writeJournal(dir, j); err != nil {
		t.Fatal(err)
	}
	runner := &integrationRunner{routes: slices.Clone(j.Routes)}
	adapter, err := network.New(network.Options{OS: "linux", Runner: runner, VerifyInterface: func(string, netip.Addr) error { return nil }, Subnets: func() ([]network.InterfaceSubnet, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{opts: Options{Paths: paths.Paths{State: dir}, Network: adapter}}
	if err := s.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.routes) != 0 {
		t.Fatal("recovery did not remove owned route")
	}
	if _, err := os.Stat(filepath.Join(dir, "work.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reconciled journal remained")
	}
}

// TestUnusedNetworkReservations exercises actor outcomes without spawning a child.
// Generation exhaustion, idle replacement and retirement must release pending policy
// so another profile can reserve the same full-tunnel mode without restarting the helper.
func TestUnusedNetworkReservations(t *testing.T) {
	for _, operation := range []string{"up", "replace", "retire"} {
		t.Run(operation, func(t *testing.T) {
			runner := &integrationRunner{}
			adapter, err := network.New(network.Options{OS: "linux", Runner: runner, VerifyInterface: func(string, netip.Addr) error { return nil }, Subnets: func() ([]network.InterfaceSubnet, error) { return nil, nil }})
			if err != nil {
				t.Fatal(err)
			}
			p, err := profile.Decode(strings.NewReader(string(profileJSON("work", ""))))
			if err != nil {
				t.Fatal(err)
			}
			p.Routes = profile.Routes{Mode: "full"}
			s := &Server{ctx: context.Background(), opts: Options{Network: adapter}, clients: make(map[*connection]bool)}
			a := newSupervisor(s, p)
			if err := adapter.CheckUp(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			if operation == "up" {
				a.state.Attempt = ^uint64(0)
			}
			reply := make(chan controlReply, 1)
			a.control(controlInput{op: operation, origin: &connection{uid: 501}, profile: p, reply: reply})
			<-reply
			if operation == "up" && (a.state.Phase != session.Failed || a.state.Detail != "attempt generation exhausted") {
				t.Fatalf("unexpected no-start outcome: %+v", a.state)
			}
			other := *p
			other.ID = "other"
			if err := adapter.CheckUp(context.Background(), &other); err != nil {
				t.Fatalf("unused reservation retained after %s: %v", operation, err)
			}
			if err := adapter.CheckAddresses("work", netip.MustParseAddr("10.99.0.2")); err == nil {
				t.Fatal("unused profile still has an address reservation")
			}
		})
	}
}

// TestDefaultAdapter verifies nil networking selects the real ownership adapter,
// not a silent no-op. Construction performs no host commands or privileged writes.
func TestDefaultAdapter(t *testing.T) {
	p, err := paths.Resolve(paths.Override{RootDir: t.TempDir(), SkipTrust: true})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.opts.Network.(*network.Manager); !ok {
		t.Fatal("default network adapter is still a no-op")
	}
}
