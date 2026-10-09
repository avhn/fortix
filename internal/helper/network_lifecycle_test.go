//go:build darwin || linux

package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// pendingNetwork holds an application open until the test observes cancellation.
// All work is in memory; no route, resolver, or privileged host path is changed.
type pendingNetwork struct {
	NoNetwork
	started, cancelled, release chan struct{}
	cleaned                     chan Journal
	active                      atomic.Bool
}

// Apply announces an in-flight transaction and waits for cancellation, then a bounded
// test release. The delayed return models final rollback work after context cancellation.
func (n *pendingNetwork) Apply(ctx context.Context, _ *profile.Profile, _ session.Effect, journal *Journal, persist func(Journal) error) error {
	n.active.Store(true)
	defer n.active.Store(false)
	close(n.started)
	<-ctx.Done()
	close(n.cancelled)
	select {
	case <-n.release:
	case <-time.After(3 * time.Second):
	}
	// Rollback can discover additional owned resources after teardown was queued.
	journal.Routes = []JournalRoute{{CIDR: "10.20.0.0/16", Interface: journal.Interface}}
	journal.ResolverFiles = []JournalResolver{{Path: "/etc/resolver/corp.example.com", Content: "# managed by fortix profile=work\nnameserver 10.20.0.1\n"}}
	if err := persist(*journal); err != nil {
		return err
	}
	return ctx.Err()
}

// Teardown refuses concurrent application and records the ownership identity only
// after Apply has finished, allowing the test to detect premature journal removal.
func (n *pendingNetwork) Teardown(_ context.Context, j Journal) error {
	if n.active.Load() {
		return errors.New("teardown overlapped application")
	}
	n.cleaned <- j
	return nil
}

// TestStopCancelsNetworkApplication verifies explicit down and helper shutdown cancel
// in-flight application promptly, retain its journal during rollback, and wait for
// application to finish before teardown can remove the ownership record.
func TestStopCancelsNetworkApplication(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "down", true: "shutdown"}[shutdown], func(t *testing.T) {
			n := &pendingNetwork{started: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{}), cleaned: make(chan Journal, 1)}
			h := startHarness(t, nil, func(o *Options) {
				o.Network = n
				o.Deadlines.Network = 2 * time.Second
			})
			defer close(n.release)
			c := h.client(t)
			c.success(t, protocol.Request{Op: "subscribe"})
			c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "")})
			c.success(t, protocol.Request{Op: "up", Profile: "work"})
			challenge := c.event(t, "challenge", "work", "")
			c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
			select {
			case <-n.started:
			case <-time.After(time.Second):
				t.Fatal("network application did not start")
			}
			if shutdown {
				h.cancel()
			} else {
				c.success(t, protocol.Request{Op: "down", Profile: "work"})
			}
			select {
			case <-n.cancelled:
			case <-time.After(time.Second):
				t.Fatal("stop did not cancel network application")
			}
			journalPath := filepath.Join(h.paths.State, "work.json")
			if _, err := os.Stat(journalPath); err != nil {
				t.Fatalf("in-flight transaction lost journal: %v", err)
			}
			select {
			case <-n.cleaned:
				t.Fatal("teardown finished before application returned")
			default:
			}
			n.release <- struct{}{}
			select {
			case j := <-n.cleaned:
				if j.Profile != "work" || j.Attempt != 1 || j.PID <= 1 || j.Interface != "ppp0" || len(j.Routes) != 1 || len(j.ResolverFiles) != 1 {
					t.Fatalf("wrong cleanup identity: %+v", j)
				}
			case <-time.After(time.Second):
				t.Fatal("teardown did not follow rollback")
			}
			if shutdown {
				select {
				case err := <-h.done:
					h.done <- err
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("shutdown did not finish after rollback")
				}
			} else {
				c.event(t, "state", "work", "disconnected")
			}
			if _, err := os.Stat(journalPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed cleanup retained journal: %v", err)
			}
		})
	}
}
