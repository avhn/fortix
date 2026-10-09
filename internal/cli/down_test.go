//go:build darwin || linux

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
)

// TestDownWaitsForAll verifies subscribe-before-stop ordering, multiple targets,
// already idle profiles, and snapshots that acknowledge cleanup independently.
func TestDownWaitsForAll(t *testing.T) {
	for _, args := range [][]string{{"down", "--all"}, {"down", "work", "other", "idle"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			subscribed, captured := false, false
			stops, snapshots := 0, 0
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "subscribe":
					subscribed = true
					return nil, nil, nil
				case "status":
					if !subscribed {
						t.Error("snapshot preceded subscription")
					}
					captured = true
					entries := []statusEntry{{Profile: "work", Attempt: 3, State: "connected", Wanted: true}, {Profile: "other", Attempt: 7, State: "connected", Wanted: true}, {Profile: "idle", State: "disconnected"}}
					if stops > 0 {
						snapshots++
						entries[0].State, entries[0].Wanted = "disconnected", false
						entries[1].State, entries[1].Wanted = "stopping", false
						if snapshots >= 2 {
							entries[1].State = "disconnected"
						}
					}
					return entries, nil, nil
				case "down":
					if !subscribed || !captured {
						t.Error("stop preceded subscription or baseline snapshot")
					}
					stops++
					return nil, []protocol.Event{{Type: "state", Profile: "other", Attempt: 7, State: "stopping"}}, nil
				}
				t.Errorf("unexpected operation %s", req.Op)
				return nil, nil, nil
			})
			code, _, diag := runCommand(t, args, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
			wantStops := len(args) - 1
			if args[1] == "--all" {
				wantStops = 1
			}
			if code != 0 || snapshots < 2 || stops != wantStops {
				t.Fatalf("code %d, snapshots %d, stops %d, diagnostics %s", code, snapshots, stops, diag)
			}
		})
	}
}

// TestDownFailures ensures cleanup errors, competing starts, and a stalled stop
// return nonzero. An invocation deadline bounds the whole command, not one profile.
func TestDownFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry statusEntry
		want  string
	}{
		{"cleanup", statusEntry{State: "failed", CleanupPending: true}, "cleanup failed"},
		{"cleanup retry", statusEntry{State: "stopping", Detail: "network cleanup failed"}, "cleanup failed"},
		{"queued up", statusEntry{State: "stopping", Wanted: true}, "competing start"},
		{"new up", statusEntry{State: "connected", Attempt: 4, Wanted: true}, "competing start"},
		{"timeout", statusEntry{State: "stopping"}, "context deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stopped := false
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "subscribe":
					return nil, nil, nil
				case "status":
					entry := statusEntry{Profile: "work", Attempt: 3, State: "connected", Wanted: true}
					if stopped {
						entry = tc.entry
						entry.Profile = "work"
						if entry.Attempt == 0 {
							entry.Attempt = 3
						}
					}
					return []statusEntry{entry}, nil, nil
				case "down":
					stopped = true
					return nil, nil, nil
				}
				return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected operation"}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			var out, diag bytes.Buffer
			code := RunContext(ctx, []string{"down", "--all"}, &out, &diag, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
			if code != 1 || !strings.Contains(diag.String(), tc.want) {
				t.Fatalf("code %d, diagnostics %s", code, &diag)
			}
		})
	}
}

// TestDownContinuesAfterRejection verifies another valid target is still stopped
// and cleaned when one selected profile does not exist.
func TestDownContinuesAfterRejection(t *testing.T) {
	stopped, verified := false, false
	socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
		switch req.Op {
		case "subscribe":
			return nil, nil, nil
		case "status":
			entry := statusEntry{Profile: "work", Attempt: 3, State: "connected", Wanted: true}
			if stopped {
				entry.State, entry.Wanted = "disconnected", false
				verified = true
			}
			return []statusEntry{entry}, nil, nil
		case "down":
			if req.Profile == "missing" {
				return nil, nil, &protocol.Error{Code: protocol.NotFound, Message: "profile not found"}
			}
			stopped = true
			return nil, nil, nil
		}
		return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected operation"}
	})
	code, _, diag := runCommand(t, []string{"down", "missing", "work"}, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
	if code != 1 || !stopped || !verified || !strings.Contains(diag, "missing") {
		t.Fatalf("code %d, stopped %v, verified %v, diagnostics %s", code, stopped, verified, diag)
	}
}
