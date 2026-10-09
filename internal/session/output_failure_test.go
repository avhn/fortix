package session

import (
	"reflect"
	"testing"

	"github.com/avhn/fortix/internal/backend"
)

// TestOutputFailedLifecycle preserves the local stream failure cause without
// acknowledging process exit or removing resources before the terminal Outcome.
// Buffered failures suppress reconnect but cannot hide an existing cleanup failure.
func TestOutputFailedLifecycle(t *testing.T) {
	for _, phase := range []Phase{Starting, Authenticating, Negotiating, Configuring, Connected, Stopping, Backoff, WaitingTrust, Failed, Disconnected} {
		t.Run(string(phase), func(t *testing.T) {
			s := New("work", Options{})
			s.Attempt, s.Phase, s.Wanted = 1, phase, true
			s.Exited, s.Cleaned = false, false
			s.Target, s.Failure = Backoff, TransportFailure
			e := input(s, Output)
			e.Observation = backend.OutputFailed{}
			next, effects := Next(s, e)
			if phase == Failed || phase == Disconnected {
				if !reflect.DeepEqual(next, s) || effects != nil {
					t.Fatal("idle stream failure changed state")
				}
				return
			}
			if next.Failure != NetworkFailure || next.Detail != "helper log or output stream failed" || next.Exited || next.Cleaned || hasEffect(effects, RemoveNetwork) || hasEffect(effects, StartProcess) {
				t.Fatalf("local failure lost cause or acknowledged exit: %+v %+v", next, effects)
			}
			if active(phase) {
				if next.Phase != Stopping || next.Target != Failed || !hasEffect(effects, StopProcess) {
					t.Fatal("stream failure did not request transport shutdown")
				}
				terminal := input(next, Output)
				terminal.Observation = backend.Outcome{}
				finished, effects := Next(next, terminal)
				if !finished.Exited || finished.Failure != NetworkFailure || finished.Detail != next.Detail || !hasEffect(effects, RemoveNetwork) {
					t.Fatal("terminal outcome lost cause or omitted cleanup")
				}
			}
			if phase == Stopping {
				s.CleanupRetries = 1
				next, effects = Next(s, e)
				if !reflect.DeepEqual(next, s) || effects != nil {
					t.Fatal("buffered stream failure hid failed cleanup")
				}
			}
			e.Attempt--
			if stale, effects := Next(s, e); !reflect.DeepEqual(stale, s) || effects != nil {
				t.Fatal("stale stream failure changed state")
			}
		})
	}
}
