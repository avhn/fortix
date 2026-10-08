package session

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/openfortivpn"
)

// fireTimer submits the current timer identity and checks the resulting phase.
// It fails t unless a live timer exists, returning the new state and ordered effects.
func fireTimer(t testing.TB, s State, phase Phase) (State, []Effect) {
	t.Helper()
	if !s.TimerActive {
		t.Fatal("no timer armed")
	}
	e := input(s, Deadline)
	e.TimerID = s.TimerID
	next, effects := Next(s, e)
	if next.Phase != phase {
		t.Fatalf("%s deadline = %s, want %s", s.Phase, next.Phase, phase)
	}
	return next, effects
}

// TestReconnectResetsDelay checks that successful non-push attempts reset exponential
// timing across repeated drops, while automatic push reconnects retain their approval cap.
func TestReconnectResetsDelay(t *testing.T) {
	for _, mode := range []string{"none", "prompt", "totp", "static", "push"} {
		t.Run(mode, func(t *testing.T) {
			s := connectedSession(t, mode)
			s, _ = apply(t, s, ProcessExited, Stopping)
			if s.Target != Backoff || s.RetryDelay != time.Second {
				t.Fatal("first transport loss did not use initial delay")
			}
			s, _ = cleanStop(t, s, Backoff)
			s, _ = fireTimer(t, s, Starting)
			s, _ = observe(t, s, openfortivpn.Authenticated{}, Negotiating)
			s, _ = observe(t, s, openfortivpn.GotAddresses{LocalIP: netip.MustParseAddr("10.20.0.10")}, Negotiating)
			s, _ = observe(t, s, openfortivpn.InterfaceUp{Name: "ppp0"}, Negotiating)
			s, _ = observe(t, s, openfortivpn.TunnelUp{}, Configuring)
			s, _ = apply(t, s, NetworkApplied, Connected)
			if mode != "push" && s.RetryCount != 0 {
				t.Fatal("successful reconnect retained exponential counter")
			}
			s, _ = apply(t, s, ProcessExited, Stopping)
			if mode == "push" {
				if !s.PushRetried || s.Target != Failed {
					t.Fatal("push approval cap lost on successful reconnect")
				}
				s, _ = cleanStop(t, s, Failed)
				s, _ = apply(t, s, Up, Starting)
				if s.PushRetried || s.RetryCount != 0 {
					t.Fatal("explicit up did not reset push retry budget")
				}
			} else if s.Target != Backoff || s.RetryDelay != time.Second || s.RetryCount != 1 {
				t.Fatal("second transport loss did not restart at initial delay")
			}
		})
	}
}

// TestCleanupRecovery covers failure replies and stalled removals through the retry
// budget, preserving failures on Down and buffered output. Reset requests cleanup only;
// neither it nor Up may start a child while resources remain unacknowledged.
func TestCleanupRecovery(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "timeout"}[timeout], func(t *testing.T) {
			s := connectedSession(t, "none")
			s, _ = apply(t, s, ProcessExited, Stopping)
			for retry := uint32(0); retry <= maxCleanupRetries; retry++ {
				phase := Stopping
				if retry == maxCleanupRetries {
					phase = Failed
				}
				var effects []Effect
				if timeout {
					s, effects = fireTimer(t, s, phase)
				} else {
					s, effects = apply(t, s, CleanupFailed, phase)
				}
				if s.Cleaned || s.Target != Failed || s.Failure != NetworkFailure || hasEffect(effects, StartProcess) {
					t.Fatal("cleanup failure lost safety gate")
				}
				if phase == Failed {
					if s.TimerActive || hasEffect(effects, StartTimer) {
						t.Fatal("cleanup budget did not bound automatic retries")
					}
					break
				}
				if s.CleanupRetries != retry+1 || !s.CleanupRetryPending || !hasEffect(effects, StartTimer) {
					t.Fatal("failed cleanup did not schedule a retry")
				}
				before := s
				if next, effects := Next(s, input(s, CleanupFailed)); !reflect.DeepEqual(next, before) || effects != nil {
					t.Fatal("duplicate failure consumed retry budget")
				}
				s, _ = apply(t, s, Down, Stopping)
				if s.Target != Failed || s.Detail != before.Detail {
					t.Fatal("down hid cleanup failure")
				}
				for _, observation := range []openfortivpn.Event{openfortivpn.AuthFailed{}, openfortivpn.CertRejected{Digest: strings.Repeat("a", 64)}} {
					next, effects := observe(t, s, observation, Stopping)
					if !reflect.DeepEqual(next, s) || effects != nil {
						t.Fatal("buffered output hid cleanup failure")
					}
				}
				old := input(s, Deadline)
				old.TimerID = s.TimerID
				s, effects = fireTimer(t, s, Stopping)
				if !hasEffect(effects, RemoveNetwork) || !s.TimerActive || s.CleanupRetryPending {
					t.Fatal("retry timer did not request timed cleanup")
				}
				if next, effects := Next(s, old); !reflect.DeepEqual(next, s) || effects != nil {
					t.Fatal("stale cleanup timer reused")
				}
			}
			if next, effects := Next(s, input(s, Up)); !reflect.DeepEqual(next, s) || effects != nil {
				t.Fatal("up bypassed exhausted cleanup")
			}
			s, effects := apply(t, s, Reset, Stopping)
			if !hasEffect(effects, RemoveNetwork) || hasEffect(effects, StartProcess) || !s.TimerActive || s.CleanupRetries != 0 {
				t.Fatal("reset did not retry cleanup safely")
			}
			s, _ = apply(t, s, CleanupDone, Failed)
			if !s.Cleaned || s.TimerActive {
				t.Fatal("successful recovery did not finish cleanup")
			}
			s, _ = apply(t, s, Reset, Disconnected)
			s, _ = apply(t, s, Up, Starting)
			if s.Attempt != 2 {
				t.Fatal("recovered session could not restart")
			}
		})
	}
}

// TestRepeatedStopEscalation proves a missing exit acknowledgement cannot strand a
// stop without a timer. Each fresh deadline repeats verified killing without cleanup.
func TestRepeatedStopEscalation(t *testing.T) {
	s := connectedSession(t, "none")
	s, _ = apply(t, s, Down, Stopping)
	for range 3 {
		old := input(s, Deadline)
		old.TimerID = s.TimerID
		next, effects := fireTimer(t, s, Stopping)
		if !hasEffect(effects, KillProcess) || !hasEffect(effects, StartTimer) || hasEffect(effects, RemoveNetwork) || next.TimerID == s.TimerID {
			t.Fatal("stop escalation did not remain scheduled")
		}
		if again, effects := Next(next, old); !reflect.DeepEqual(again, next) || effects != nil {
			t.Fatal("stale stop timer accepted")
		}
		s = next
	}
	s, _ = cleanStop(t, s, Disconnected)
}

// TestQueuedUp checks quick down/up ordering, repeated requests, cancellation by a
// later Down, and suppression after cleanup failure or buffered authentication rejection.
func TestQueuedUp(t *testing.T) {
	for _, cancel := range []string{"", "down", "cleanup_failure", "auth_failure"} {
		t.Run(cancel, func(t *testing.T) {
			s := connectedSession(t, "push")
			s.PushRetried = true
			s, _ = apply(t, s, Down, Stopping)
			for range 2 {
				var effects []Effect
				s, effects = apply(t, s, Up, Stopping)
				if !s.PendingUp || !s.Wanted || hasEffect(effects, StartProcess) {
					t.Fatal("up not queued behind stopping")
				}
			}
			s, _ = apply(t, s, ProcessExited, Stopping)
			want := Starting
			switch cancel {
			case "down":
				s, _ = apply(t, s, Down, Stopping)
				want = Disconnected
			case "cleanup_failure":
				s, _ = apply(t, s, CleanupFailed, Stopping)
				want = Failed
			case "auth_failure":
				s, _ = observe(t, s, openfortivpn.AuthFailed{}, Stopping)
				want = Failed
			}
			s, effects := apply(t, s, CleanupDone, want)
			if s.PendingUp || hasEffect(effects, StartProcess) != (want == Starting) {
				t.Fatal("queued up ignored cancellation or bypassed cleanup")
			}
			if want == Starting && (s.Attempt != 2 || s.PushRetried || s.RetryCount != 0) {
				t.Fatal("queued explicit up did not start fresh attempt")
			}
		})
	}
}
