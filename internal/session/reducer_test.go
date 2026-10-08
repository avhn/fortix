package session

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/openfortivpn"
)

// input stamps a reducer input with its session's authoritative profile and generation.
// Tests add payloads after construction, avoiding accidental identity mismatches.
func input(s State, kind EventKind) Event {
	return Event{Profile: s.Profile, Attempt: s.Attempt, Kind: kind, Jitter: 0.5}
}

// apply runs Next with a stamped kind and requires the expected resulting phase.
// It fails t on a phase mismatch and returns the state and effect data for inspection.
func apply(t testing.TB, s State, kind EventKind, phase Phase) (State, []Effect) {
	t.Helper()
	next, effects := Next(s, input(s, kind))
	if next.Phase != phase {
		t.Fatalf("%s + %s = %s, want %s", s.Phase, kind, next.Phase, phase)
	}
	return next, effects
}

// observe runs one stamped stdout event and checks its resulting phase.
// It preserves the returned effects so tests can inspect networking and failure actions.
func observe(t testing.TB, s State, event openfortivpn.Event, phase Phase) (State, []Effect) {
	t.Helper()
	e := input(s, Output)
	e.Observation = event
	next, effects := Next(s, e)
	if next.Phase != phase {
		t.Fatalf("%s + %T = %s, want %s", s.Phase, event, next.Phase, phase)
	}
	return next, effects
}

// hasEffect returns whether effects include kind without modifying the action list.
// It is used for behavior assertions rather than depending on unrelated action ordering.
func hasEffect(effects []Effect, kind EffectKind) bool {
	for _, e := range effects {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// connectedSession drives a complete successful transcript and helper network result.
// It requires all phases and the ApplyNetwork effect, returning a connected session.
func connectedSession(t testing.TB, mode string) State {
	t.Helper()
	s, effects := apply(t, New("work", Options{MFAMode: mode}), Up, Starting)
	if !hasEffect(effects, StartProcess) || s.Attempt != 1 {
		t.Fatal("child not requested")
	}
	s, _ = observe(t, s, openfortivpn.ConnectedToGateway{}, Authenticating)
	s, _ = observe(t, s, openfortivpn.Authenticated{}, Negotiating)
	s, _ = observe(t, s, openfortivpn.VPNAllocated{}, Negotiating)
	s, _ = observe(t, s, openfortivpn.GotAddresses{LocalIP: netip.MustParseAddr("10.20.0.10"), DNS: []netip.Addr{netip.MustParseAddr("10.20.0.1")}, Suffix: "corp.example.com"}, Negotiating)
	s, _ = observe(t, s, openfortivpn.NegotiationComplete{}, Negotiating)
	s, _ = observe(t, s, openfortivpn.InterfaceUp{Name: "ppp0"}, Negotiating)
	s, effects = observe(t, s, openfortivpn.TunnelUp{}, Configuring)
	if !hasEffect(effects, ApplyNetwork) {
		t.Fatal("network application not requested")
	}
	s, _ = apply(t, s, NetworkApplied, Connected)
	return s
}

// cleanStop acknowledges process exit and resource cleanup, requiring the final phase.
// It proves cleanup starts only after exit and no premature retry or trust prompt occurs.
func cleanStop(t testing.TB, s State, target Phase) (State, []Effect) {
	t.Helper()
	if !s.Exited {
		var effects []Effect
		s, effects = apply(t, s, ProcessExited, Stopping)
		if !hasEffect(effects, RemoveNetwork) || hasEffect(effects, StartProcess) || hasEffect(effects, EmitCert) {
			t.Fatal("incorrect exit cleanup effects")
		}
	}
	return apply(t, s, CleanupDone, target)
}

// TestCredentialTransitions covers password and unexpected code prompts, answers,
// repeated challenges, push budgets, and late TLS messages while waiting on a human.
func TestCredentialTransitions(t *testing.T) {
	for _, mode := range []string{"none", "push"} {
		s, _ := apply(t, New("work", Options{MFAMode: mode}), Up, Starting)
		e := input(s, Challenge)
		e.Request = openfortivpn.Request{Kind: openfortivpn.Password, KeyInfo: "work_password", Prompt: "Password"}
		s, effects := Next(s, e)
		if s.Phase != WaitingPassword || !hasEffect(effects, EmitChallenge) {
			t.Fatal("password not requested")
		}
		timer := s.TimerID
		e.Attempt = s.Attempt
		again, effects := Next(s, e)
		if !reflect.DeepEqual(s, again) || effects != nil || s.TimerID != timer {
			t.Fatal("duplicate challenge restarted deadline")
		}
		s, effects = observe(t, s, openfortivpn.ConnectedToGateway{}, WaitingPassword)
		if effects != nil {
			t.Fatal("TLS message interrupted prompt")
		}
		s, effects = apply(t, s, CredentialsAnswered, Authenticating)
		want := 60 * time.Second
		if mode == "push" {
			want = 120 * time.Second
		}
		for _, effect := range effects {
			if effect.Kind == StartTimer && effect.Duration != want {
				t.Fatalf("wrong authentication deadline: %s", effect.Duration)
			}
		}
		e = input(s, Challenge)
		e.Request = openfortivpn.Request{Kind: openfortivpn.Code, KeyInfo: "work_otp", Prompt: "Code"}
		s, effects = Next(s, e)
		if s.Phase != WaitingCode || !hasEffect(effects, EmitChallenge) {
			t.Fatal("unexpected code was not routed")
		}
		s, _ = apply(t, s, CredentialsAnswered, Authenticating)
		s, _ = observe(t, s, openfortivpn.Authenticated{}, Negotiating)
		if s.TimerID <= timer {
			t.Fatal("timer generation not advanced")
		}
	}
}

// TestDownLifecycle checks SIGTERM, the ten-second escalation, cleanup gating, and
// idempotence. Down during failure cleanup must suppress a pending reconnect.
func TestDownLifecycle(t *testing.T) {
	s := connectedSession(t, "none")
	s, effects := apply(t, s, Down, Stopping)
	if s.Wanted || s.Target != Disconnected || !hasEffect(effects, StopProcess) || hasEffect(effects, RemoveNetwork) {
		t.Fatal("unsafe stop lifecycle")
	}
	before := s
	s, _ = apply(t, s, Down, Stopping)
	if s.TimerID != before.TimerID || s.Exited {
		t.Fatal("repeated down restarted cleanup")
	}
	if got, effects := Next(s, input(s, CleanupDone)); !reflect.DeepEqual(got, s) || effects != nil {
		t.Fatal("cleanup acknowledged before child exit")
	}
	e := input(s, Deadline)
	e.TimerID = s.TimerID
	s, effects = Next(s, e)
	if s.Phase != Stopping || !hasEffect(effects, KillProcess) || !hasEffect(effects, StartTimer) || !s.TimerActive || s.TimerID == e.TimerID {
		t.Fatal("stop deadline did not escalate")
	}
	if again, effects := Next(s, e); !reflect.DeepEqual(again, s) || effects != nil {
		t.Fatal("repeated timer escalated twice")
	}
	s, _ = cleanStop(t, s, Disconnected)
	if s.Detail != "" || !s.Exited || !s.Cleaned {
		t.Fatal("incomplete disconnected state")
	}
	s, _ = apply(t, s, Up, Starting)
	if s.Attempt != 2 {
		t.Fatal("new attempt reused generation")
	}
}

// TestFailurePolicy checks every non-retrying failure and successful cleanup.
// Status-zero early exits must fail, and authentication errors never request backoff.
func TestFailurePolicy(t *testing.T) {
	for _, reason := range []Failure{AuthFailure, CertFailure, ConflictFailure, NetworkFailure, TimeoutFailure, ProcessFailure, CancelledFailure, TunnelFailure, ""} {
		t.Run(string(reason), func(t *testing.T) {
			s := connectedSession(t, "none")
			e := input(s, AttemptFailed)
			e.Failure = reason
			s, effects := Next(s, e)
			if s.Phase != Stopping || s.Target != Failed || !hasEffect(effects, StopProcess) {
				t.Fatal("failure did not stop")
			}
			s, effects = cleanStop(t, s, Failed)
			if s.TimerActive || hasEffect(effects, StartTimer) || hasEffect(effects, StartProcess) {
				t.Fatal("terminal failure automatically retried")
			}
			s, _ = apply(t, s, Reset, Disconnected)
			if s.Wanted || s.Failure != "" {
				t.Fatal("failure not reset")
			}
		})
	}
	for _, mode := range []string{"none", "push"} {
		s, _ := apply(t, New("work", Options{MFAMode: mode}), Up, Starting)
		e := input(s, ProcessExited)
		e.ExitCode = 0
		s, effects := Next(s, e)
		if s.Target != Failed || s.Failure != ProcessFailure || !hasEffect(effects, RemoveNetwork) || hasEffect(effects, StopProcess) {
			t.Fatal("zero early exit was not a failure")
		}
		s, _ = cleanStop(t, s, Failed)
		s, _ = apply(t, s, Up, Starting)
		if s.Attempt != 2 {
			t.Fatal("explicit retry failed")
		}
	}
}

// TestOutputFailures checks fatal stdout observations and incomplete networking.
// Raw unknown lines never fail a session, including lines with an ERROR prefix.
func TestOutputFailures(t *testing.T) {
	cases := []struct {
		event  openfortivpn.Event
		reason Failure
	}{
		{openfortivpn.AuthFailed{}, AuthFailure},
		{openfortivpn.TunnelModeDenied{}, TunnelFailure},
		{openfortivpn.PPPFailure{Message: "pppd: We failed to authenticate ourselves to the peer."}, AuthFailure},
		{openfortivpn.PPPFailure{Message: "pppd: The peer system failed (or refused) to authenticate itself."}, AuthFailure},
		{openfortivpn.PPPFailure{Message: "pppd: options failed"}, ProcessFailure},
		{openfortivpn.Teardown{Message: "Closed connection to gateway."}, ProcessFailure},
		{openfortivpn.LoggedOut{}, ProcessFailure},
	}
	for _, tc := range cases {
		s, _ := apply(t, New("work", Options{}), Up, Starting)
		s, _ = observe(t, s, tc.event, Stopping)
		if s.Target != Failed || s.Failure != tc.reason {
			t.Fatalf("%T failure became %s -> %s", tc.event, s.Failure, s.Target)
		}
	}
	s := connectedSession(t, "none")
	if next, effects := observe(t, s, openfortivpn.Unknown{Line: "ERROR:  unrecognized"}, Connected); !reflect.DeepEqual(next, s) || effects != nil {
		t.Fatal("unknown diagnostic changed state")
	}
	for _, fields := range []State{{}, {LocalIP: netip.MustParseAddr("10.20.0.10")}, {Interface: "ppp0"}} {
		s, _ := apply(t, New("work", Options{}), Up, Starting)
		s, _ = observe(t, s, openfortivpn.Authenticated{}, Negotiating)
		s.LocalIP, s.Interface = fields.LocalIP, fields.Interface
		s, effects := observe(t, s, openfortivpn.TunnelUp{}, Stopping)
		if s.Failure != NetworkFailure || hasEffect(effects, ApplyNetwork) {
			t.Fatal("incomplete tunnel metadata reached networking")
		}
	}
}

// TestCertificateTrust checks cleanup before prompting, exact digest confirmation,
// persistence before restart, stale replies, and refusal of incomplete certificate data.
func TestCertificateTrust(t *testing.T) {
	for _, digest := range []string{strings.Repeat("a", 64), "", strings.Repeat("g", 64), strings.Repeat("A", 64)} {
		s, _ := apply(t, New("work", Options{}), Up, Starting)
		cert := openfortivpn.CertRejected{Digest: digest, Subject: "CN=vpn.example.com", Issuer: "CN=Example CA"}
		s, effects := observe(t, s, cert, Stopping)
		if hasEffect(effects, EmitCert) || hasEffect(effects, StartProcess) {
			t.Fatal("certificate trust exposed before cleanup")
		}
		target := Failed
		if digest == strings.Repeat("a", 64) {
			target = WaitingTrust
		}
		s, effects = cleanStop(t, s, target)
		if target == Failed {
			if hasEffect(effects, EmitCert) {
				t.Fatal("invalid digest prompted trust")
			}
			continue
		}
		if !hasEffect(effects, EmitCert) || s.TimerActive {
			t.Fatal("missing trust prompt or automatic deadline")
		}
		for _, wrong := range []string{"", strings.Repeat("b", 64)} {
			e := input(s, Trust)
			e.Digest = wrong
			if next, effects := Next(s, e); !reflect.DeepEqual(next, s) || effects != nil {
				t.Fatal("unobserved digest accepted")
			}
		}
		e := input(s, Trust)
		e.Digest = digest
		next, effects := Next(s, e)
		if next.Phase != Starting || next.Attempt != s.Attempt+1 || effects[0].Kind != PersistTrust || effects[0].Certificate != cert || !hasEffect(effects, StartProcess) {
			t.Fatal("confirmed trust did not persist before restart")
		}
		if again, effects := Next(next, e); !reflect.DeepEqual(again, next) || effects != nil {
			t.Fatal("old confirmation reused")
		}
	}
}

// TestTransportReconnect checks cleanup-gated backoff and timer-bound generations.
// Push allows one reconnect, then requires an explicit Up to prevent approval floods.
func TestTransportReconnect(t *testing.T) {
	for _, event := range []openfortivpn.Event{openfortivpn.Teardown{Message: "Closed connection to gateway."}, openfortivpn.PPPFailure{Message: "pppd: The peer is not responding"}, openfortivpn.LoggedOut{}} {
		s := connectedSession(t, "none")
		s, _ = observe(t, s, event, Stopping)
		if s.Target != Backoff || s.RetryDelay != time.Second || s.RetryCount != 1 {
			t.Fatal("transport loss did not schedule backoff")
		}
		if next, effects := Next(s, input(s, Up)); !reflect.DeepEqual(next, s) || effects != nil {
			t.Fatal("new child allowed before cleanup")
		}
		s, _ = cleanStop(t, s, Backoff)
		e := input(s, Deadline)
		e.TimerID = s.TimerID
		next, effects := Next(s, e)
		if next.Phase != Starting || next.Attempt != 2 || !hasEffect(effects, StartProcess) || next.RetryCount != 1 {
			t.Fatal("backoff timer did not start a new generation")
		}
		if again, effects := Next(next, e); !reflect.DeepEqual(again, next) || effects != nil {
			t.Fatal("old retry timer reused")
		}
	}
	s := connectedSession(t, "push")
	s, _ = apply(t, s, ProcessExited, Stopping)
	if s.Target != Backoff {
		t.Fatal("first push reconnect refused")
	}
	s, _ = cleanStop(t, s, Backoff)
	e := input(s, Deadline)
	e.TimerID = s.TimerID
	s, _ = Next(s, e)
	s, _ = observe(t, s, openfortivpn.Authenticated{}, Negotiating)
	s, _ = observe(t, s, openfortivpn.GotAddresses{LocalIP: netip.MustParseAddr("10.20.0.10")}, Negotiating)
	s, _ = observe(t, s, openfortivpn.InterfaceUp{Name: "ppp0"}, Negotiating)
	s, _ = observe(t, s, openfortivpn.TunnelUp{}, Configuring)
	s, _ = apply(t, s, NetworkApplied, Connected)
	s, _ = apply(t, s, ProcessExited, Stopping)
	if s.Target != Failed {
		t.Fatal("flapping gateway could flood push approvals")
	}
}

// TestPhaseDeadlines verifies every phase's default and custom budget, cancelled timer
// isolation, and timeout failure policy. Duplicate milestones cannot extend a phase.
func TestPhaseDeadlines(t *testing.T) {
	defaults := DefaultDeadlines()
	if defaults != (Deadlines{30 * time.Second, 60 * time.Second, 120 * time.Second, 75 * time.Second, 10 * time.Second, 10 * time.Second}) {
		t.Fatalf("unexpected deadline defaults: %+v", defaults)
	}
	for _, phase := range []Phase{Starting, WaitingPassword, WaitingCode, Authenticating, Negotiating, Configuring} {
		s := New("work", Options{})
		s.Attempt, s.Phase, s.Wanted, s.TimerID, s.TimerActive = 1, phase, true, 7, true
		e := input(s, Deadline)
		e.TimerID = 6
		if next, effects := Next(s, e); !reflect.DeepEqual(next, s) || effects != nil {
			t.Fatal("cancelled phase timer accepted")
		}
		e.TimerID = 7
		next, effects := Next(s, e)
		if next.Phase != Stopping || next.Target != Failed || next.Failure != TimeoutFailure || !hasEffect(effects, StopProcess) {
			t.Fatalf("%s deadline did not fail safely", phase)
		}
	}
	custom := Deadlines{time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second, 6 * time.Second}
	s := New("work", Options{Deadlines: custom})
	if s.Deadlines != custom || New("work", Options{Deadlines: Deadlines{Connect: -1}}).Deadlines != defaults {
		t.Fatal("deadline override/defaulting mismatch")
	}
	s, effects := apply(t, s, Up, Starting)
	for _, effect := range effects {
		if effect.Kind == StartTimer && effect.Duration != custom.Connect {
			t.Fatal("custom connect budget not used")
		}
	}
	old := input(s, Deadline)
	old.TimerID = s.TimerID
	s, _ = observe(t, s, openfortivpn.ConnectedToGateway{}, Authenticating)
	if next, effects := Next(s, old); !reflect.DeepEqual(next, s) || effects != nil {
		t.Fatal("old phase timer remained valid")
	}
}

// TestCleanupFailureAndOverrides checks duplicate acknowledgements, cleanup failure,
// Down suppression, and fatal log observations arriving during pending reconnect.
func TestCleanupFailureAndOverrides(t *testing.T) {
	s := connectedSession(t, "none")
	s, _ = apply(t, s, ProcessExited, Stopping)
	if again, effects := Next(s, input(s, ProcessExited)); !reflect.DeepEqual(again, s) || effects != nil {
		t.Fatal("duplicate exit started cleanup again")
	}
	s, _ = apply(t, s, CleanupFailed, Stopping)
	if s.Target != Failed || s.Cleaned {
		t.Fatal("failed cleanup allowed retry")
	}
	if again, effects := Next(s, input(s, Up)); !reflect.DeepEqual(again, s) || effects != nil {
		t.Fatal("new attempt allowed after failed cleanup")
	}
	s, _ = apply(t, s, CleanupDone, Failed)
	if again, effects := Next(s, input(s, CleanupDone)); !reflect.DeepEqual(again, s) || effects != nil {
		t.Fatal("duplicate cleanup changed state")
	}
	for _, observation := range []openfortivpn.Event{openfortivpn.AuthFailed{}, openfortivpn.CertRejected{Digest: strings.Repeat("a", 64)}} {
		s := connectedSession(t, "none")
		s, _ = apply(t, s, ProcessExited, Stopping)
		s, _ = observe(t, s, observation, Stopping)
		if s.Target == Backoff {
			t.Fatal("fatal observation did not suppress reconnect")
		}
		s, _ = apply(t, s, Down, Stopping)
		s, _ = cleanStop(t, s, Disconnected)
		if s.Wanted {
			t.Fatal("down not respected")
		}
	}
}

// TestGenerationIsolation exhaustively rejects every event kind for all twelve phases
// when profile or attempt is stale. It also checks unknown event kinds are no-ops.
func TestGenerationIsolation(t *testing.T) {
	phases := []Phase{Disconnected, Starting, WaitingPassword, WaitingCode, Authenticating, Negotiating, Configuring, Connected, WaitingTrust, Backoff, Stopping, Failed}
	kinds := []EventKind{Up, Down, Reset, Output, Challenge, CredentialsAnswered, ChallengeCancelled, Trust, Deadline, ProcessExited, CleanupDone, CleanupFailed, NetworkApplied, AttemptFailed, "unknown"}
	for _, phase := range phases {
		for _, kind := range kinds {
			s := New("work", Options{})
			s.Phase, s.Attempt, s.Wanted, s.TimerID, s.TimerActive = phase, 3, true, 5, true
			e := input(s, kind)
			e.Observation, e.Request.Kind, e.TimerID = openfortivpn.AuthFailed{}, openfortivpn.Code, s.TimerID
			for _, wrongProfile := range []bool{false, true} {
				stale := e
				if wrongProfile {
					stale.Profile = "other"
				} else {
					stale.Attempt--
				}
				if next, effects := Next(s, stale); !reflect.DeepEqual(next, s) || effects != nil {
					t.Fatalf("stale %s accepted in %s", kind, phase)
				}
			}
		}
	}
}

// TestNetworkCopies ensures reducer and effect DNS slices do not alias event data or
// earlier state, preserving pure reduction when the supervisor reuses buffers.
func TestNetworkCopies(t *testing.T) {
	s, _ := apply(t, New("work", Options{}), Up, Starting)
	s, _ = observe(t, s, openfortivpn.Authenticated{}, Negotiating)
	addresses := openfortivpn.GotAddresses{LocalIP: netip.MustParseAddr("10.20.0.10"), DNS: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}
	s, _ = observe(t, s, addresses, Negotiating)
	addresses.DNS[0] = netip.MustParseAddr("10.20.0.2")
	if s.DNS[0] == addresses.DNS[0] {
		t.Fatal("state aliases parser DNS buffer")
	}
	s, _ = observe(t, s, openfortivpn.InterfaceUp{Name: "ppp0"}, Negotiating)
	next, effects := observe(t, s, openfortivpn.TunnelUp{}, Configuring)
	for _, e := range effects {
		if e.Kind == ApplyNetwork {
			e.DNS[0] = addresses.DNS[0]
			if next.DNS[0] == e.DNS[0] || s.DNS[0] == e.DNS[0] || e.Interface != "ppp0" {
				t.Fatal("network effect aliases state")
			}
		}
	}
}

// TestTransitionMatrix exercises every input kind in every representative phase.
// Listed transitions must reach their target; unlisted inputs must preserve the entire
// state and emit nothing. Detailed tests separately assert payloads and cleanup ordering.
func TestTransitionMatrix(t *testing.T) {
	matrix := map[Phase]map[EventKind]Phase{
		Disconnected:    {Up: Starting},
		Starting:        {Down: Stopping, Output: Stopping, Challenge: WaitingPassword, Deadline: Stopping, ProcessExited: Stopping, AttemptFailed: Stopping},
		WaitingPassword: {Down: Stopping, Output: Stopping, CredentialsAnswered: Authenticating, ChallengeCancelled: Stopping, Deadline: Stopping, ProcessExited: Stopping, AttemptFailed: Stopping},
		WaitingCode:     {Down: Stopping, Output: Stopping, CredentialsAnswered: Authenticating, ChallengeCancelled: Stopping, Deadline: Stopping, ProcessExited: Stopping, AttemptFailed: Stopping},
		Authenticating:  {Down: Stopping, Output: Stopping, Challenge: WaitingPassword, Deadline: Stopping, ProcessExited: Stopping, AttemptFailed: Stopping},
		Negotiating:     {Down: Stopping, Output: Stopping, Deadline: Stopping, ProcessExited: Stopping, AttemptFailed: Stopping},
		Configuring:     {Down: Stopping, Output: Stopping, Deadline: Stopping, ProcessExited: Stopping, NetworkApplied: Connected, AttemptFailed: Stopping},
		Connected:       {Down: Stopping, Output: Stopping, ProcessExited: Stopping, AttemptFailed: Stopping},
		WaitingTrust:    {Down: Disconnected, Trust: Starting, Output: Failed},
		Backoff:         {Up: Starting, Down: Disconnected, Deadline: Starting, Output: Failed},
		Stopping:        {Up: Stopping, Down: Stopping, Output: Stopping, Deadline: Stopping, CleanupDone: Disconnected, CleanupFailed: Stopping},
		Failed:          {Up: Starting, Down: Disconnected, Reset: Disconnected},
	}
	kinds := []EventKind{Up, Down, Reset, Output, Challenge, CredentialsAnswered, ChallengeCancelled, Trust, Deadline, ProcessExited, CleanupDone, CleanupFailed, NetworkApplied, AttemptFailed, "unknown"}
	for phase, transitions := range matrix {
		for _, kind := range kinds {
			t.Run(string(phase)+"/"+string(kind), func(t *testing.T) {
				s := New("work", Options{})
				s.Phase, s.Attempt, s.Wanted = phase, 1, phase != Disconnected
				s.TimerID = 5
				s.TimerActive = phase == Backoff || phase == Stopping || (active(phase) && phase != Connected)
				s.Exited = !active(phase)
				s.Cleaned = s.Exited && phase != Stopping
				s.CleanupStarted = phase == Stopping
				s.Target = Disconnected
				s.Certificate.Digest = strings.Repeat("a", 64)
				e := input(s, kind)
				e.TimerID, e.Digest = s.TimerID, s.Certificate.Digest
				e.Observation = openfortivpn.AuthFailed{}
				e.Request.Kind = openfortivpn.Password
				e.Failure = AuthFailure
				next, effects := Next(s, e)
				if want, changes := transitions[kind]; changes {
					if next.Phase != want {
						t.Fatalf("got %s, want %s", next.Phase, want)
					}
				} else if !reflect.DeepEqual(next, s) || effects != nil {
					t.Fatalf("unexpected transition: %+v, %+v", next, effects)
				}
				if phase == Stopping && kind == Up && (!next.PendingUp || !next.Wanted || hasEffect(effects, StartProcess)) {
					t.Fatal("up was not queued behind cleanup")
				}
				for _, effect := range effects {
					if effect.Profile != s.Profile || (effect.Attempt != s.Attempt && effect.Attempt != next.Attempt) {
						t.Fatal("effect lost attempt identity")
					}
				}
			})
		}
	}
}

// TestGenerationExhaustion verifies attempt wraparound cannot revalidate old events.
// No process or timer may be requested when the generation space is exhausted.
func TestGenerationExhaustion(t *testing.T) {
	s := New("work", Options{})
	s.Attempt = ^uint64(0)
	next, effects := Next(s, input(s, Up))
	if next.Phase != Failed || next.Attempt != s.Attempt || next.Wanted || hasEffect(effects, StartProcess) || hasEffect(effects, StartTimer) {
		t.Fatal("attempt generation wrapped")
	}
}

// TestBufferedFatalOutput rejects retries after fatal observations buffered during
// cleanup or backoff. A newer certificate replaces the digest a human may confirm.
func TestBufferedFatalOutput(t *testing.T) {
	for _, phase := range []Phase{Stopping, Backoff} {
		for _, observation := range []openfortivpn.Event{
			openfortivpn.AuthFailed{}, openfortivpn.TunnelModeDenied{},
			openfortivpn.PPPFailure{Message: "pppd: We failed to authenticate ourselves to the peer."},
		} {
			s := connectedSession(t, "none")
			s, _ = apply(t, s, ProcessExited, Stopping)
			if phase == Backoff {
				s, _ = cleanStop(t, s, Backoff)
			}
			want := Failed
			if phase == Stopping {
				want = Stopping
			}
			s, effects := observe(t, s, observation, want)
			if s.Phase == Backoff || s.Target == Backoff && s.Phase == Stopping || hasEffect(effects, StartProcess) {
				t.Fatal("buffered rejection left automatic retry active")
			}
			if phase == Backoff && s.TimerActive {
				t.Fatal("retry timer survived rejection")
			}
		}
	}
	s, _ := apply(t, New("work", Options{}), Up, Starting)
	s, _ = observe(t, s, openfortivpn.CertRejected{Digest: strings.Repeat("a", 64)}, Stopping)
	s, _ = cleanStop(t, s, WaitingTrust)
	s, effects := observe(t, s, openfortivpn.CertRejected{Digest: strings.Repeat("b", 64)}, WaitingTrust)
	if s.Certificate.Digest != strings.Repeat("b", 64) || !hasEffect(effects, EmitCert) {
		t.Fatal("latest captured certificate was not shown")
	}
	e := input(s, Trust)
	e.Digest = strings.Repeat("a", 64)
	if next, effects := Next(s, e); !reflect.DeepEqual(next, s) || effects != nil {
		t.Fatal("old digest confirmation accepted after certificate change")
	}
	e.Digest = s.Certificate.Digest
	next, effects := Next(s, e)
	if effects[0].Kind != PersistTrust || effects[0].Attempt != next.Attempt {
		t.Fatal("trust persistence does not belong to the new attempt")
	}
	failed := input(next, AttemptFailed)
	failed.Attempt, failed.Failure = effects[0].Attempt, CertFailure
	next, _ = Next(next, failed)
	if next.Phase != Stopping || next.Target != Failed {
		t.Fatal("trust persistence failure could not stop the new attempt")
	}
}

// TestEmittedDeadlines checks the actual timer effects for all phase budget mappings,
// including code fallback in MFA none and push approval, with distinctive custom values.
func TestEmittedDeadlines(t *testing.T) {
	d := Deadlines{time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second, 6 * time.Second}
	cases := []struct {
		phase       Phase
		mode        string
		kind        EventKind
		observation openfortivpn.Event
		request     openfortivpn.Kind
		want        time.Duration
	}{
		{Disconnected, "none", Up, nil, "", d.Connect},
		{Starting, "none", Output, openfortivpn.ConnectedToGateway{}, "", d.Authenticate},
		{Starting, "push", Output, openfortivpn.ConnectedToGateway{}, "", d.Human},
		{Starting, "none", Challenge, nil, openfortivpn.Password, d.Human},
		{Authenticating, "none", Challenge, nil, openfortivpn.Code, d.Human},
		{Authenticating, "none", Output, openfortivpn.Authenticated{}, "", d.Negotiate},
		{Negotiating, "none", Output, openfortivpn.TunnelUp{}, "", d.Network},
		{Connected, "none", Down, nil, "", d.Stop},
	}
	for _, tc := range cases {
		s := New("work", Options{MFAMode: tc.mode, Deadlines: d})
		s.Phase, s.Attempt, s.Wanted = tc.phase, 1, true
		s.LocalIP, s.Interface = netip.MustParseAddr("10.20.0.10"), "ppp0"
		e := input(s, tc.kind)
		e.Observation, e.Request.Kind = tc.observation, tc.request
		_, effects := Next(s, e)
		found := false
		for _, effect := range effects {
			if effect.Kind == StartTimer {
				found = true
				if effect.Duration != tc.want {
					t.Fatalf("%s + %s: got %s, want %s", tc.phase, tc.kind, effect.Duration, tc.want)
				}
			}
		}
		if !found {
			t.Fatalf("%s + %s did not arm a timer", tc.phase, tc.kind)
		}
	}
}
