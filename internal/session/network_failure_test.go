package session

import "testing"

// TestNetworkRefusal verifies pre-spawn refusals are terminal but immediately editable,
// and post-spawn conflicts retain their specific detail through stop and cleanup.
func TestNetworkRefusal(t *testing.T) {
	for _, phase := range []Phase{Disconnected, Backoff, Failed} {
		t.Run(string(phase), func(t *testing.T) {
			s := New("work", Options{})
			s.Phase, s.Exited, s.Cleaned = phase, true, true
			s.Attempt, s.Wanted = 3, true
			e := Event{Profile: "work", Attempt: 3, Kind: UpRefused, Failure: ConflictFailure, Detail: "another full tunnel is active"}
			next, effects := Next(s, e)
			if next.Phase != Failed || next.Failure != ConflictFailure || next.Detail != e.Detail || !next.Wanted || !next.Cleaned || !next.Exited {
				t.Fatalf("refusal state: %+v", next)
			}
			for _, effect := range effects {
				if effect.Kind == StartProcess || effect.Kind == RemoveNetwork {
					t.Fatal("pre-spawn refusal requested privileged effects")
				}
			}
			next, _ = Next(next, Event{Profile: "work", Attempt: 3, Kind: Up})
			if next.Phase != Starting || next.Attempt != 4 {
				t.Fatal("refusal prevented a later explicit attempt")
			}
		})
	}
	s := New("work", Options{})
	s.Phase, s.Attempt, s.Wanted = Configuring, 1, true
	detail := "local IP is already used by another active tunnel"
	s, _ = Next(s, Event{Profile: "work", Attempt: 1, Kind: AttemptFailed, Failure: ConflictFailure, Detail: detail})
	if s.Phase != Stopping || s.Detail != detail || s.Target != Failed {
		t.Fatalf("live conflict did not request stop: %+v", s)
	}
	s, _ = Next(s, Event{Profile: "work", Attempt: 1, Kind: ProcessExited})
	s, _ = Next(s, Event{Profile: "work", Attempt: 1, Kind: CleanupDone})
	if s.Phase != Failed || s.Detail != detail || s.Failure != ConflictFailure {
		t.Fatalf("cleanup lost terminal conflict: %+v", s)
	}
}
