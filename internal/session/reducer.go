package session

import (
	"net/netip"
	"strings"
	"time"

	"github.com/avhn/fortix/internal/openfortivpn"
)

// maxCleanupRetries bounds automatic retries after failed or stalled resource removal.
// Exhaustion requires an explicit Reset and never permits a child with leaked resources.
const maxCleanupRetries = 3

// Next returns the state and ordered effects for e without mutating s or doing I/O.
// Wrong profile/generation, stale timers, and inputs inappropriate to the phase are
// ignored. Failures stop the child before cleanup; only completed cleanup permits
// trust confirmation, reconnect, or another attempt. Credentials are never inputs.
// The supervisor executes effects and sends their outcomes back with the same identity.
func Next(s State, e Event) (State, []Effect) {
	if e.Profile != s.Profile || e.Attempt != s.Attempt {
		return s, nil
	}
	switch e.Kind {
	case Up:
		if s.Phase == Disconnected || (s.Phase == Failed && s.Exited && s.Cleaned) || s.Phase == Backoff {
			s.RetryCount, s.PushRetried = 0, false
			return beginAttempt(s)
		}
		if s.Phase == Stopping && s.Target == Disconnected && s.CleanupRetries == 0 {
			s.Wanted, s.PendingUp = true, true
			return s, []Effect{stateEffect(s)}
		}
	case Down:
		return down(s)
	case Reset:
		if s.Phase == Failed && s.Exited {
			s.Wanted, s.PendingUp = false, false
			if !s.Cleaned {
				s.CleanupRetries, s.CleanupRetryPending = 0, false
				return beginStop(s, Failed, "retrying network cleanup")
			}
			s.Failure = ""
			return transition(s, Disconnected, "", 0)
		}
	case Trust:
		if s.Phase == WaitingTrust && s.Wanted && s.Certificate.Digest != "" && e.Digest == s.Certificate.Digest {
			next, effects := beginAttempt(s)
			// Persistence failures must belong to the new generation so they can stop it.
			persist := effect(next, PersistTrust)
			persist.Certificate = s.Certificate
			return next, append([]Effect{persist}, effects...)
		}
	case Deadline:
		return deadline(s, e)
	case ProcessExited:
		return processExited(s, e)
	case CleanupDone:
		if (s.Phase == Stopping || s.Phase == Failed) && s.Exited && s.CleanupStarted && !s.Cleaned {
			s.Cleaned, s.CleanupRetryPending = true, false
			return finishStop(s)
		}
	case CleanupFailed:
		if s.Phase == Stopping && s.Exited && s.CleanupStarted && !s.Cleaned && !s.CleanupRetryPending {
			return cleanupFailed(s)
		}
	case Challenge:
		return challenge(s, e.Request)
	case CredentialsAnswered:
		if s.Phase == WaitingPassword || s.Phase == WaitingCode {
			return transition(s, Authenticating, "authenticating", authDeadline(s))
		}
	case ChallengeCancelled:
		if s.Phase == WaitingPassword || s.Phase == WaitingCode {
			return fail(s, CancelledFailure, e.Jitter)
		}
	case Output:
		return output(s, e)
	case NetworkApplied:
		if s.Phase == Configuring {
			if s.MFAMode != "push" {
				s.RetryCount = 0
			}
			return transition(s, Connected, "connected", 0)
		}
	case AttemptFailed:
		if active(s.Phase) {
			reason := e.Failure
			if reason == "" {
				reason = ProcessFailure
			}
			return fail(s, reason, e.Jitter)
		}
	}
	return s, nil
}

// beginAttempt increments generation, clears attempt metadata, and requests a child.
// Existing timers are cancelled under their old generation before the new timer starts.
// Generation exhaustion fails safely instead of making old replies valid again.
func beginAttempt(s State) (State, []Effect) {
	var effects []Effect
	if s.TimerActive {
		effects = append(effects, timerEffect(s, CancelTimer, 0))
		s.TimerActive = false
	}
	if s.Attempt == ^uint64(0) {
		s.Phase, s.Detail, s.Wanted = Failed, "attempt generation exhausted", false
		return s, append(effects, stateEffect(s))
	}
	s.Attempt++
	s.Wanted, s.PendingUp = true, false
	s.Exited, s.Cleaned, s.CleanupStarted = false, false, false
	s.CleanupRetries, s.CleanupRetryPending = 0, false
	s.Target, s.Failure, s.RetryDelay = "", "", 0
	s.LocalIP, s.DNS, s.Suffix, s.Interface = netip.Addr{}, nil, "", ""
	s.Certificate = openfortivpn.CertRejected{}
	next, entered := transition(s, Starting, "starting", s.Deadlines.Connect)
	effects = append(effects, entered...)
	return next, append(effects, effect(next, StartProcess))
}

// transition changes phase/detail, cancels any old timer, and arms duration if positive.
// It always emits a state notification; each new timer receives a distinct identifier.
func transition(s State, phase Phase, detail string, duration time.Duration) (State, []Effect) {
	effects := make([]Effect, 0, 3)
	if s.TimerActive {
		effects = append(effects, timerEffect(s, CancelTimer, 0))
	}
	s.Phase, s.Detail, s.TimerActive = phase, detail, duration > 0
	if s.TimerActive {
		s.TimerID++
		effects = append(effects, timerEffect(s, StartTimer, duration))
	}
	return s, append(effects, stateEffect(s))
}

// active reports whether phase can receive process, authentication, or network events.
// Idle, cleanup, trust, and backoff phases cannot advance the old child.
func active(phase Phase) bool {
	switch phase {
	case Starting, WaitingPassword, WaitingCode, Authenticating, Negotiating, Configuring, Connected:
		return true
	default:
		return false
	}
}

// down removes desired connectivity and stops active work, or cancels an idle retry.
// During cleanup it cancels queued Up but preserves cleanup failures and acknowledgements.
func down(s State) (State, []Effect) {
	s.Wanted, s.PendingUp = false, false
	switch {
	case active(s.Phase):
		return beginStop(s, Disconnected, "stopping")
	case s.Phase == Stopping:
		if s.CleanupRetries == 0 {
			s.Target, s.Detail = Disconnected, "stopping"
		}
		return s, []Effect{stateEffect(s)}
	case s.Phase == WaitingTrust || s.Phase == Backoff || (s.Phase == Failed && s.Cleaned):
		return transition(s, Disconnected, "", 0)
	default:
		return s, nil
	}
}

// authDeadline selects the push/human budget or ordinary authentication budget.
// Push delivery is not observable, so its duration never implies a delivered prompt.
func authDeadline(s State) time.Duration {
	if s.MFAMode == "push" {
		return s.Deadlines.Human
	}
	return s.Deadlines.Authenticate
}

// challenge enters password or code waiting from a valid authentication phase.
// Invalid kinds are ignored. Identical repeated requests cannot reset a live deadline.
func challenge(s State, request openfortivpn.Request) (State, []Effect) {
	if s.Phase != Starting && s.Phase != Authenticating && s.Phase != WaitingPassword && s.Phase != WaitingCode {
		return s, nil
	}
	phase := WaitingPassword
	if request.Kind == openfortivpn.Code {
		phase = WaitingCode
	} else if request.Kind != openfortivpn.Password {
		return s, nil
	}
	if s.Phase == WaitingPassword || s.Phase == WaitingCode {
		return s, nil
	}
	next, effects := transition(s, phase, "credential required", s.Deadlines.Human)
	prompt := effect(next, EmitChallenge)
	prompt.Request = request
	return next, append(effects, prompt)
}

// output applies known stdout observations and ignores diagnostic text.
// Fatal authentication or certificate observations can override a pending reconnect,
// but no output can resume a child while cleanup is underway.
func output(s State, e Event) (State, []Effect) {
	if s.Phase == Stopping || s.Phase == Backoff || s.Phase == WaitingTrust {
		if s.Phase == Stopping && s.CleanupRetries > 0 {
			// Buffered diagnostics cannot hide leaked resources or enable trust/reconnect.
			return s, nil
		}
		// Buffered fatal output must suppress retry and replace an older trust digest.
		target, reason, detail := Phase(""), Failure(""), ""
		switch observed := e.Observation.(type) {
		case openfortivpn.AuthFailed:
			target, reason, detail = Failed, AuthFailure, "authentication rejected"
		case openfortivpn.TunnelModeDenied:
			target, reason, detail = Failed, TunnelFailure, "tunnel mode denied"
		case openfortivpn.PPPFailure:
			if pppAuthenticationFailure(observed.Message) {
				target, reason, detail = Failed, AuthFailure, "authentication rejected"
			}
		case openfortivpn.CertRejected:
			if s.Wanted {
				s.Certificate = observed
				target, reason, detail = trustTarget(observed), CertFailure, "certificate rejected"
			}
		}
		if target == "" {
			return s, nil
		}
		s.Failure = reason
		if s.Phase == Stopping {
			s.PendingUp = false
			s.Target, s.Detail = target, detail
			return s, []Effect{stateEffect(s)}
		}
		next, effects := transition(s, target, detail, 0)
		if target == WaitingTrust {
			cert := effect(next, EmitCert)
			cert.Certificate = s.Certificate
			effects = append(effects, cert)
		}
		return next, effects
	}
	if !active(s.Phase) {
		return s, nil
	}
	switch observed := e.Observation.(type) {
	case openfortivpn.ConnectedToGateway:
		if s.Phase == Starting {
			return transition(s, Authenticating, "authenticating", authDeadline(s))
		}
	case openfortivpn.Authenticated:
		if s.Phase == Starting || s.Phase == Authenticating {
			return transition(s, Negotiating, "negotiating", s.Deadlines.Negotiate)
		}
	case openfortivpn.AuthFailed:
		return fail(s, AuthFailure, e.Jitter)
	case openfortivpn.TunnelModeDenied:
		return fail(s, TunnelFailure, e.Jitter)
	case openfortivpn.CertRejected:
		s.Certificate, s.Failure = observed, CertFailure
		return beginStop(s, trustTarget(observed), "certificate rejected")
	case openfortivpn.GotAddresses:
		if s.Phase == Negotiating {
			s.LocalIP, s.DNS, s.Suffix = observed.LocalIP, append([]netip.Addr(nil), observed.DNS...), observed.Suffix
		}
	case openfortivpn.InterfaceUp:
		if s.Phase == Negotiating {
			s.Interface = observed.Name
		}
	case openfortivpn.TunnelUp:
		if s.Phase == Negotiating {
			if !s.LocalIP.IsValid() || s.Interface == "" {
				return fail(s, NetworkFailure, e.Jitter)
			}
			next, effects := transition(s, Configuring, "configuring network", s.Deadlines.Network)
			apply := effect(next, ApplyNetwork)
			apply.LocalIP, apply.DNS, apply.Suffix, apply.Interface = s.LocalIP, append([]netip.Addr(nil), s.DNS...), s.Suffix, s.Interface
			return next, append(effects, apply)
		}
	case openfortivpn.PPPFailure:
		if pppAuthenticationFailure(observed.Message) {
			return fail(s, AuthFailure, e.Jitter)
		}
		if s.Phase == Connected {
			return fail(s, TransportFailure, e.Jitter)
		}
		return fail(s, ProcessFailure, e.Jitter)
	case openfortivpn.Teardown, openfortivpn.LoggedOut:
		if s.Phase == Connected {
			return fail(s, TransportFailure, e.Jitter)
		}
		return fail(s, ProcessFailure, e.Jitter)
	}
	return s, nil
}

// pppAuthenticationFailure identifies PPP credential rejection without guessing which
// factor failed. It returns false for transport and generic PPP diagnostics.
func pppAuthenticationFailure(message string) bool {
	return strings.Contains(message, "failed to authenticate") || strings.Contains(message, "refused) to authenticate")
}

// trustTarget selects a human confirmation only for a complete, normalized digest.
// Incomplete certificate blocks remain failures; command suggestions cannot grant trust.
func trustTarget(cert openfortivpn.CertRejected) Phase {
	if len(cert.Digest) != 64 {
		return Failed
	}
	for _, c := range cert.Digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return Failed
		}
	}
	return WaitingTrust
}

// fail selects a non-retrying failure or a bounded transport reconnect after cleanup.
// Authentication, certificate, conflict, and early failures never automatically retry.
// PushRetried is independent of exponential timing and survives successful reconnects.
func fail(s State, reason Failure, jitter float64) (State, []Effect) {
	target := Failed
	if reason == TransportFailure && s.Phase == Connected && s.Wanted && (s.MFAMode != "push" || !s.PushRetried) {
		target = Backoff
		if s.MFAMode == "push" {
			s.PushRetried = true
		}
		s.RetryDelay = s.Policy.Delay(s.RetryCount, jitter)
		if s.RetryCount < ^uint32(0) {
			s.RetryCount++
		}
	}
	s.Failure = reason
	detail := string(reason) + " failure"
	if reason == AuthFailure {
		detail = "authentication rejected"
	}
	return beginStop(s, target, detail)
}

// beginStop requests cancellation and SIGTERM, then waits for exit before cleanup.
// If the child already exited, cleanup starts directly. Networking is never removed
// while a live child might recreate it, and another generation cannot start early.
func beginStop(s State, target Phase, detail string) (State, []Effect) {
	s.Target, s.PendingUp = target, false
	duration := s.Deadlines.Stop
	if s.Exited {
		duration = s.Deadlines.Network
	}
	next, effects := transition(s, Stopping, detail, duration)
	effects = append(effects, effect(next, CancelChallenge))
	if !next.Exited {
		effects = append(effects, effect(next, StopProcess))
	} else {
		next.CleanupStarted = true
		effects = append(effects, effect(next, RemoveNetwork))
	}
	return next, effects
}

// processExited records child exit, even status zero before TunnelUp, and starts cleanup.
// Duplicate or idle exits are ignored. Connected exits are transport failures, while
// early exits are terminal process failures rather than false successful connections.
func processExited(s State, e Event) (State, []Effect) {
	if s.Exited || (!active(s.Phase) && s.Phase != Stopping) {
		return s, nil
	}
	s.Exited = true
	if s.Phase != Stopping {
		reason := ProcessFailure
		if s.Phase == Connected {
			reason = TransportFailure
		}
		return fail(s, reason, e.Jitter)
	}
	s.CleanupStarted = true
	next, effects := transition(s, Stopping, s.Detail, s.Deadlines.Network)
	return next, append(effects, effect(next, RemoveNetwork))
}

// cleanupFailed records failed or stalled removal and schedules bounded retries.
// It preserves exit/cleanup gating, cancels queued Up, and emits Failed on exhaustion.
// A later Reset retries removal only; it cannot start a child until cleanup succeeds.
func cleanupFailed(s State) (State, []Effect) {
	s.Failure, s.Target, s.PendingUp = NetworkFailure, Failed, false
	if s.CleanupRetries >= maxCleanupRetries {
		return transition(s, Failed, "network cleanup failed; reset to retry cleanup", 0)
	}
	s.CleanupRetries++
	s.CleanupRetryPending = true
	return transition(s, Stopping, "network cleanup failed", s.Deadlines.Network)
}

// finishStop enters the cleanup target after verified exit and resource removal.
// Trust metadata is emitted only here; automatic retries get a fresh backoff timer.
// A queued explicit Up starts only after successful cleanup, never after cleanup failure.
func finishStop(s State) (State, []Effect) {
	if s.PendingUp && s.Wanted && s.Target == Disconnected && s.CleanupRetries == 0 {
		s.RetryCount, s.PushRetried = 0, false
		return beginAttempt(s)
	}
	target := s.Target
	if !s.Wanted && s.CleanupRetries == 0 && s.Failure != NetworkFailure {
		target = Disconnected
	}
	duration := time.Duration(0)
	if target == Backoff {
		duration = s.RetryDelay
	}
	next, effects := transition(s, target, s.Detail, duration)
	if target == Disconnected {
		next.Detail = ""
		effects[len(effects)-1].Detail = ""
	}
	if target == WaitingTrust {
		cert := effect(next, EmitCert)
		cert.Certificate = s.Certificate
		effects = append(effects, cert)
	}
	return next, effects
}

// deadline accepts only the active timer and handles retry, stop escalation, or failure.
// Stop timeouts re-arm verified kill requests until exit is acknowledged. Cleanup
// timeouts retry removal with a bounded budget. Authentication/human timeouts never retry.
func deadline(s State, e Event) (State, []Effect) {
	if !s.TimerActive || e.TimerID != s.TimerID {
		return s, nil
	}
	s.TimerActive = false
	switch s.Phase {
	case Backoff:
		if s.Wanted {
			return beginAttempt(s)
		}
	case Stopping:
		if !s.Exited {
			next, effects := transition(s, Stopping, s.Detail, s.Deadlines.Stop)
			return next, append(effects, effect(next, KillProcess))
		}
		if s.CleanupStarted && !s.Cleaned {
			if !s.CleanupRetryPending {
				return cleanupFailed(s)
			}
			s.CleanupRetryPending = false
			next, effects := transition(s, Stopping, s.Detail, s.Deadlines.Network)
			return next, append(effects, effect(next, RemoveNetwork))
		}
	default:
		if active(s.Phase) {
			return fail(s, TimeoutFailure, e.Jitter)
		}
	}
	return s, nil
}

// effect initializes one action with s's profile and generation and no payload.
// Specific helpers add timer, state, network, or prompt metadata without I/O.
func effect(s State, kind EffectKind) Effect {
	return Effect{Kind: kind, Profile: s.Profile, Attempt: s.Attempt}
}

// timerEffect returns a timer action with phase, timer identity, and duration.
// CancelTimer uses zero duration but retains the old identity so later firings are stale.
func timerEffect(s State, kind EffectKind, duration time.Duration) Effect {
	e := effect(s, kind)
	e.Phase, e.TimerID, e.Duration = s.Phase, s.TimerID, duration
	return e
}

// stateEffect returns a public state notification with helper-generated detail only.
// It excludes raw logs, prompt answers, and attempt tokens and cannot fail.
func stateEffect(s State) Effect {
	e := effect(s, EmitState)
	e.Phase, e.Detail = s.Phase, s.Detail
	return e
}
