package session

import (
	"net/netip"
	"time"

	"github.com/avhn/fortix/internal/backend"
)

// Phase is a public session status. Stopping waits for child exit and cleanup.
// Exhausted cleanup retries enter Failed without permitting a new attempt.
type Phase string

// Session phases cover idle, connection progress, human input, cleanup, and retry.
// Values are suitable for state notifications and contain no user-provided data.
const (
	Disconnected    Phase = "disconnected"
	Starting        Phase = "starting"
	WaitingPassword Phase = "waiting_password"
	WaitingCode     Phase = "waiting_code"
	Authenticating  Phase = "authenticating"
	Negotiating     Phase = "negotiating"
	Configuring     Phase = "configuring"
	Connected       Phase = "connected"
	WaitingTrust    Phase = "waiting_trust"
	Backoff         Phase = "backoff"
	Stopping        Phase = "stopping"
	Failed          Phase = "failed"
)

// Deadlines gives positive per-phase durations; omitted or negative values use defaults.
// Human covers password/code prompts and push approval. Stop is the SIGTERM grace period.
type Deadlines struct {
	Connect      time.Duration
	Authenticate time.Duration
	Human        time.Duration
	Negotiate    time.Duration
	Network      time.Duration
	Stop         time.Duration
}

// DefaultDeadlines returns fresh connect (30s), auth (60s), human/push (120s),
// negotiation (75s), networking (10s), and stop (10s) budgets, without reading a clock.
func DefaultDeadlines() Deadlines {
	return Deadlines{Connect: 30 * time.Second, Authenticate: 60 * time.Second, Human: 120 * time.Second, Negotiate: 75 * time.Second, Network: 10 * time.Second, Stop: 10 * time.Second}
}

// Options selects backend, timing, and retry policy for a profile's session.
// Backend and MFAMode are validated profile values. Omitted Backend keeps the external
// lifecycle for existing callers; native supervisors must select native explicitly.
// Push permits at most one automatic reconnect per explicit Up.
type Options struct {
	Backend   string
	MFAMode   string
	Deadlines Deadlines
	Backoff   BackoffPolicy
}

// State contains one profile's current generation and non-secret attempt metadata.
// Target is the state to enter after stopping; Exited and Cleaned gate that transition.
// TimerID increases when a timer is armed, preventing cancelled phase timers from firing.
// RetryCount resets on non-push success; PushRetried limits automatic push approvals.
// PendingUp queues an explicit reconnect during a normal stop, never failed cleanup.
// CleanupRetries bounds automatic removal retries; CleanupRetryPending means the timer
// schedules removal rather than timing an in-flight cleanup. Reset can retry exhausted
// cleanup without starting a transport. Treat slices as immutable; Next copies DNS and
// pushed-prefix payloads. Link records backend ownership; native never has a child PID.
type State struct {
	Profile             string
	Attempt             uint64
	Phase               Phase
	Detail              string
	Backend             string
	MFAMode             string
	Deadlines           Deadlines
	Policy              BackoffPolicy
	Wanted              bool
	PendingUp           bool
	RetryCount          uint32
	PushRetried         bool
	RetryDelay          time.Duration
	TimerID             uint64
	TimerActive         bool
	Target              Phase
	Failure             Failure
	Exited              bool
	Cleaned             bool
	CleanupStarted      bool
	CleanupRetries      uint32
	CleanupRetryPending bool
	Link                backend.LinkIdentity
	PeerIP              netip.Addr
	PushedPrefixes      []netip.Prefix
	MTU                 int
	LocalIP             netip.Addr
	DNS                 []netip.Addr
	Suffix              string
	Interface           string
	Certificate         backend.CertRejected
}

// Failure categorizes terminal causes independently of raw diagnostics.
// Only transport loss after a working connection is eligible for automatic reconnect.
type Failure = backend.Failure

// Failure categories distinguish rejection, conflicts, deadlines, and child lifecycle.
// They are helper-generated values, never credential responses or untrusted log text.
const (
	TransportFailure = backend.TransportFailure
	AuthFailure      = backend.AuthFailure
	CertFailure      = backend.CertFailure
	ConflictFailure  = backend.ConflictFailure
	NetworkFailure   = backend.NetworkFailure
	InterfaceFailure = backend.InterfaceFailure
	TimeoutFailure   = backend.TimeoutFailure
	ProcessFailure   = backend.ProcessFailure
	CancelledFailure = backend.CancelledFailure
	TunnelFailure    = backend.TunnelFailure
)

// EventKind identifies supervisor, client, and stdout inputs for Next.
// Every event is bound to Profile and Attempt, including user replies and timers.
type EventKind string

// Reducer inputs separate process exit from cleanup completion and network outcomes.
// Output carries a shared backend observation; Deadline carries the active TimerID.
const (
	Up                  EventKind = "up"
	Down                EventKind = "down"
	Reset               EventKind = "reset"
	Output              EventKind = "output"
	Challenge           EventKind = "challenge"
	CredentialsAnswered EventKind = "credentials_answered"
	ChallengeCancelled  EventKind = "challenge_cancelled"
	Trust               EventKind = "trust"
	Deadline            EventKind = "deadline"
	ProcessExited       EventKind = "process_exited"
	CleanupDone         EventKind = "cleanup_done"
	CleanupFailed       EventKind = "cleanup_failed"
	NetworkApplied      EventKind = "network_applied"
	AttemptFailed       EventKind = "attempt_failed"
	UpRefused           EventKind = "up_refused"
)

// Event contains one attempt-bound input without ever holding an account secret.
// Observation, Request, Digest, TimerID, Failure, and Jitter apply to their respective
// kinds. Jitter is a supervisor-provided sample in [0,1], making retry timing pure.
// ExitCode is diagnostic only: exit before TunnelUp is failure even with code zero.
// Detail is a helper-controlled explanation for refused or failed networking.
type Event struct {
	Profile     string
	Attempt     uint64
	Kind        EventKind
	Observation backend.Event
	Request     backend.Request
	Digest      string
	TimerID     uint64
	Failure     Failure
	Jitter      float64
	ExitCode    int
	Detail      string
}

// EffectKind identifies work the supervisor must perform outside the pure reducer.
// Timer and process effects always retain their originating attempt identity.
type EffectKind string

// Effect kinds describe transport lifecycle, timers, networking, and notifications.
// Process names remain compatible with existing supervisors; native StartProcess and
// StopProcess start/stop in-process work. Native never emits KillProcess.
// CancelChallenge invalidates pending replies; no effect contains a credential value.
const (
	StartProcess    EffectKind = "start_process"
	StopProcess     EffectKind = "stop_process"
	KillProcess     EffectKind = "kill_process"
	StartTimer      EffectKind = "start_timer"
	CancelTimer     EffectKind = "cancel_timer"
	ApplyNetwork    EffectKind = "apply_network"
	RemoveNetwork   EffectKind = "remove_network"
	EmitState       EffectKind = "emit_state"
	EmitChallenge   EffectKind = "emit_challenge"
	CancelChallenge EffectKind = "cancel_challenge"
	EmitCert        EffectKind = "emit_cert"
	PersistTrust    EffectKind = "persist_trust"
)

// Effect carries immutable action data for a supervisor, never performs that action.
// Phase and Detail describe state notifications; Duration and TimerID describe timers;
// link/address/interface fields describe networking; Request and Certificate describe
// prompts. Native link identity never contains a child PID; networking slices are copied.
type Effect struct {
	Kind           EffectKind
	Profile        string
	Attempt        uint64
	Phase          Phase
	Detail         string
	TimerID        uint64
	Duration       time.Duration
	Link           backend.LinkIdentity
	PeerIP         netip.Addr
	PushedPrefixes []netip.Prefix
	MTU            int
	LocalIP        netip.Addr
	DNS            []netip.Addr
	Suffix         string
	Interface      string
	Request        backend.Request
	Certificate    backend.CertRejected
}

// New returns an idle session for profileID with defaulted timing and retry options.
// profileID and MFAMode must come from a validated profile; it performs no I/O and
// cannot fail. Generation zero means no transport has been started yet. Native is
// explicit; omitted Backend preserves the external process lifecycle for old callers.
func New(profileID string, opts Options) State {
	d := opts.Deadlines
	defaults := DefaultDeadlines()
	for _, pair := range []struct{ value, fallback *time.Duration }{
		{&d.Connect, &defaults.Connect}, {&d.Authenticate, &defaults.Authenticate},
		{&d.Human, &defaults.Human}, {&d.Negotiate, &defaults.Negotiate},
		{&d.Network, &defaults.Network}, {&d.Stop, &defaults.Stop},
	} {
		if *pair.value <= 0 {
			*pair.value = *pair.fallback
		}
	}
	selected := opts.Backend
	if selected == "" {
		selected = "openfortivpn"
	}
	return State{Profile: profileID, Phase: Disconnected, Backend: selected, MFAMode: opts.MFAMode, Deadlines: d, Policy: opts.Backoff.normalized()}
}
