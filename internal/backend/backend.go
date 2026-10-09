// Package backend defines attempt-bound VPN lifecycle and observation contracts.
// Implementations own transport resources, while the helper owns routes and DNS.
package backend

import (
	"context"

	"github.com/avhn/fortix/internal/profile"
)

// Backend starts one VPN attempt using validated, allowlisted configuration.
// Start must honor ctx, reject unsupported configuration before sending credentials,
// and release partial resources on error. A successful start transfers cleanup to Tunnel.
type Backend interface {
	Start(ctx context.Context, attempt Attempt) (Tunnel, error)
}

// Tunnel owns one attempt's transport, workers, and optional child process.
// Events are ordered and contain no secrets. Answer borrows secret only until it returns
// and rejects stale or unexpected requests. Stop is idempotent and honors ctx; it does
// not imply workers have exited. Wait completes after workers stop, a terminal Outcome
// is emitted, and Events closes. Only then may the helper remove network resources.
type Tunnel interface {
	Events() <-chan Event
	Answer(ctx context.Context, request Request, secret []byte) error
	Stop(ctx context.Context) error
	Wait() error
}

// Attempt binds configuration and callbacks to a profile's nonzero generation.
// Implementations retain this identity for all callbacks and cannot reuse a Tunnel
// across generations. Config and its slices must be treated as immutable snapshots.
type Attempt struct {
	Profile    string
	Generation uint64
	Config     Config
	Hooks      Hooks
}

// Config contains only a validated profile, never credentials or arbitrary commands.
// Backend-specific trusted executable paths and injected runners belong to constructors.
type Config struct {
	Profile profile.Profile
}

// Hooks exposes helper-owned link registration and redacted diagnostic delivery.
// RegisterLink must persist and acknowledge identity before interface configuration or
// route mutation; errors abort the attempt. Diagnostic receives only sanitized text,
// never cookies, authentication responses, or secrets. Callbacks belong to the Attempt.
type Hooks struct {
	RegisterLink func(context.Context, LinkIdentity) error
	Diagnostic   func(string)
}

// LinkIdentity records a link before configuration for ownership and recovery checks.
// Index is the OS interface index when available. PID and StartTime identify an external
// child and must both be absent for native links; the helper's PID is never substituted.
// An interface name or PID alone does not authorize mutation or process signalling.
type LinkIdentity struct {
	Interface string
	Index     int
	PID       int
	StartTime string
}

// Kind identifies the purpose of a credential challenge, not authorization to answer it.
// The supervisor must independently authenticate the caller and bind the generation.
type Kind string

// Credential kinds distinguish the account password from a second-factor response.
const (
	Password Kind = "password"
	Code     Kind = "code"
)

// Request contains bounded, decoded challenge metadata, never a credential response.
// KeyInfo and Prompt are untrusted display data; they cannot authorize another attempt.
type Request struct {
	Kind    Kind
	KeyInfo string
	Prompt  string
}

// Failure categorizes a terminal cause independently of untrusted diagnostics.
// Only transport loss after a working connection is eligible for automatic reconnect.
type Failure string

// Failure categories distinguish trust, authentication, network, and lifecycle errors.
const (
	TransportFailure Failure = "transport"
	AuthFailure      Failure = "authentication"
	CertFailure      Failure = "certificate"
	ConflictFailure  Failure = "conflict"
	NetworkFailure   Failure = "network"
	InterfaceFailure Failure = "interface"
	TimeoutFailure   Failure = "timeout"
	ProcessFailure   Failure = "process"
	CancelledFailure Failure = "cancelled"
	TunnelFailure    Failure = "tunnel_mode"
)
