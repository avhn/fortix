package backend

import "net/netip"

// AuthenticationFailedCode identifies rejected credentials in helper state events.
// Unsupported second factors are not credential rejection and must not use this code.
const AuthenticationFailedCode = "AUTHENTICATION_FAILED"

// Event is a sealed, typed observation shared by native and external VPN backends.
// Observations do not prove OS ownership; the helper separately verifies registered links.
type Event interface{ vpnEvent() }

// eventTag seals observations without adding data or exposing implementation methods.
type eventTag struct{}

// vpnEvent marks a value as an observation without I/O or failure.
func (eventTag) vpnEvent() {}

// ConnectedToGateway indicates completed TLS verification, not authentication.
type ConnectedToGateway struct{ eventTag }

// Authenticated indicates that the gateway accepted authentication for this attempt.
type Authenticated struct{ eventTag }

// AuthFailed indicates credential rejection without guessing which factor failed.
type AuthFailed struct{ eventTag }

// TunnelModeDenied indicates that the gateway refused the tunnel protocol or realm.
type TunnelModeDenied struct{ eventTag }

// VPNAllocated indicates allocated gateway resources after authentication.
type VPNAllocated struct{ eventTag }

// GotAddresses preserves the external backend's partial address observation.
// Native implementations use Negotiated once authoritative negotiation is complete.
type GotAddresses struct {
	eventTag
	LocalIP netip.Addr
	DNS     []netip.Addr
	Suffix  string
}

// NegotiationComplete indicates completed PPP negotiation before helper networking.
type NegotiationComplete struct{ eventTag }

// Negotiated carries authoritative IPv4 metadata before helper network configuration.
// PeerIP is the PPP peer, not the TLS gateway. PushedPrefixes are canonical IPv4 routes;
// MTU is the negotiated payload size in bytes. DNS and prefixes are immutable snapshots.
type Negotiated struct {
	eventTag
	LocalIP        netip.Addr
	PeerIP         netip.Addr
	PushedPrefixes []netip.Prefix
	MTU            int
	DNS            []netip.Addr
	Suffix         string
}

// InterfaceUp preserves the external backend's reported, not yet verified link name.
type InterfaceUp struct {
	eventTag
	Name string
}

// LinkReady identifies a link after RegisterLink acknowledges its ownership record.
// Native links have no child PID and cannot be stopped by signalling the helper.
type LinkReady struct {
	eventTag
	Link LinkIdentity
}

// TunnelUp indicates a running transport; helper networking still needs to be applied.
type TunnelUp struct{ eventTag }

// CertificateRejected contains rejected leaf certificate metadata and SHA-256 digest.
// Digest is empty for incomplete or malformed observations and cannot then grant trust.
type CertificateRejected struct {
	eventTag
	Digest  string
	Subject string
	Issuer  string
}

// CertRejected retains the historical spelling for external backend compatibility.
type CertRejected = CertificateRejected

// RouteRejectReason identifies a route collision or an ordinary installation failure.
// Unknown reasons fail conservatively as network failures, never successful routing.
type RouteRejectReason string

// Route rejection reasons distinguish another link's ownership from command failure.
const (
	RouteConflict RouteRejectReason = "conflict"
	RouteFailed   RouteRejectReason = "failed"
)

// RouteRejected reports a pushed-route failure from either backend's typed adapter.
// Prefix identifies the rejected route; Message is diagnostic only and must be redacted
// before display. The reducer uses Reason, never message text, to select a failure.
type RouteRejected struct {
	eventTag
	Prefix  netip.Prefix
	Reason  RouteRejectReason
	Message string
}

// OutputFailed indicates a local helper log or output-stream failure, not a rejected
// route. It requests transport shutdown without acknowledging worker completion;
// a later Outcome remains required before any owned network resources are removed.
type OutputFailed struct{ eventTag }

// CredentialRequested asks the supervisor to obtain a generation-bound response.
// Native second-factor requests are unsupported and must not silently change backends.
type CredentialRequested struct {
	eventTag
	Request Request
}

// Outcome acknowledges stopped transport workers or a reaped external child.
// ExitCode is diagnostic and zero alone never proves a successful connection. Failure
// and Detail are helper-controlled categories and explanations, never gateway text.
// An empty Failure lets the reducer infer early-exit or connected-transport failure.
type Outcome struct {
	eventTag
	ExitCode int
	Failure  Failure
	Detail   string
}

// PPPFailure preserves an external PPP diagnostic without its logging prefix.
type PPPFailure struct {
	eventTag
	Message string
}

// LoggedOut indicates successful explicit gateway logout, not worker completion.
type LoggedOut struct{ eventTag }

// Teardown reports transport closure without proving workers exited or cleanup finished.
type Teardown struct {
	eventTag
	Message string
}

// Unknown preserves unrecognized text for separate, redacted diagnostic handling.
// It is never interpreted as a state-changing observation by the reducer.
type Unknown struct {
	eventTag
	Line string
}
