package openfortivpn

import "net/netip"

// Event is a sealed stdout observation. Unknown text is diagnostic, not a failure.
// Certificate observations may span several input lines before an Event is emitted.
type Event interface{ vpnEvent() }

// eventTag seals event implementations while keeping concrete value types lightweight.
// Embedding it supplies a marker only, with no data or I/O.
type eventTag struct{}

// vpnEvent marks an observation as an Event and has no inputs, output, or failure.
func (eventTag) vpnEvent() {}

// ConnectedToGateway indicates a completed initial TLS connection, not authentication.
type ConnectedToGateway struct{ eventTag }

// Authenticated indicates that the gateway accepted authentication for this attempt.
type Authenticated struct{ eventTag }

// AuthFailed indicates rejected authentication without guessing which credential failed.
type AuthFailed struct{ eventTag }

// TunnelModeDenied indicates that the gateway refused the tunnel protocol or realm.
type TunnelModeDenied struct{ eventTag }

// VPNAllocated indicates that the gateway allocated VPN resources after authentication.
type VPNAllocated struct{ eventTag }

// GotAddresses contains the local address, usable DNS addresses, and advertised suffix.
// Invalid address lines are Unknown; unspecified DNS addresses are omitted.
type GotAddresses struct {
	eventTag
	LocalIP netip.Addr
	DNS     []netip.Addr
	Suffix  string
}

// NegotiationComplete indicates completed PPP negotiation, before helper networking.
type NegotiationComplete struct{ eventTag }

// InterfaceUp identifies the PPP link reported by openfortivpn, not a verified OS link.
type InterfaceUp struct {
	eventTag
	Name string
}

// TunnelUp indicates a running tunnel; helper networking still needs to be applied.
type TunnelUp struct{ eventTag }

// CertRejected collects a rejected certificate's displayed metadata and final SHA256.
// Digest is empty for incomplete or malformed blocks; such values cannot be trusted.
type CertRejected struct {
	eventTag
	Digest  string
	Subject string
	Issuer  string
}

// PPPFailure contains a ppp or pppd error line's message, without its logging prefix.
type PPPFailure struct {
	eventTag
	Message string
}

// LoggedOut indicates a successful explicit logout from the gateway.
type LoggedOut struct{ eventTag }

// Teardown contains a connection closure or PPP termination milestone.
// It does not prove the child exited or owned network resources were removed.
type Teardown struct {
	eventTag
	Message string
}

// Unknown preserves an unrecognized original line for separate diagnostic handling.
// Consumers must redact diagnostics before storing or exposing them to clients.
type Unknown struct {
	eventTag
	Line string
}
