package openfortivpn

import "github.com/avhn/fortix/internal/backend"

// Event is the shared sealed observation type; unknown text remains diagnostic only.
type Event = backend.Event

// ConnectedToGateway indicates a completed initial TLS connection, not authentication.
type ConnectedToGateway = backend.ConnectedToGateway

// Authenticated indicates that the gateway accepted authentication for this attempt.
type Authenticated = backend.Authenticated

// AuthFailed indicates rejected authentication without guessing which credential failed.
type AuthFailed = backend.AuthFailed

// TunnelModeDenied indicates that the gateway refused the tunnel protocol or realm.
type TunnelModeDenied = backend.TunnelModeDenied

// VPNAllocated indicates allocated gateway resources after authentication.
type VPNAllocated = backend.VPNAllocated

// GotAddresses contains the local address, DNS addresses, and advertised suffix.
type GotAddresses = backend.GotAddresses

// NegotiationComplete indicates completed PPP negotiation before helper networking.
type NegotiationComplete = backend.NegotiationComplete

// InterfaceUp identifies the reported PPP link, not a verified OS link.
type InterfaceUp = backend.InterfaceUp

// TunnelUp indicates a running tunnel before helper networking is applied.
type TunnelUp = backend.TunnelUp

// CertRejected contains displayed rejected certificate metadata and its leaf digest.
type CertRejected = backend.CertificateRejected

// CertificateRejected is the backend-neutral spelling of the certificate observation.
type CertificateRejected = backend.CertificateRejected

// RouteRejected contains a typed pushed-route collision or installation failure.
type RouteRejected = backend.RouteRejected

// RouteRejectReason identifies a typed route failure without interpreting diagnostics.
type RouteRejectReason = backend.RouteRejectReason

// Route rejection reasons are identical across native and external backend adapters.
const (
	RouteConflict = backend.RouteConflict
	RouteFailed   = backend.RouteFailed
)

// PPPFailure contains a PPP error message without its logging prefix.
type PPPFailure = backend.PPPFailure

// LoggedOut indicates successful explicit gateway logout.
type LoggedOut = backend.LoggedOut

// Teardown contains closure metadata without proving child exit or resource cleanup.
type Teardown = backend.Teardown

// Unknown preserves unrecognized text for separate redacted diagnostic handling.
type Unknown = backend.Unknown
