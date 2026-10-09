package helper

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/native"
	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// nativeDiagnostic uses the same private, rotating log and live notifications as
// external output. Redaction precedes storage and publication; a failed write asks
// the actor to stop without falsely acknowledging transport completion.
func (a *supervisor) nativeDiagnostic(log *rotatingLog, attempt uint64, message string) {
	if log == nil {
		return
	}
	line := log.redact("native: " + message)
	if err := log.write(line); err != nil {
		a.send(session.Event{Profile: a.id, Attempt: attempt, Kind: session.Output, Observation: backend.OutputFailed{}})
		return
	}
	a.server.emit(protocol.Event{Type: "log", Profile: a.id, Attempt: attempt, Line: line}, nil)
}

// nativeOutcome adds fixed, short causes after workers finish. HTTP diagnostics
// include only the numeric status, never a response body or a supplied request path.
// Existing backend categories retain authority over retry and cleanup decisions.
func nativeOutcome(outcome backend.Outcome, err error) backend.Outcome {
	if err == nil || errors.Is(err, context.Canceled) {
		return outcome
	}
	var mfa *native.UnsupportedMFA
	var httpError *native.HTTPError
	var conflict *network.ConflictError
	switch {
	case errors.As(err, &mfa):
		outcome.Failure, outcome.Detail = backend.AuthFailure, "native backend does not support second factors; select openfortivpn"
	case errors.Is(err, native.ErrAuthentication):
		outcome.Failure, outcome.Detail = backend.AuthFailure, "authentication rejected"
	case errors.As(err, &httpError):
		if outcome.Failure == "" {
			outcome.Failure = backend.ProcessFailure
		}
		outcome.Detail = fmt.Sprintf("gateway HTTP status %d", httpError.Status)
	case errors.As(err, &conflict):
		outcome.Failure, outcome.Detail = backend.ConflictFailure, "network conflict; see profile log"
	default:
		if outcome.Failure == "" && outcome.ExitCode != 0 {
			outcome.Detail = "native backend failed; see profile log"
		}
	}
	return outcome
}

// nativeMilestone selects only typed setup observations, never raw gateway output.
// The actor rejects stale generations before logging their allocated local address.
func nativeMilestone(observation backend.Event) string {
	switch value := observation.(type) {
	case backend.ConnectedToGateway:
		return "connected to gateway"
	case backend.Authenticated:
		return "authenticated"
	case backend.VPNAllocated:
		return "allocated"
	case backend.Negotiated:
		return "PPP negotiated with local address " + value.LocalIP.String()
	}
	return ""
}

// carvedRoutesMessage reports gateway routes that were not installed as pushed,
// which happens when local networks are kept off the tunnel. It lists the routes
// actually installed on the tunnel so the log shows what the VPN now reaches.
// Default halves are omitted from both sides because they never carve.
func carvedRoutesMessage(pushed []netip.Prefix, journal network.Journal, iface string) string {
	var installed []string
	for _, route := range journal.Routes {
		if route.Interface == iface {
			if prefix, err := netip.ParsePrefix(route.CIDR); err == nil && prefix.Bits() > 1 {
				installed = append(installed, route.CIDR)
			}
		}
	}
	var changed []string
	for _, prefix := range pushed {
		if prefix.Bits() > 1 && !slices.Contains(installed, prefix.String()) {
			changed = append(changed, prefix.String())
		}
	}
	if len(changed) == 0 {
		return ""
	}
	return fmt.Sprintf("local networks kept off the tunnel; gateway routes %s were narrowed, installed: %s", routeList(changed), routeList(installed))
}

// routeList joins at most sixteen routes so a large push stays one readable log line.
func routeList(routes []string) string {
	const shown = 16
	if len(routes) == 0 {
		return "none"
	}
	if len(routes) <= shown {
		return strings.Join(routes, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(routes[:shown], ", "), len(routes)-shown)
}
