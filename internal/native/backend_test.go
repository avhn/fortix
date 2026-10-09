package native

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/ppp"
)

// TestNativeNegotiatedUnnumbered discards every advertised peer before metadata reaches
// the session, including a public gateway, LAN address, missing address and invalid IPv4.
// Negotiated local IP, DNS, MTU and pushed XML policy keep their original sources.
func TestNativeNegotiatedUnnumbered(t *testing.T) {
	local := netip.MustParseAddr("10.99.0.2")
	config := VPNConfig{AssignedIP: netip.MustParseAddr("10.99.0.90"), Domains: []string{"corp.example.com"}, SplitRoutes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	for _, peer := range []string{"198.51.100.5", "192.0.2.1", "169.254.1.1", "10.99.0.2", "", "0.0.0.0", "2001:db8::1"} {
		t.Run(peer, func(t *testing.T) {
			advertised, _ := netip.ParseAddr(peer)
			info := ppp.Negotiated{LocalIP: local, PeerIP: advertised, MRU: 1400, PeerMRU: 1354, PrimaryDNS: netip.MustParseAddr("10.20.0.1"), SecondaryDNS: netip.MustParseAddr("10.20.0.2")}
			got, err := nativeNegotiated(info, config)
			want := backend.Negotiated{LocalIP: local, PeerIP: local, MTU: 1354, DNS: []netip.Addr{info.PrimaryDNS, info.SecondaryDNS}, Suffix: "corp.example.com", PushedPrefixes: config.SplitRoutes}
			if err != nil || !reflect.DeepEqual(got, want) || info.PeerIP != advertised {
				t.Fatalf("advertised peer escaped native boundary: %+v (%v)", got, err)
			}
		})
	}
}

// TestNativeNegotiatedRequiresLocal refuses missing or unusable PPP local addresses.
// Neither a valid advertised peer nor XML's assigned address can replace negotiation.
func TestNativeNegotiatedRequiresLocal(t *testing.T) {
	for _, local := range []string{"", "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "2001:db8::1"} {
		t.Run(local, func(t *testing.T) {
			address, _ := netip.ParseAddr(local)
			info := ppp.Negotiated{LocalIP: address, PeerIP: netip.MustParseAddr("198.51.100.5"), MRU: 1354, PeerMRU: 1354}
			config := VPNConfig{AssignedIP: netip.MustParseAddr("10.99.0.2")}
			if _, err := nativeNegotiated(info, config); err == nil {
				t.Fatal("unusable negotiated local address accepted")
			}
		})
	}
}

// TestOutcomeTimeoutPhase distinguishes fatal setup deadlines from retryable data
// transport loss, preserving graceful cancellation after an explicit Stop.
func TestOutcomeTimeoutPhase(t *testing.T) {
	for _, activated := range []bool{false, true} {
		for _, err := range []error{context.DeadlineExceeded, fmt.Errorf("TLS write: %w", os.ErrDeadlineExceeded)} {
			tunnel := &Tunnel{ctx: context.Background(), activated: activated}
			want := backend.TimeoutFailure
			if activated {
				want = backend.TransportFailure
			}
			if got := tunnel.outcome(err); got.Failure != want {
				t.Fatalf("activated=%v error=%v outcome=%+v, want %s", activated, err, got, want)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tunnel := &Tunnel{ctx: ctx, activated: true}
	if got := tunnel.outcome(context.Canceled); got != (backend.Outcome{}) {
		t.Fatalf("explicit stop produced failure: %+v", got)
	}
	if got := tunnel.outcome(ppp.ErrRenegotiation); got.Failure != backend.TransportFailure {
		t.Fatalf("renegotiation is not transport loss: %+v", got)
	}
}
