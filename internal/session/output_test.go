package session

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/openfortivpn"
)

// TestObservationMatrix checks every stdout observation type in all twelve phases.
// It asserts target/failure policy, network payload updates, required effects, and full
// no-op behavior for observations inappropriate to a phase, independently of input kinds.
func TestObservationMatrix(t *testing.T) {
	phases := []Phase{Disconnected, Starting, WaitingPassword, WaitingCode, Authenticating, Negotiating, Configuring, Connected, WaitingTrust, Backoff, Stopping, Failed}
	fatal := map[Phase]Phase{
		Starting: Stopping, WaitingPassword: Stopping, WaitingCode: Stopping,
		Authenticating: Stopping, Negotiating: Stopping, Configuring: Stopping,
		Connected: Stopping, Stopping: Stopping, WaitingTrust: Failed, Backoff: Failed,
	}
	transport := map[Phase]Phase{
		Starting: Stopping, WaitingPassword: Stopping, WaitingCode: Stopping,
		Authenticating: Stopping, Negotiating: Stopping, Configuring: Stopping, Connected: Stopping,
	}
	certificate := map[Phase]Phase{
		Starting: Stopping, WaitingPassword: Stopping, WaitingCode: Stopping,
		Authenticating: Stopping, Negotiating: Stopping, Configuring: Stopping,
		Connected: Stopping, Stopping: Stopping, WaitingTrust: WaitingTrust, Backoff: WaitingTrust,
	}
	addresses := openfortivpn.GotAddresses{LocalIP: netip.MustParseAddr("10.20.0.10"), DNS: []netip.Addr{netip.MustParseAddr("10.20.0.1")}, Suffix: "corp.example.com"}
	cases := []struct {
		event       openfortivpn.Event
		transitions map[Phase]Phase
		failure     Failure
		target      Phase
	}{
		{openfortivpn.ConnectedToGateway{}, map[Phase]Phase{Starting: Authenticating}, "", ""},
		{openfortivpn.Authenticated{}, map[Phase]Phase{Starting: Negotiating, Authenticating: Negotiating}, "", ""},
		{openfortivpn.AuthFailed{}, fatal, AuthFailure, Failed},
		{openfortivpn.TunnelModeDenied{}, fatal, TunnelFailure, Failed},
		{openfortivpn.VPNAllocated{}, nil, "", ""},
		{addresses, map[Phase]Phase{Negotiating: Negotiating}, "", ""},
		{openfortivpn.NegotiationComplete{}, nil, "", ""},
		{openfortivpn.InterfaceUp{Name: "ppp1"}, map[Phase]Phase{Negotiating: Negotiating}, "", ""},
		{openfortivpn.TunnelUp{}, map[Phase]Phase{Negotiating: Configuring}, "", ""},
		{openfortivpn.CertRejected{Digest: strings.Repeat("b", 64), Subject: "CN=vpn.example.com", Issuer: "CN=Example CA"}, certificate, CertFailure, WaitingTrust},
		{openfortivpn.PPPFailure{Message: "pppd: options failed"}, transport, ProcessFailure, Failed},
		{openfortivpn.PPPFailure{Message: "pppd: We failed to authenticate ourselves to the peer."}, fatal, AuthFailure, Failed},
		{openfortivpn.LoggedOut{}, transport, ProcessFailure, Failed},
		{openfortivpn.Teardown{Message: "Closed connection to gateway."}, transport, ProcessFailure, Failed},
		{openfortivpn.Unknown{Line: "ERROR:  unrecognized"}, nil, "", ""},
	}
	for _, phase := range phases {
		for index, tc := range cases {
			t.Run(fmt.Sprintf("%s/%d_%T", phase, index, tc.event), func(t *testing.T) {
				s := New("work", Options{MFAMode: "none"})
				s.Phase, s.Attempt, s.Wanted = phase, 1, phase != Disconnected
				s.TimerID = 5
				s.TimerActive = phase == Backoff || phase == Stopping || (active(phase) && phase != Connected)
				s.Exited, s.CleanupStarted = !active(phase), phase == Stopping
				s.Cleaned = s.Exited && phase != Stopping
				s.Target = Disconnected
				s.Certificate.Digest = strings.Repeat("a", 64)
				s.LocalIP, s.Interface = netip.MustParseAddr("10.20.0.11"), "ppp0"
				e := input(s, Output)
				e.Observation = tc.event
				next, effects := Next(s, e)
				want, changes := tc.transitions[phase]
				if !changes {
					if !reflect.DeepEqual(next, s) || effects != nil {
						t.Fatalf("ignored observation changed state: %+v, %+v", next, effects)
					}
					return
				}
				if next.Phase != want {
					t.Fatalf("got %s, want %s", next.Phase, want)
				}
				if tc.failure != "" {
					reason, target := tc.failure, tc.target
					if phase == Connected && tc.failure == ProcessFailure {
						reason, target = TransportFailure, Backoff
					}
					if next.Failure != reason || (want == Stopping && next.Target != target) {
						t.Fatalf("got %s -> %s, want %s -> %s", next.Failure, next.Target, reason, target)
					}
					if hasEffect(effects, StartProcess) || hasEffect(effects, ApplyNetwork) {
						t.Fatal("fatal observation started work")
					}
					if active(phase) && !hasEffect(effects, StopProcess) {
						t.Fatal("fatal observation did not stop child")
					}
					if hasEffect(effects, EmitCert) != (want == WaitingTrust) {
						t.Fatal("certificate emitted before cleanup or omitted after cleanup")
					}
				} else {
					switch tc.event.(type) {
					case openfortivpn.GotAddresses:
						if next.LocalIP != addresses.LocalIP || !reflect.DeepEqual(next.DNS, addresses.DNS) || next.Suffix != addresses.Suffix || effects != nil {
							t.Fatal("address metadata not stored exactly")
						}
					case openfortivpn.InterfaceUp:
						if next.Interface != "ppp1" || effects != nil {
							t.Fatal("interface metadata not stored")
						}
					case openfortivpn.TunnelUp:
						if !hasEffect(effects, ApplyNetwork) || !hasEffect(effects, StartTimer) {
							t.Fatal("complete tunnel did not request timed networking")
						}
					default:
						if !hasEffect(effects, EmitState) || !hasEffect(effects, StartTimer) {
							t.Fatal("milestone did not emit phase and timer")
						}
					}
				}
			})
		}
	}
}
