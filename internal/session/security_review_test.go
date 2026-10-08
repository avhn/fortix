package session

import (
	"net/netip"
	"testing"

	"github.com/avhn/fortix/internal/openfortivpn"
)

// TestTunnelMilestonesAreOneShot refuses a forged later interface name and applies
// networking only once, even when the child repeats its tunnel-ready status line.
func TestTunnelMilestonesAreOneShot(t *testing.T) {
	s := New("work", Options{})
	s.Phase, s.Attempt = Negotiating, 1
	s.LocalIP = netip.MustParseAddr("10.20.0.2")
	e := Event{Profile: s.Profile, Attempt: s.Attempt, Kind: Output, Observation: openfortivpn.InterfaceUp{Name: "ppp0"}}
	s, _ = Next(s, e)
	e.Observation = openfortivpn.InterfaceUp{Name: "en0"}
	s, effects := Next(s, e)
	if s.Interface != "ppp0" || len(effects) != 0 {
		t.Fatal("second interface replaced the tunnel")
	}
	e.Observation = openfortivpn.TunnelUp{}
	s, effects = Next(s, e)
	if s.Phase != Configuring || !hasEffect(effects, ApplyNetwork) {
		t.Fatal("first tunnel-ready milestone lost")
	}
	s, effects = Next(s, e)
	if s.Phase != Configuring || len(effects) != 0 {
		t.Fatal("duplicate tunnel-ready applied network twice")
	}
}
