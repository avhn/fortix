package helper

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/network"
)

// TestCarvedRoutesMessage reports narrowed gateway routes and stays silent when the
// pushed list was installed unchanged; default halves never count as narrowed.
func TestCarvedRoutesMessage(t *testing.T) {
	pushed := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("192.0.2.0/23"), netip.MustParsePrefix("0.0.0.0/1")}
	journal := network.Journal{Routes: []network.JournalRoute{
		{CIDR: "10.20.0.0/16", Interface: "utun4"}, {CIDR: "192.0.3.0/24", Interface: "utun4"},
		{CIDR: "0.0.0.0/1", Interface: "utun4"}, {CIDR: "203.0.113.10/32", Interface: "en0"},
	}}
	message := carvedRoutesMessage(pushed, journal, "utun4")
	if !strings.Contains(message, "routes 192.0.2.0/23 were narrowed") || !strings.Contains(message, "installed: 10.20.0.0/16, 192.0.3.0/24") || strings.Contains(message, "0.0.0.0/1") || strings.Contains(message, "203.0.113.10") {
		t.Fatalf("message = %q", message)
	}
	journal.Routes = []network.JournalRoute{{CIDR: "10.20.0.0/16", Interface: "utun4"}, {CIDR: "192.0.2.0/23", Interface: "utun4"}}
	if message := carvedRoutesMessage(pushed, journal, "utun4"); message != "" {
		t.Fatalf("unchanged push reported: %q", message)
	}
	many := make([]string, 0, 20)
	for i := range 20 {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16).String())
	}
	if got := routeList(many); !strings.HasSuffix(got, "and 4 more") {
		t.Fatalf("long list = %q", got)
	}
}
