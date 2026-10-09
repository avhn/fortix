package network

import (
	"net/netip"
	"testing"
)

// TestLoopbackTLSJournal permits local split-route gateways without weakening tunnel IP validation.
func TestLoopbackTLSJournal(t *testing.T) {
	m, _, _, journal := windowsFixture(t)
	for _, text := range []string{"127.0.0.1", "127.0.0.2", "198.51.100.1"} {
		journal.GatewayIP = text
		if err := m.validateJournal(journal); err != nil {
			t.Fatalf("valid TLS peer %s: %v", text, err)
		}
	}
	for _, text := range []string{"::1", "127.00.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255"} {
		journal.GatewayIP = text
		if err := m.validateJournal(journal); err == nil {
			t.Fatalf("invalid TLS peer accepted: %s", text)
		}
	}
	if validIPv4("127.0.0.1") || tunnelAddress(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback became a usable tunnel address or physical gateway exception")
	}
	journal.GatewayIP = "127.0.0.1"
	journal.LocalIP = "127.0.0.1"
	journal.Address = &JournalAddress{IP: "127.0.0.1", Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, State: mutationIntent}
	if err := m.validateJournal(journal); err == nil {
		t.Fatal("loopback tunnel address accepted")
	}
}
