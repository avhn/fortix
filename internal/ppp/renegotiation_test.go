package ppp

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// TestStopOnRenegotiation verifies the opt-in barrier rejects new LCP and IPCP
// generations without acknowledging changed MRU or addressing. Exact retransmits
// and malformed offers remain harmless, while default callers can still renegotiate.
func TestStopOnRenegotiation(t *testing.T) {
	for _, protocol := range []uint16{ProtocolLCP, ProtocolIPCP} {
		e := openEngine(t)
		e.config.StopOnRenegotiation = true
		m := &e.lcp
		body := append([]byte{1, 4, 4, 176}, uint32Option(5, 42)...)
		if protocol == ProtocolIPCP {
			m = &e.ipcp
			body = addressOption(3, netip.MustParseAddr("10.9.0.1"))
		}
		before := e.info
		response := decoded(t, feed(t, e, protocol, ConfigureRequest, m.peerID, m.peerData), 0, ConfigureAck)
		if !e.opened || !bytes.Equal(response.Data, m.peerData) {
			t.Fatal("exact retransmit changed open link")
		}
		if output := feed(t, e, protocol, ConfigureRequest, m.peerID+1, []byte{1}); len(output) != 0 || !e.opened {
			t.Fatal("malformed offer disturbed open link")
		}
		output, data, err := e.input(controlPacket(protocol, ConfigureRequest, m.peerID+1, body), time.Unix(1000, 0))
		if !errors.Is(err, ErrRenegotiation) || len(output) != 0 || data != nil || e.info != before {
			t.Fatalf("protocol=%x barrier output=%x data=%x info=%+v error=%v", protocol, output, data, e.info, err)
		}
	}
}
