package ppp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// testEngine starts a deterministic LCP exchange without transport goroutines.
func testEngine(t *testing.T) *engine {
	t.Helper()
	config, err := (Config{Magic: 0xaabbccdd}).defaults()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(config, time.Unix(1000, 0))
	if _, err := e.lcp.sendRequest(e, time.Unix(1000, 0), true); err != nil {
		t.Fatal(err)
	}
	return e
}

// feed applies one simulated control packet and requires successful processing.
func feed(t *testing.T, e *engine, protocol uint16, code, id byte, data []byte) [][]byte {
	t.Helper()
	output, _, err := e.input(controlPacket(protocol, code, id, data), time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return output
}

// decoded requires one complete expected control response from an engine step.
func decoded(t *testing.T, output [][]byte, index int, code byte) Control {
	t.Helper()
	if len(output) <= index {
		t.Fatalf("missing output %d: %x", index, output)
	}
	c, err := DecodeControl(output[index][2:])
	if err != nil || c.Code != code {
		t.Fatalf("wanted code %d, got %x, error %v", code, output, err)
	}
	return c
}

// openEngine completes minimal bidirectional LCP/IPCP with a nonempty peer address.
func openEngine(t *testing.T) *engine {
	t.Helper()
	e := testEngine(t)
	feed(t, e, ProtocolLCP, ConfigureAck, e.lcp.id, e.lcp.request)
	feed(t, e, ProtocolLCP, ConfigureRequest, 21, append([]byte{1, 4, 5, 74}, uint32Option(5, 0x10203040)...))
	feed(t, e, ProtocolIPCP, ConfigureNak, e.ipcp.id, addressOption(3, netip.MustParseAddr("10.0.0.2")))
	feed(t, e, ProtocolIPCP, ConfigureRequest, 22, addressOption(3, netip.MustParseAddr("10.0.0.1")))
	feed(t, e, ProtocolIPCP, ConfigureAck, e.ipcp.id, e.ipcp.request)
	if !e.opened {
		t.Fatal("engine did not open")
	}
	return e
}

// TestConfigureAckMatching proves exact ID, order, width, and content matching.
func TestConfigureAckMatching(t *testing.T) {
	e := testEngine(t)
	for _, packet := range [][]byte{
		controlPacket(ProtocolLCP, ConfigureAck, e.lcp.id+1, e.lcp.request),
		controlPacket(ProtocolLCP, ConfigureAck, e.lcp.id, e.lcp.request[:4]),
		controlPacket(ProtocolLCP, ConfigureAck, e.lcp.id, append(bytes.Clone(e.lcp.request[4:]), e.lcp.request[:4]...)),
		controlPacket(ProtocolLCP, ConfigureAck, e.lcp.id, append([]byte{1, 4, 5, 73}, e.lcp.request[4:]...)),
	} {
		if _, _, err := e.input(packet, time.Unix(1000, 0)); err != nil || e.lcp.localAck {
			t.Fatalf("accepted inexact Ack: %x, %v", packet, err)
		}
	}
	// Padding is outside the declared control body and must not affect matching.
	packet := append(controlPacket(ProtocolLCP, ConfigureAck, e.lcp.id, e.lcp.request), 99)
	if _, _, err := e.input(packet, time.Unix(1000, 0)); err != nil || !e.lcp.localAck || e.lcp.open() {
		t.Fatalf("exact padded Ack transition: %+v, %v", e.lcp, err)
	}
	oldID := e.lcp.id
	output, err := e.tick(e.lcp.due)
	request := decoded(t, output, 0, ConfigureRequest)
	if err != nil || request.ID == oldID || e.lcp.localAck {
		t.Fatalf("Ack-Received retry transition: %x, %v", output, err)
	}
}

// TestLCPPeerOptions verifies supported MRU/magic/ACCM and exact rejection of
// authentication, PFC, ACFC, compression, unsupported options, and invalid widths.
func TestLCPPeerOptions(t *testing.T) {
	for _, rejected := range [][]byte{
		{3, 4, 0xc0, 0x23}, {7, 2}, {8, 2}, {17, 4, 0, 1}, {99, 2}, {1, 3, 0}, {2, 2}, {5, 2},
	} {
		e := testEngine(t)
		body := append(append([]byte{1, 4, 0, 1}, uint32Option(5, e.info.Magic)...), rejected...)
		// Use one MRU option even when the test rejects an invalid MRU width.
		if rejected[0] == 1 || rejected[0] == 5 {
			body = rejected
		}
		output := feed(t, e, ProtocolLCP, ConfigureRequest, 42, body)
		response := decoded(t, output, 0, ConfigureReject)
		if !bytes.Equal(response.Data, rejected) || e.lcp.peerAck || e.info.PeerMRU != 1500 {
			t.Fatalf("inexact rejection or partial commit: %x", response)
		}
	}
	e := testEngine(t)
	body := append([]byte{1, 4, 0, 1}, uint32Option(5, e.info.Magic)...)
	response := decoded(t, feed(t, e, ProtocolLCP, ConfigureRequest, 43, body), 0, ConfigureNak)
	if !bytes.Equal(response.Data[:4], []byte{1, 4, 5, 74}) || binary.BigEndian.Uint32(response.Data[6:]) == e.info.Magic {
		t.Fatalf("bad loopback/MRU Nak: %x", response)
	}
	body = append([]byte{1, 4, 0, 128}, uint32Option(5, 1234)...)
	body = append(body, uint32Option(2, 0xffffffff)...)
	response = decoded(t, feed(t, e, ProtocolLCP, ConfigureRequest, 44, body), 0, ConfigureAck)
	if !bytes.Equal(response.Data, body) || e.info.PeerMRU != 128 || e.info.PeerMagic != 1234 {
		t.Fatalf("supported options: %x, %+v", response, e.info)
	}
	// Absent MRU/magic restore their default semantics rather than retaining old values.
	feed(t, e, ProtocolLCP, ConfigureRequest, 45, nil)
	if e.info.PeerMRU != 1500 || e.info.PeerMagic != 0 {
		t.Fatal(e.info)
	}
}

// TestLocalOfferChanges validates exact Reject matching and bounded Nak loops.
func TestLocalOfferChanges(t *testing.T) {
	e := testEngine(t)
	original := bytes.Clone(e.lcp.request)
	for _, body := range [][]byte{{1, 4, 5, 73}, {5, 6, 0, 0, 0, 1}, {99, 2}, {1, 3, 5}} {
		feed(t, e, ProtocolLCP, ConfigureReject, e.lcp.id, body)
		if !bytes.Equal(e.lcp.request, original) {
			t.Fatalf("accepted fabricated Reject %x", body)
		}
	}
	for _, body := range [][]byte{{1, 4, 5, 75}, {1, 4, 0, 1}, {5, 6, 0, 0, 0, 0}, {5, 3, 2}, {99, 2}} {
		feed(t, e, ProtocolLCP, ConfigureNak, e.lcp.id, body)
		if !bytes.Equal(e.lcp.request, original) {
			t.Fatalf("accepted invalid Nak %x", body)
		}
	}
	response := decoded(t, feed(t, e, ProtocolLCP, ConfigureNak, e.lcp.id, append([]byte{1, 4, 5, 0}, uint32Option(5, 42)...)), 0, ConfigureRequest)
	if e.info.MRU != 1280 || e.info.Magic != 42 || response.ID == 1 {
		t.Fatalf("did not adopt LCP Nak: %x", response)
	}
	feed(t, e, ProtocolLCP, ConfigureReject, e.lcp.id, e.lcp.request[4:])
	if len(e.lcp.request) != 4 || e.info.Magic != 0 {
		t.Fatal("optional magic rejection failed")
	}
	if _, _, err := e.input(controlPacket(ProtocolLCP, ConfigureReject, e.lcp.id, e.lcp.request), time.Unix(1000, 0)); !errors.Is(err, ErrRejected) {
		t.Fatalf("required MRU rejection: %v", err)
	}
	e = testEngine(t)
	for range e.config.MaxNak {
		feed(t, e, ProtocolLCP, ConfigureNak, e.lcp.id, uint32Option(5, 42))
	}
	if _, _, err := e.input(controlPacket(ProtocolLCP, ConfigureNak, e.lcp.id, uint32Option(5, 42)), time.Unix(1000, 0)); !errors.Is(err, ErrNegotiation) {
		t.Fatalf("Nak loop did not terminate: %v", err)
	}
}

// TestIPCPOptionsAndRejection covers forbidden address-pair/compression/NBNS,
// optional DNS, unusable address Naks, and explicit required address rejection.
func TestIPCPOptionsAndRejection(t *testing.T) {
	e := openEngine(t)
	if e.info.PeerIP.String() != "10.0.0.1" {
		t.Fatal(e.info.PeerIP)
	}
	for _, body := range [][]byte{{1, 10, 0, 0, 0, 0, 0, 0, 0, 0}, {2, 4, 0, 1}, {130, 6, 0, 0, 0, 0}, {132, 6, 0, 0, 0, 0}, {3, 2}} {
		e := openEngine(t)
		response := decoded(t, feed(t, e, ProtocolIPCP, ConfigureRequest, 77, body), 0, ConfigureReject)
		if !bytes.Equal(response.Data, body) || e.opened {
			t.Fatalf("IPCP rejection: %x", response)
		}
	}
	// Renegotiation permits testing a new local offer without reusing stale Acks.
	feed(t, e, ProtocolIPCP, ConfigureRequest, 99, nil)
	for _, addr := range []string{"0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"} {
		original := bytes.Clone(e.ipcp.request)
		feed(t, e, ProtocolIPCP, ConfigureNak, e.ipcp.id, addressOption(3, netip.MustParseAddr(addr)))
		if !bytes.Equal(original, e.ipcp.request) {
			t.Fatalf("adopted unusable address %s", addr)
		}
	}
	dns := e.ipcp.request[6:]
	feed(t, e, ProtocolIPCP, ConfigureReject, e.ipcp.id, dns)
	if len(e.ipcp.request) != 6 || e.info.PrimaryDNS.IsValid() || e.info.SecondaryDNS.IsValid() {
		t.Fatal("optional DNS rejection failed")
	}
	if _, _, err := e.input(controlPacket(ProtocolIPCP, ConfigureReject, e.ipcp.id, e.ipcp.request), time.Unix(1000, 0)); !errors.Is(err, ErrRejected) {
		t.Fatal(err)
	}
}

// TestNakAppendedOptions preserves ordered requested replacements while ignoring
// trailing unrequested suggestions, without accepting reordered or partial updates.
func TestNakAppendedOptions(t *testing.T) {
	assigned := addressOption(3, netip.MustParseAddr("10.0.0.3"))
	primary := addressOption(129, netip.MustParseAddr("1.1.1.1"))
	secondary := addressOption(131, netip.MustParseAddr("8.8.8.8"))
	for _, tc := range []struct {
		name string
		code byte
		body []byte
		want []byte
	}{
		{"appended_dns", ConfigureNak, append(bytes.Clone(assigned), primary...), assigned},
		{"appended_unknown", ConfigureNak, append(bytes.Clone(assigned), 99, 2), assigned},
		{"multiple_appended", ConfigureNak, append(append(bytes.Clone(assigned), secondary...), primary...), assigned},
		{"unrequested_only", ConfigureNak, primary, nil},
		{"unrequested_before_requested", ConfigureNak, append(bytes.Clone(primary), assigned...), nil},
		{"invalid_requested", ConfigureNak, append(uint32Option(3, 0), primary...), nil},
		{"reject_appended", ConfigureReject, append(uint32Option(3, 0), primary...), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := testEngine(t)
			e.config.DisableDNS = true
			feed(t, e, ProtocolLCP, ConfigureAck, e.lcp.id, e.lcp.request)
			feed(t, e, ProtocolLCP, ConfigureRequest, 21, nil)
			original, id := bytes.Clone(e.ipcp.request), e.ipcp.id
			output := feed(t, e, ProtocolIPCP, tc.code, id, tc.body)
			if tc.want == nil {
				if len(output) != 0 || !bytes.Equal(e.ipcp.request, original) || e.ipcp.changes != 0 || e.info.LocalIP.IsValid() {
					t.Fatalf("invalid or ignored response changed offer: %x, %+v", output, e.ipcp)
				}
				return
			}
			request := decoded(t, output, 0, ConfigureRequest)
			if request.ID == id || !bytes.Equal(request.Data, tc.want) || e.info.LocalIP.String() != "10.0.0.3" || e.ipcp.changes != 1 || e.info.PrimaryDNS.IsValid() || e.info.SecondaryDNS.IsValid() {
				t.Fatalf("appended suggestions lost replacement or enabled DNS: %x, %+v", request, e.info)
			}
		})
	}
	// Requested options must keep their order even after an ignored suggestion.
	for _, body := range [][]byte{
		append(bytes.Clone(primary), assigned...),
		append(append(bytes.Clone(assigned), 99, 2), primary...),
	} {
		e := openEngine(t)
		feed(t, e, ProtocolIPCP, ConfigureRequest, 99, nil)
		original := bytes.Clone(e.ipcp.request)
		if output := feed(t, e, ProtocolIPCP, ConfigureNak, e.ipcp.id, body); len(output) != 0 || !bytes.Equal(e.ipcp.request, original) || e.ipcp.changes != 0 {
			t.Fatalf("accepted out-of-order Nak: %x", body)
		}
	}
}

// TestPeerDNSOffers verifies a peer can request DNS only when values are available.
func TestPeerDNSOffers(t *testing.T) {
	e := openEngine(t)
	e.config.PrimaryDNS = netip.MustParseAddr("9.9.9.9")
	e.config.SecondaryDNS = netip.MustParseAddr("8.8.4.4")
	body := append(uint32Option(129, 0), uint32Option(131, 0)...)
	response := decoded(t, feed(t, e, ProtocolIPCP, ConfigureRequest, 90, body), 0, ConfigureNak)
	want := append(addressOption(129, e.config.PrimaryDNS), addressOption(131, e.config.SecondaryDNS)...)
	if !bytes.Equal(response.Data, want) {
		t.Fatalf("peer DNS Nak: %x", response)
	}
	response = decoded(t, feed(t, e, ProtocolIPCP, ConfigureRequest, 91, want), 0, ConfigureAck)
	if !bytes.Equal(response.Data, want) {
		t.Fatal(response)
	}
	e.config.PrimaryDNS, e.config.SecondaryDNS = netip.Addr{}, netip.Addr{}
	response = decoded(t, feed(t, e, ProtocolIPCP, ConfigureRequest, 92, body), 0, ConfigureReject)
	if !bytes.Equal(response.Data, body) {
		t.Fatal(response)
	}
}

// TestProtocolAndCodeRejects verifies CCP, IPv6CP, unknown protocols, optional
// rejected codes, required protocol failures, and unknown control Code-Rejects.
func TestProtocolAndCodeRejects(t *testing.T) {
	for _, protocol := range []uint16{0x80fd, 0x8057, 0x0057, 0x1235} {
		e := openEngine(t)
		packet := []byte{byte(protocol >> 8), byte(protocol), 1, 2, 3}
		output, _, err := e.input(packet, time.Unix(1000, 0))
		response := decoded(t, output, 0, ProtocolReject)
		if err != nil || !bytes.Equal(response.Data, packet) {
			t.Fatalf("Protocol-Reject: %x, %v", response, err)
		}
	}
	for _, protocol := range []uint16{ProtocolLCP, ProtocolIPCP} {
		e := openEngine(t)
		response := decoded(t, feed(t, e, protocol, 99, 42, []byte{7}), 0, CodeReject)
		if !bytes.Equal(response.Data, controlPacket(protocol, 99, 42, []byte{7})[2:]) {
			t.Fatal(response)
		}
		if protocol == ProtocolIPCP {
			for _, code := range []byte{ProtocolReject, EchoRequest, EchoReply, DiscardRequest} {
				decoded(t, feed(t, e, protocol, code, 43, []byte{0, 0, 0, 0}), 0, CodeReject)
			}
		}
	}
	for _, protocol := range []uint16{ProtocolLCP, ProtocolIPCP, ProtocolIPv4} {
		e := openEngine(t)
		if _, _, err := e.input(controlPacket(ProtocolLCP, ProtocolReject, 1, []byte{byte(protocol >> 8), byte(protocol)}), time.Unix(1000, 0)); !errors.Is(err, ErrRejected) {
			t.Fatalf("required protocol rejected: %v", err)
		}
	}
	for _, code := range []byte{ConfigureRequest, ConfigureAck, ConfigureNak, ConfigureReject, TerminateRequest, TerminateAck, CodeReject, EchoRequest} {
		e := openEngine(t)
		if _, _, err := e.input(controlPacket(ProtocolLCP, CodeReject, 1, []byte{code, 1, 0, 4}), time.Unix(1000, 0)); !errors.Is(err, ErrRejected) {
			t.Fatalf("required code rejected: %v", err)
		}
	}
	e := openEngine(t)
	feed(t, e, ProtocolLCP, CodeReject, 1, []byte{99, 1, 0, 4})
	feed(t, e, ProtocolLCP, CodeReject, 1, []byte{1})
	feed(t, e, ProtocolLCP, ProtocolReject, 1, []byte{0x80, 0xfd})
	feed(t, e, ProtocolLCP, ProtocolReject, 1, []byte{0x80})
	feed(t, e, ProtocolLCP, DiscardRequest, 1, nil)
}

// TestMalformedAndPreOpenPackets ensures no malformed/compressed packet, early
// IPv4/IPCP, or oversized control field can open a link or provoke output.
func TestMalformedAndPreOpenPackets(t *testing.T) {
	for _, packet := range [][]byte{
		nil, {0}, {0, 0x20, 1, 2, 3}, {0xff, 3, 0xc0, 0x21}, {0xc0, 0x21, 1},
		{0xc0, 0x21, 1, 1, 0, 3}, {0xc0, 0x21, 1, 1, 0, 8, 1, 0, 5, 0},
		controlPacket(ProtocolLCP, ConfigureRequest, 1, []byte{1, 4, 5, 74, 1, 4, 5, 74}),
		controlPacket(ProtocolIPCP, ConfigureRequest, 1, nil),
		append([]byte{0, 0x21}, ipv4Packet(20)...),
		append([]byte{0x80, 0xfd}, make([]byte, DefaultMRU+1)...),
	} {
		e := testEngine(t)
		output, data, err := e.input(packet, time.Unix(1000, 0))
		if err != nil || len(output) != 0 || data != nil || e.opened {
			t.Fatalf("malformed/early packet processed: %x, %x, %v", packet, output, err)
		}
	}
	e := openEngine(t)
	for _, packet := range [][]byte{{0, 0x21}, append([]byte{0, 0x21}, make([]byte, 20)...)} {
		if _, data, err := e.input(packet, time.Unix(1000, 0)); err != nil || data != nil {
			t.Fatal("invalid IPv4 delivered")
		}
	}
	if output, err := e.tick(time.Unix(1000, 0)); err != nil || len(output) != 0 {
		t.Fatal("early timer fired")
	}
}

// TestRenegotiation closes the IPv4 gate and reopens both protocols on a new LCP
// offer, while exact duplicate offers only replay their previous response.
func TestRenegotiation(t *testing.T) {
	e := openEngine(t)
	output := feed(t, e, ProtocolLCP, ConfigureRequest, e.lcp.peerID, e.lcp.peerData)
	if len(output) != 1 || !e.opened {
		t.Fatal("duplicate offer restarted link")
	}
	body := append([]byte{1, 4, 5, 0}, uint32Option(5, 777)...)
	output = feed(t, e, ProtocolLCP, ConfigureRequest, 31, body)
	decoded(t, output, 0, ConfigureAck)
	decoded(t, output, 1, ConfigureRequest)
	if e.opened || e.ipActive || e.info.LocalIP.IsValid() {
		t.Fatal("LCP renegotiation retained an open IPv4 link")
	}
	feed(t, e, ProtocolLCP, ConfigureAck, e.lcp.id, e.lcp.request)
	feed(t, e, ProtocolIPCP, ConfigureNak, e.ipcp.id, addressOption(3, netip.MustParseAddr("10.0.0.3")))
	feed(t, e, ProtocolIPCP, ConfigureAck, e.ipcp.id, e.ipcp.request)
	feed(t, e, ProtocolIPCP, ConfigureRequest, 32, nil)
	if !e.opened || e.info.LocalIP.String() != "10.0.0.3" || e.info.PeerMagic != 777 || e.info.PeerMRU != 1280 {
		t.Fatalf("renegotiation failed: %+v", e.info)
	}
}

// TestDeadlinesAndShutdownEdges verifies absolute negotiation deadlines, stopping
// gates, no-address failure, bounded diagnostics, and reflected magic rejection.
func TestDeadlinesAndShutdownEdges(t *testing.T) {
	e := testEngine(t)
	if _, err := e.tick(e.deadline); !errors.Is(err, ErrNegotiation) {
		t.Fatal(err)
	}
	e = testEngine(t)
	feed(t, e, ProtocolLCP, ConfigureAck, e.lcp.id, e.lcp.request)
	feed(t, e, ProtocolLCP, ConfigureRequest, 1, nil)
	feed(t, e, ProtocolIPCP, ConfigureRequest, 2, nil)
	if _, _, err := e.input(controlPacket(ProtocolIPCP, ConfigureAck, e.ipcp.id, e.ipcp.request), time.Unix(1000, 0)); !errors.Is(err, ErrRejected) {
		t.Fatal("zero local address opened IPCP")
	}
	e = openEngine(t)
	e.info.PeerMRU = 128
	body := bytes.Repeat([]byte{42}, 500)
	response := decoded(t, feed(t, e, ProtocolLCP, 99, 2, body), 0, CodeReject)
	if len(response.Data) != 124 {
		t.Fatal("Code-Reject exceeded peer MRU")
	}
	if output := feed(t, e, ProtocolLCP, EchoRequest, 3, uint32Option(5, e.info.Magic)[2:]); len(output) != 0 {
		t.Fatal("responded to reflected magic")
	}
	feed(t, e, ProtocolLCP, EchoRequest, 3, nil)
	now := time.Unix(1000, 0)
	e.stop(now)
	if output, err := e.tick(now); err != nil || len(output) != 0 {
		t.Fatal("early termination retry")
	}
	feed(t, e, ProtocolLCP, ConfigureRequest, 3, nil)
	feed(t, e, ProtocolLCP, ConfigureAck, e.lcp.id, e.lcp.request)
	feed(t, e, ProtocolIPCP, ConfigureRequest, 3, nil)
	if _, data, err := e.input(append([]byte{0, 0x21}, ipv4Packet(20)...), now); err != nil || data != nil {
		t.Fatal("stopping link delivered IPv4")
	}
}

// TestConfigValidation exercises defaults and rejects unbounded or invalid inputs.
func TestConfigValidation(t *testing.T) {
	config, err := (Config{}).defaults()
	if err != nil || config.Magic == 0 || config.EchoInterval != 10*time.Second || config.Clock == nil {
		t.Fatalf("defaults: %+v, %v", config, err)
	}
	for _, config := range []Config{
		{MaxConfigure: -1}, {MaxConfigure: 101}, {MaxNak: 101}, {MaxTerminate: 11},
		{RetryInterval: time.Nanosecond}, {RetryInterval: 2 * time.Minute},
		{WriteTimeout: -1}, {WriteTimeout: 2 * time.Minute}, {EchoInterval: -1},
		{EchoInterval: 2 * time.Minute}, {NegotiationTimeout: -1}, {NegotiationTimeout: time.Hour},
		{PrimaryDNS: netip.MustParseAddr("::1")}, {SecondaryDNS: netip.MustParseAddr("0.0.0.0")},
	} {
		if _, err := config.defaults(); err == nil {
			t.Fatalf("accepted invalid config: %+v", config)
		}
	}
	if _, err := Negotiate(context.Background(), nil, Config{}); err == nil {
		t.Fatal("accepted nil transport")
	}
	if _, err := Negotiate(context.Background(), newPeer(), Config{MaxNak: -1}); err == nil {
		t.Fatal("accepted invalid config at entry")
	}
	if differentMagic(0x5a5a5a5a) != 1 {
		t.Fatal("zero alternate magic")
	}
}
