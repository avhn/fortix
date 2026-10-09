package ppp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// peerTransport simulates a gateway packet boundary and cancellable full-duplex I/O.
type peerTransport struct {
	incoming chan readResult
	outgoing chan []byte
	writeErr error
}

// newPeer allocates small bounded queues rather than opening privileged interfaces.
func newPeer() *peerTransport {
	return &peerTransport{incoming: make(chan readResult, 64), outgoing: make(chan []byte, 64)}
}

// ReadPacket waits for a peer packet, injected error, or context cancellation.
func (p *peerTransport) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-p.incoming:
		return result.packet, result.err
	}
}

// WritePacket records an owned packet or simulates transport failure.
func (p *peerTransport) WritePacket(ctx context.Context, packet []byte) error {
	if p.writeErr != nil {
		return p.writeErr
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.outgoing <- bytes.Clone(packet):
		return nil
	}
}

// send delivers one control packet from the simulated gateway.
func (p *peerTransport) send(protocol uint16, code, id byte, body []byte) {
	p.incoming <- readResult{packet: controlPacket(protocol, code, id, body)}
}

// receive checks the exact protocol and code of the next output without hanging.
func (p *peerTransport) receive(t *testing.T, protocol uint16, code byte) Control {
	t.Helper()
	select {
	case packet := <-p.outgoing:
		if len(packet) < 2 || binary.BigEndian.Uint16(packet[:2]) != protocol {
			t.Fatalf("unexpected protocol in %x", packet)
		}
		control, err := DecodeControl(packet[2:])
		if err != nil || control.Code != code {
			t.Fatalf("wanted code %d, got %x, error %v", code, packet, err)
		}
		return control
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for peer output")
		return Control{}
	}
}

// fakeClock serializes simulated time and one-shot timer registrations.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*fakeTimer]time.Time
}

// fakeTimer records its owner and single buffered deadline notification.
type fakeTimer struct {
	clock *fakeClock
	ch    chan time.Time
}

// newClock starts simulated time at a nonzero stable epoch.
func newClock() *fakeClock {
	return &fakeClock{now: time.Unix(1000, 0), timers: make(map[*fakeTimer]time.Time)}
}

// Now reads simulated monotonic time under the same lock used for timer creation.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// NewTimer registers a deadline or immediately delivers an already due event.
func (c *fakeClock) NewTimer(delay time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &fakeTimer{clock: c, ch: make(chan time.Time, 1)}
	if delay <= 0 {
		timer.ch <- c.now
	} else {
		c.timers[timer] = c.now.Add(delay)
	}
	return timer
}

// dueWithin reports whether a registered timer expires within delay of simulated now.
func (c *fakeClock) dueWithin(delay time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	limit := c.now.Add(delay)
	for _, due := range c.timers {
		if !due.After(limit) {
			return true
		}
	}
	return false
}

// C returns the timer's one-shot event stream.
func (t *fakeTimer) C() <-chan time.Time { return t.ch }

// Stop removes a pending timer from the simulated clock.
func (t *fakeTimer) Stop() {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	delete(t.clock.timers, t)
}

// advance delivers each elapsed timer at most once. The worker reads Now before it
// registers a timer, so advance first waits briefly for a timer due inside the step;
// advancing in that gap would push the registration a full step past the target.
func (c *fakeClock) advance(delay time.Duration) {
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if c.dueWithin(delay) {
			break
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delay)
	for timer, due := range c.timers {
		if !due.After(c.now) {
			timer.ch <- c.now
			delete(c.timers, timer)
		}
	}
}

// startNegotiation owns cancellation and a finite result wait for each simulator.
func startNegotiation(t *testing.T, peer *peerTransport, config Config) <-chan negotiationResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	result := make(chan negotiationResult, 1)
	go func() {
		info, err := Negotiate(ctx, peer, config)
		result <- negotiationResult{info: info, err: err}
	}()
	t.Cleanup(cancel)
	return result
}

// awaitNegotiated waits for completion and owns worker teardown after a success.
func awaitNegotiated(t *testing.T, result <-chan negotiationResult) Negotiated {
	t.Helper()
	select {
	case negotiated := <-result:
		if negotiated.err != nil {
			t.Fatal(negotiated.err)
		}
		t.Cleanup(func() {
			negotiated.info.Link.cancel()
			_ = negotiated.info.Link.Wait()
		})
		return negotiated.info
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for negotiation")
		return Negotiated{}
	}
}

// exchangeLCP completes both directions with MRU, magic, and tolerated ACCM.
func exchangeLCP(t *testing.T, peer *peerTransport, ackFirst bool) Control {
	t.Helper()
	request := peer.receive(t, ProtocolLCP, ConfigureRequest)
	peerOffer := append([]byte{1, 4, 5, 74}, uint32Option(5, 0x10203040)...)
	peerOffer = append(peerOffer, uint32Option(2, 0)...)
	if ackFirst {
		peer.send(ProtocolLCP, ConfigureAck, request.ID, request.Data)
	}
	peer.send(ProtocolLCP, ConfigureRequest, 71, peerOffer)
	ack := peer.receive(t, ProtocolLCP, ConfigureAck)
	if ack.ID != 71 || !bytes.Equal(ack.Data, peerOffer) {
		t.Fatal("peer Configure-Ack was not byte-identical")
	}
	if !ackFirst {
		peer.send(ProtocolLCP, ConfigureAck, request.ID, request.Data)
	}
	return peer.receive(t, ProtocolIPCP, ConfigureRequest)
}

// openPeer establishes the link with assigned IPv4 and optional DNS rejection.
func openPeer(t *testing.T, config Config, ackFirst, rejectDNS bool) (*peerTransport, Negotiated) {
	t.Helper()
	peer := newPeer()
	result := startNegotiation(t, peer, config)
	request := exchangeLCP(t, peer, ackFirst)
	if rejectDNS && !config.DisableDNS {
		peer.send(ProtocolIPCP, ConfigureReject, request.ID, request.Data[6:])
		request = peer.receive(t, ProtocolIPCP, ConfigureRequest)
		if len(request.Data) != 6 {
			t.Fatalf("DNS rejection retained options: %x", request.Data)
		}
	}
	peer.send(ProtocolIPCP, ConfigureRequest, 91, nil)
	ack := peer.receive(t, ProtocolIPCP, ConfigureAck)
	if ack.ID != 91 || len(ack.Data) != 0 {
		t.Fatal("empty peer IPCP request was not acknowledged")
	}
	nak := addressOption(3, netip.MustParseAddr("10.0.0.2"))
	if !rejectDNS && !config.DisableDNS {
		nak = append(nak, addressOption(129, netip.MustParseAddr("1.1.1.1"))...)
		nak = append(nak, addressOption(131, netip.MustParseAddr("8.8.8.8"))...)
	}
	peer.send(ProtocolIPCP, ConfigureNak, request.ID, nak)
	revised := peer.receive(t, ProtocolIPCP, ConfigureRequest)
	if revised.ID == request.ID || !bytes.Equal(revised.Data, nak) {
		t.Fatalf("Nak not adopted in new offer: %x", revised)
	}
	peer.send(ProtocolIPCP, ConfigureAck, revised.ID, revised.Data)
	return peer, awaitNegotiated(t, result)
}

// ipv4Packet creates a complete minimal IPv4 packet of a requested size.
func ipv4Packet(size int) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	packet[8], packet[9] = 64, 17
	return packet
}

// TestPeerNegotiationAndData exercises both Ack orders, optional DNS, and IPv4 I/O.
func TestPeerNegotiationAndData(t *testing.T) {
	for _, ackFirst := range []bool{false, true} {
		for _, rejectDNS := range []bool{false, true} {
			t.Run(string([]byte{'0' + byteBool(ackFirst), '0' + byteBool(rejectDNS)}), func(t *testing.T) {
				clock := newClock()
				config := Config{Clock: clock, Magic: 0xaabbccdd, PrimaryDNS: netip.MustParseAddr("9.9.9.9")}
				peer, info := openPeer(t, config, ackFirst, rejectDNS)
				if info.LocalIP.String() != "10.0.0.2" || info.PeerIP.IsValid() || info.MRU != DefaultMRU || info.PeerMRU != DefaultMRU || info.PeerMagic != 0x10203040 || info.Magic != config.Magic {
					t.Fatalf("unexpected negotiated state: %+v", info)
				}
				wantDNS := "1.1.1.1"
				if rejectDNS {
					wantDNS = "9.9.9.9"
				}
				if info.PrimaryDNS.String() != wantDNS {
					t.Fatalf("DNS: %v, want %s", info.PrimaryDNS, wantDNS)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				packet := ipv4Packet(24)
				if err := info.Link.WriteIPv4(ctx, packet); err != nil {
					t.Fatal(err)
				}
				select {
				case wire := <-peer.outgoing:
					if !bytes.Equal(wire, append([]byte{0, 0x21}, packet...)) {
						t.Fatalf("incorrect IPv4 framing: %x", wire)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				peer.incoming <- readResult{packet: append([]byte{0, 0x21}, packet...)}
				got, err := info.Link.ReadIPv4(ctx)
				if err != nil || !bytes.Equal(got, packet) {
					t.Fatalf("IPv4 demux: %x, %v", got, err)
				}
			})
		}
	}
}

// TestPeerNakAppendedDNS completes negotiation when DNS discovery is disabled
// and the peer appends an unsolicited DNS suggestion to a usable address Nak.
func TestPeerNakAppendedDNS(t *testing.T) {
	peer := newPeer()
	fallback := netip.MustParseAddr("9.9.9.9")
	result := startNegotiation(t, peer, Config{Clock: newClock(), Magic: 11, DisableDNS: true, PrimaryDNS: fallback})
	request := exchangeLCP(t, peer, true)
	assigned := addressOption(3, netip.MustParseAddr("10.0.0.2"))
	nak := append(bytes.Clone(assigned), addressOption(129, netip.MustParseAddr("1.1.1.1"))...)
	peer.send(ProtocolIPCP, ConfigureNak, request.ID, nak)
	revised := peer.receive(t, ProtocolIPCP, ConfigureRequest)
	if revised.ID == request.ID || !bytes.Equal(revised.Data, assigned) {
		t.Fatalf("address assignment lost or DNS discovery enabled: %x", revised)
	}
	peer.send(ProtocolIPCP, ConfigureRequest, 91, nil)
	peer.receive(t, ProtocolIPCP, ConfigureAck)
	peer.send(ProtocolIPCP, ConfigureAck, revised.ID, revised.Data)
	info := awaitNegotiated(t, result)
	if info.LocalIP.String() != "10.0.0.2" || info.PrimaryDNS != fallback {
		t.Fatalf("unexpected address or DNS fallback: %+v", info)
	}
}

// byteBool formats deterministic subtest names without configuration string parsing.
func byteBool(value bool) byte {
	if value {
		return 1
	}
	return 0
}

// TestPeerKeepalive validates negotiated magic, exact IDs, diagnostic isolation,
// queue backpressure, and failure after three missed ten-second reply windows.
func TestPeerKeepalive(t *testing.T) {
	clock := newClock()
	peer, info := openPeer(t, Config{Clock: clock, Magic: 0xaabbccdd}, false, false)
	clock.advance(10 * time.Second)
	echo := peer.receive(t, ProtocolLCP, EchoRequest)
	if binary.BigEndian.Uint32(echo.Data) != info.Magic {
		t.Fatal("echo request did not use local negotiated magic")
	}
	// An unrelated Protocol-Reject must not replace the outstanding echo ID.
	peer.incoming <- readResult{packet: []byte{0x80, 0xfd, 1, 2, 3}}
	peer.receive(t, ProtocolLCP, ProtocolReject)
	peer.send(ProtocolLCP, EchoReply, echo.ID, uint32Option(5, info.PeerMagic)[2:])
	peer.send(ProtocolLCP, EchoRequest, 123, append(uint32Option(5, info.PeerMagic)[2:], 42))
	reply := peer.receive(t, ProtocolLCP, EchoReply)
	if reply.ID != 123 || binary.BigEndian.Uint32(reply.Data[:4]) != info.Magic || reply.Data[4] != 42 {
		t.Fatalf("incorrect echo reply: %x", reply)
	}
	for range 40 {
		peer.incoming <- readResult{packet: append([]byte{0, 0x21}, ipv4Packet(20)...)}
	}
	for range 3 {
		clock.advance(10 * time.Second)
		echo = peer.receive(t, ProtocolLCP, EchoRequest)
		// Reflected local magic and stale identifiers must not count as replies.
		peer.send(ProtocolLCP, EchoReply, echo.ID, uint32Option(5, info.Magic)[2:])
		peer.send(ProtocolLCP, EchoReply, echo.ID-1, uint32Option(5, info.PeerMagic)[2:])
	}
	clock.advance(10 * time.Second)
	select {
	case <-info.Link.done:
		if err := info.Link.Wait(); !errors.Is(err, ErrKeepalive) {
			t.Fatalf("keepalive failure: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("three missed replies did not fail link")
	}
}

// TestPeerTermination covers remote Terminate, local Ack matching, idempotent
// Close, and closed readiness after an Echo-Request during local termination.
func TestPeerTermination(t *testing.T) {
	t.Run("remote", func(t *testing.T) {
		peer, info := openPeer(t, Config{Magic: 11}, false, false)
		peer.send(ProtocolLCP, TerminateRequest, 66, []byte("stop"))
		ack := peer.receive(t, ProtocolLCP, TerminateAck)
		if ack.ID != 66 || string(ack.Data) != "stop" {
			t.Fatal("incorrect termination acknowledgement")
		}
		if err := info.Link.Wait(); !errors.Is(err, ErrTerminated) {
			t.Fatal(err)
		}
	})
	t.Run("local", func(t *testing.T) {
		peer, info := openPeer(t, Config{Magic: 11}, true, false)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		closed := make(chan error, 1)
		go func() { closed <- info.Link.Close(ctx) }()
		request := peer.receive(t, ProtocolLCP, TerminateRequest)
		peer.send(ProtocolLCP, TerminateAck, request.ID+1, nil)
		peer.send(ProtocolLCP, EchoRequest, 123, uint32Option(5, info.PeerMagic)[2:])
		reply := peer.receive(t, ProtocolLCP, EchoReply)
		if reply.ID != 123 || binary.BigEndian.Uint32(reply.Data) != info.Magic {
			t.Fatalf("incorrect echo reply during termination: %x", reply)
		}
		// A worker command is a publication barrier after the echo response.
		if err := info.Link.WriteIPv4(ctx, ipv4Packet(20)); !errors.Is(err, ErrNotOpen) {
			t.Fatalf("terminating link accepted IPv4: %v", err)
		}
		if _, open := info.Link.Info(); open {
			t.Fatal("echo request reopened readiness during local termination")
		}
		peer.send(ProtocolLCP, TerminateAck, request.ID, nil)
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if err := info.Link.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := info.Link.ReadIPv4(ctx); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	})
	t.Run("bounded", func(t *testing.T) {
		clock := newClock()
		peer, info := openPeer(t, Config{Clock: clock, Magic: 11}, false, false)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		closed := make(chan error, 1)
		go func() { closed <- info.Link.Close(ctx) }()
		first := peer.receive(t, ProtocolLCP, TerminateRequest)
		clock.advance(3 * time.Second)
		second := peer.receive(t, ProtocolLCP, TerminateRequest)
		if first.ID != second.ID {
			t.Fatal("terminate retransmission changed ID")
		}
		clock.advance(3 * time.Second)
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	})
}

// TestPeerRetryAndCancellation verifies byte-identical retries and prompt cleanup.
func TestPeerRetryAndCancellation(t *testing.T) {
	clock := newClock()
	peer := newPeer()
	result := startNegotiation(t, peer, Config{Clock: clock, Magic: 5, MaxConfigure: 2})
	first := peer.receive(t, ProtocolLCP, ConfigureRequest)
	clock.advance(3 * time.Second)
	second := peer.receive(t, ProtocolLCP, ConfigureRequest)
	if first.ID != second.ID || !bytes.Equal(first.Data, second.Data) {
		t.Fatal("retransmission was not byte-identical")
	}
	clock.advance(3 * time.Second)
	select {
	case got := <-result:
		if !errors.Is(got.err, ErrNegotiation) {
			t.Fatal(got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retry budget did not fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Negotiate(ctx, newPeer(), Config{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// TestTransportFailures preserves underlying reader/writer failures and validates
// outbound packet rejection without killing an otherwise healthy link.
func TestTransportFailures(t *testing.T) {
	peer := newPeer()
	peer.writeErr = io.ErrClosedPipe
	if _, err := Negotiate(context.Background(), peer, Config{Magic: 1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	peer, info := openPeer(t, Config{Magic: 1, DisableDNS: true}, false, false)
	if err := info.Link.WriteIPv4(context.Background(), []byte{6}); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := info.Link.ReadIPv4(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := info.Link.WriteIPv4(ctx, ipv4Packet(20)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	peer.incoming <- readResult{err: io.ErrUnexpectedEOF}
	if err := info.Link.Wait(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}

// TestDataGenerationIsolation prevents queued packets from a previous address
// from being delivered across a renegotiation, including a receiver race.
func TestDataGenerationIsolation(t *testing.T) {
	e := openEngine(t)
	link := &Link{data: make(chan dataPacket, 4), done: make(chan struct{})}
	link.publish(e)
	link.data <- dataPacket{packet: ipv4Packet(20), generation: 0}
	e.opened = false
	link.publish(e)
	if len(link.data) != 0 || link.generation != 1 {
		t.Fatal("old receive queue survived closure")
	}
	e.opened = true
	link.publish(e)
	old, fresh := ipv4Packet(20), ipv4Packet(24)
	link.data <- dataPacket{packet: old, generation: 0}
	link.data <- dataPacket{packet: fresh, generation: 1}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := link.ReadIPv4(ctx)
	if err != nil || !bytes.Equal(got, fresh) {
		t.Fatalf("obsolete generation delivered: %x, %v", got, err)
	}
	link.open = false
	link.data <- dataPacket{packet: fresh, generation: 1}
	if _, err := link.ReadIPv4(ctx); !errors.Is(err, ErrNotOpen) {
		t.Fatal(err)
	}
}

// TestCloseDeadlineAndLiveCancellation verifies a missing Terminate-Ack cannot
// retain workers past caller cancellation, including an active negotiation read.
func TestCloseDeadlineAndLiveCancellation(t *testing.T) {
	peer, info := openPeer(t, Config{Magic: 3}, false, false)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- info.Link.Close(ctx) }()
	peer.receive(t, ProtocolLCP, TerminateRequest)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled Close retained workers")
	}
	peer = newPeer()
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		_, err := Negotiate(ctx, peer, Config{Magic: 3})
		result <- err
	}()
	peer.receive(t, ProtocolLCP, ConfigureRequest)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled negotiation retained workers")
	}
}

// TestSmallPeerMRUAndClosedDataGate checks that outbound IPv4 respects the peer's
// independent MRU and that renegotiation rejects writes until IPCP reopens.
func TestSmallPeerMRUAndClosedDataGate(t *testing.T) {
	peer, info := openPeer(t, Config{Magic: 3}, false, false)
	peer.send(ProtocolIPCP, ConfigureRequest, 92, nil)
	peer.receive(t, ProtocolIPCP, ConfigureAck)
	request := peer.receive(t, ProtocolIPCP, ConfigureRequest)
	if err := info.Link.WriteIPv4(context.Background(), ipv4Packet(20)); !errors.Is(err, ErrNotOpen) {
		t.Fatal(err)
	}
	peer.send(ProtocolIPCP, ConfigureAck, request.ID, request.Data)
	// A subsequent echo is a barrier after the queued Configure-Ack.
	peer.send(ProtocolLCP, EchoRequest, 100, uint32Option(5, info.PeerMagic)[2:])
	peer.receive(t, ProtocolLCP, EchoReply)
	if _, open := info.Link.Info(); !open {
		t.Fatal("IPCP did not reopen")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Direct worker commands test the independent send-MRU boundary without
	// requiring a second full exchange to establish a different peer MRU.
	e := openEngine(t)
	e.info.PeerMRU = 128
	requestCommand := command{ctx: ctx, packet: ipv4Packet(129), result: make(chan error, 1)}
	if output, err := info.Link.handleCommand(ctx, peer, e, requestCommand); err != nil || len(output) != 0 {
		t.Fatalf("MRU rejection killed the link: %x, %v", output, err)
	}
	if err := <-requestCommand.result; !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}
