package ppp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Transport carries complete PPP packets, including a two-byte protocol field,
// without HDLC or gateway framing. ReadPacket and WritePacket must honor context
// cancellation promptly. The link serializes writes and performs only one read
// at a time; a read may run concurrently with a write. Buffers belong to callers.
// Transport ownership stays with the caller, which closes the underlying stream.
type Transport interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
}

// Clock supplies monotonic deadlines and cancellable timers for deterministic
// negotiation and keepalive tests. Production defaults to the system clock.
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}

// Timer exposes a single deadline notification. Stop releases pending resources;
// a new timer is used after each event, so implementations need no reset support.
type Timer interface {
	C() <-chan time.Time
	Stop()
}

// Config controls finite negotiation and shutdown budgets. Zero values choose
// MRU 1354, random nonzero magic, ten Configure transmissions, five Nak/Reject
// changes, two Terminate transmissions, three-second retries and writes,
// thirty-second negotiation, and ten-second echo intervals. Echo failure always
// requires three missed replies. DNS fallback addresses are optional IPv4 values;
// IPCP DNS overrides them. DisableDNS omits DNS discovery, not fallback values.
// Clock and Magic allow reproducible peer simulations without host networking.
// StopOnRenegotiation fails a reopened protocol before acknowledging a new offer,
// for callers that cannot reconfigure their network while forwarding is paused.
type Config struct {
	Clock               Clock
	Magic               uint32
	MaxConfigure        int
	MaxNak              int
	MaxTerminate        int
	RetryInterval       time.Duration
	NegotiationTimeout  time.Duration
	WriteTimeout        time.Duration
	EchoInterval        time.Duration
	DisableDNS          bool
	StopOnRenegotiation bool
	PrimaryDNS          netip.Addr
	SecondaryDNS        netip.Addr
}

// Negotiated is an immutable snapshot of the IPv4 address, DNS, MRUs, and magic
// numbers. PeerIP may be invalid when the peer sends an empty IPCP request.
// Link owns ongoing control processing and IPv4 I/O; Info returns updated values
// if the peer later renegotiates. MRUs describe information fields, not protocols.
type Negotiated struct {
	LocalIP      netip.Addr
	PeerIP       netip.Addr
	PrimaryDNS   netip.Addr
	SecondaryDNS netip.Addr
	MRU          int
	PeerMRU      int
	Magic        uint32
	PeerMagic    uint32
	Link         *Link
}

// Link is a bounded IPv4 demultiplexer with one control worker and one transport
// reader. Its lifetime is bounded by the context passed to Negotiate or Close.
// A full receive queue drops data rather than delaying control or keepalive.
type Link struct {
	cancel     context.CancelFunc
	done       chan struct{}
	data       chan dataPacket
	commands   chan command
	mu         sync.RWMutex
	info       Negotiated
	open       bool
	generation uint64
	err        error
}

// dataPacket associates received data with the address generation that accepted it.
// A receiver racing renegotiation cannot deliver a packet from an obsolete link.
type dataPacket struct {
	packet     []byte
	generation uint64
}

// command serializes outbound data and local termination on the control worker.
type command struct {
	ctx    context.Context
	packet []byte
	stop   bool
	result chan error
}

// readResult transports a single owned packet or read failure to the worker.
type readResult struct {
	packet []byte
	err    error
}

// negotiationResult delivers the first complete negotiation or its failure.
type negotiationResult struct {
	info Negotiated
	err  error
}

// systemClock implements monotonic time and standard library timers.
type systemClock struct{}

// Now returns the system's monotonic-capable current time.
func (systemClock) Now() time.Time { return time.Now() }

// NewTimer schedules a single bounded wait using the system timer heap.
func (systemClock) NewTimer(delay time.Duration) Timer {
	return systemTimer{time.NewTimer(delay)}
}

// systemTimer adapts a standard timer without exposing reset races to callers.
type systemTimer struct{ timer *time.Timer }

// C returns the single deadline channel.
func (t systemTimer) C() <-chan time.Time { return t.timer.C }

// Stop releases the pending timer; its channel is never reused.
func (t systemTimer) Stop() { t.timer.Stop() }

// defaults fills zero-valued budgets and validates finite resource limits before
// any transport operation. Random magic generation failures are returned directly.
func (c Config) defaults() (Config, error) {
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.MaxConfigure == 0 {
		c.MaxConfigure = 10
	}
	if c.MaxNak == 0 {
		c.MaxNak = 5
	}
	if c.MaxTerminate == 0 {
		c.MaxTerminate = 2
	}
	if c.RetryInterval == 0 {
		c.RetryInterval = 3 * time.Second
	}
	if c.NegotiationTimeout == 0 {
		c.NegotiationTimeout = 30 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 3 * time.Second
	}
	if c.EchoInterval == 0 {
		c.EchoInterval = 10 * time.Second
	}
	if c.MaxConfigure < 1 || c.MaxConfigure > 100 || c.MaxNak < 1 || c.MaxNak > 100 || c.MaxTerminate < 1 || c.MaxTerminate > 10 || c.RetryInterval < time.Millisecond || c.RetryInterval > time.Minute || c.WriteTimeout < time.Millisecond || c.WriteTimeout > time.Minute || c.NegotiationTimeout < time.Millisecond || c.NegotiationTimeout > 10*time.Minute || c.EchoInterval < time.Millisecond || c.EchoInterval > time.Minute {
		return c, errors.New("invalid PPP retry or deadline budget")
	}
	for _, addr := range []netip.Addr{c.PrimaryDNS, c.SecondaryDNS} {
		if addr.IsValid() && !usableAddress(addr) {
			return c, errors.New("PPP DNS fallback must be a unicast IPv4 address")
		}
	}
	if c.Magic == 0 {
		var value [4]byte
		if _, err := rand.Read(value[:]); err != nil {
			return c, err
		}
		c.Magic = binary.BigEndian.Uint32(value[:])
		if c.Magic == 0 {
			c.Magic = 1
		}
	}
	return c, nil
}

// Negotiate exchanges LCP and IPCP in both directions and returns only after both
// are open with a usable local IPv4 address. ctx governs negotiation and the
// resulting link lifetime. transport must implement cancellable packet I/O;
// config supplies optional clock, magic, DNS fallbacks, and finite budgets.
// Failures release both workers before returning and preserve transport/context
// errors. No credentials or host network configuration are handled here.
func Negotiate(ctx context.Context, transport Transport, config Config) (Negotiated, error) {
	if transport == nil {
		return Negotiated{}, errors.New("nil PPP transport")
	}
	config, err := config.defaults()
	if err != nil {
		return Negotiated{}, err
	}
	if err := ctx.Err(); err != nil {
		return Negotiated{}, err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	link := &Link{cancel: cancel, done: make(chan struct{}), data: make(chan dataPacket, 32), commands: make(chan command)}
	ready := make(chan negotiationResult, 1)
	go link.run(workerCtx, transport, config, ready)
	result := <-ready
	if result.err != nil {
		<-link.done
	}
	return result.info, result.err
}

// Info returns the latest negotiated snapshot and whether IPv4 is currently open.
// The returned snapshot is detached from mutable worker state.
func (l *Link) Info() (Negotiated, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.info, l.open
}

// ReadIPv4 returns one complete owned IPv4 packet, a context error, or the terminal
// link error. Control packets are serviced separately even when callers are idle.
func (l *Link) ReadIPv4(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.done:
			return nil, l.failure()
		case data := <-l.data:
			l.mu.RLock()
			open, generation := l.open, l.generation
			l.mu.RUnlock()
			if !open {
				return nil, ErrNotOpen
			}
			if data.generation == generation {
				return data.packet, nil
			}
		}
	}
}

// WriteIPv4 validates and copies a complete IPv4 packet, then waits for serialized
// transport I/O. Oversized, malformed, or pre-open packets are rejected. ctx bounds
// queueing and the write; the configured write timeout remains an upper bound.
func (l *Link) WriteIPv4(ctx context.Context, packet []byte) error {
	if len(packet) > DefaultMRU || !validIPv4(packet) {
		return ErrMalformed
	}
	request := command{ctx: ctx, packet: bytes.Clone(packet), result: make(chan error, 1)}
	return l.submit(ctx, request)
}

// submit dispatches one command without retaining a caller blocked on cancellation.
func (l *Link) submit(ctx context.Context, request command) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return l.failure()
	case l.commands <- request:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-request.result:
		return err
	case <-l.done:
		return l.failure()
	}
}

// Close requests LCP Terminate and waits for Ack or bounded retry exhaustion.
// A context deadline forces worker cancellation and waits for reader cleanup.
// Repeated Close calls are safe; graceful local closure returns nil.
func (l *Link) Close(ctx context.Context) error {
	request := command{ctx: ctx, stop: true, result: make(chan error, 1)}
	err := l.submit(ctx, request)
	if err != nil && !errors.Is(err, ErrClosed) {
		l.cancel()
		<-l.done
		return err
	}
	select {
	case <-ctx.Done():
		l.cancel()
		<-l.done
		return ctx.Err()
	case <-l.done:
		return l.Wait()
	}
}

// Wait blocks until both workers exit and returns their terminal error. A bounded
// local termination returns nil; peer termination and keepalive failure remain errors.
func (l *Link) Wait() error {
	<-l.done
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.err
}

// failure provides a non-nil I/O error even after graceful local termination.
func (l *Link) failure() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.err != nil {
		return l.err
	}
	return ErrClosed
}

// publish atomically exposes current state, applying DNS fallback only to the
// snapshot so rejected discovery options cannot overwrite negotiated DNS values.
func (l *Link) publish(e *engine) Negotiated {
	info := e.info
	if !info.PrimaryDNS.IsValid() {
		info.PrimaryDNS = e.config.PrimaryDNS
	}
	if !info.SecondaryDNS.IsValid() {
		info.SecondaryDNS = e.config.SecondaryDNS
	}
	info.Link = l
	l.mu.Lock()
	if l.open && !e.opened {
		l.generation++
		// Packets queued under an old address must not survive renegotiation.
	drain:
		for {
			select {
			case <-l.data:
			default:
				break drain
			}
		}
	}
	l.info, l.open = info, e.opened
	l.mu.Unlock()
	return info
}

// readPackets owns the only transport reader and hands off at most one packet.
// Copying before handoff permits transports to reuse their next-read buffers.
func readPackets(ctx context.Context, transport Transport, packets chan<- readResult, done chan<- struct{}) {
	defer close(done)
	for {
		packet, err := transport.ReadPacket(ctx)
		if len(packet) > DefaultMRU+2 {
			packet = nil
		} else {
			packet = bytes.Clone(packet)
		}
		select {
		case packets <- readResult{packet: packet, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

// writePackets serializes finite control output under the worker lifetime and
// configured write deadline. A partial control exchange fails the whole link.
func writePackets(ctx context.Context, transport Transport, config Config, packets [][]byte) error {
	for _, packet := range packets {
		writeCtx, cancel := context.WithTimeout(ctx, config.WriteTimeout)
		err := transport.WritePacket(writeCtx, packet)
		cancel()
		if err != nil {
			return fmt.Errorf("write PPP packet: %w", err)
		}
	}
	return nil
}

// run keeps all mutable protocol state in one worker and guarantees reader cleanup
// before closing done. Timers come from Clock; context/write budgets use contexts.
func (l *Link) run(ctx context.Context, transport Transport, config Config, ready chan<- negotiationResult) {
	packets := make(chan readResult, 1)
	readerDone := make(chan struct{})
	go readPackets(ctx, transport, packets, readerDone)
	e := newEngine(config, config.Clock.Now())
	announced := false
	var terminal error
	defer func() {
		l.cancel()
		<-readerDone
		if errors.Is(terminal, ErrClosed) {
			terminal = nil
		}
		l.mu.Lock()
		l.err, l.open = terminal, false
		l.mu.Unlock()
		if !announced {
			if terminal == nil {
				terminal = ErrClosed
			}
			ready <- negotiationResult{err: terminal}
		}
		close(l.done)
	}()
	initial, err := e.lcp.sendRequest(e, config.Clock.Now(), true)
	if err != nil {
		terminal = err
		return
	}
	if terminal = writePackets(ctx, transport, config, [][]byte{initial}); terminal != nil {
		return
	}
	for {
		info := l.publish(e)
		if e.opened && !announced {
			announced = true
			ready <- negotiationResult{info: info}
		}
		timer := config.Clock.NewTimer(max(time.Duration(0), e.nextDeadline().Sub(config.Clock.Now())))
		var output [][]byte
		select {
		case <-ctx.Done():
			terminal = ctx.Err()
		case result := <-packets:
			if result.err != nil {
				terminal = fmt.Errorf("read PPP packet: %w", result.err)
				break
			}
			var data []byte
			output, data, terminal = e.input(result.packet, config.Clock.Now())
			if data != nil {
				l.mu.RLock()
				generation := l.generation
				l.mu.RUnlock()
				select {
				case l.data <- dataPacket{packet: data, generation: generation}:
				default:
					// Dropping data avoids starving control when the interface stalls.
				}
			}
		case <-timer.C():
			output, terminal = e.tick(config.Clock.Now())
		case request := <-l.commands:
			output, terminal = l.handleCommand(ctx, transport, e, request)
		}
		timer.Stop()
		if err := writePackets(ctx, transport, config, output); err != nil {
			terminal = err
		}
		if terminal != nil {
			return
		}
	}
}

// handleCommand checks the current data gate and serializes a bounded user write,
// or begins local termination. Caller cancellations do not tear down a healthy
// link unless an in-flight write could have left transport framing incomplete.
func (l *Link) handleCommand(ctx context.Context, transport Transport, e *engine, request command) ([][]byte, error) {
	if err := request.ctx.Err(); err != nil {
		request.result <- err
		return nil, nil
	}
	if request.stop {
		var output [][]byte
		if !e.stopping {
			output = [][]byte{e.stop(e.config.Clock.Now())}
		}
		request.result <- nil
		return output, nil
	}
	if !e.opened || e.stopping {
		request.result <- ErrNotOpen
		return nil, nil
	}
	if len(request.packet) > min(e.info.PeerMRU, DefaultMRU) {
		request.result <- ErrMalformed
		return nil, nil
	}
	writeCtx, cancel := context.WithTimeout(request.ctx, e.config.WriteTimeout)
	stopCancel := context.AfterFunc(ctx, cancel)
	packet := append([]byte{0, byte(ProtocolIPv4)}, request.packet...)
	err := transport.WritePacket(writeCtx, packet)
	stopCancel()
	cancel()
	request.result <- err
	return nil, err
}
