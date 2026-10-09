package native

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/avhn/fortix/internal/ppp"
	"github.com/avhn/fortix/internal/tun"
)

// frameTransport adapts gateway frames to PPP with one TLS writer and bounded queues.
// Control frames take priority over queued data; an in-flight write has a deadline.
// PPP owns the sole reader/demultiplexer and the bounded inbound IPv4 queue.
type frameTransport struct {
	conn          net.Conn
	ctx           context.Context
	cancel        context.CancelFunc
	control, data chan frameWrite
	done          chan struct{}
}

// frameWrite owns one bounded PPP payload and a one-slot write acknowledgement.
type frameWrite struct {
	ctx    context.Context
	packet []byte
	result chan error
}

// newFrameTransport starts the sole writer; its caller must join it through close.
func newFrameTransport(ctx context.Context, conn net.Conn) *frameTransport {
	ctx, cancel := context.WithCancel(ctx)
	f := &frameTransport{conn: conn, ctx: ctx, cancel: cancel, control: make(chan frameWrite, 8), data: make(chan frameWrite, 32), done: make(chan struct{})}
	go f.writeFrames()
	return f
}

// close cancels and joins the sole writer without closing the gateway connection.
func (f *frameTransport) close() { f.cancel(); <-f.done }

// ReadPacket reads a bounded complete PPP frame, interrupting partial reads on cancel.
// PPP validates the protocol and negotiated MRU before delivering IPv4 payloads.
func (f *frameTransport) ReadPacket(ctx context.Context) ([]byte, error) {
	finish, err := frameDeadline(ctx, f.conn.SetReadDeadline)
	if err != nil {
		return nil, err
	}
	packet, err := ReadFrame(f.conn)
	finish()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return packet, err
}

// WritePacket queues one bounded payload and waits for actual TLS write completion.
// Control and data admission have separate limits and honor caller cancellation.
func (f *frameTransport) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) < 2 || len(packet) > ppp.DefaultMRU+2 {
		return ErrInvalidFrame
	}
	request := frameWrite{ctx: ctx, packet: append([]byte(nil), packet...), result: make(chan error, 1)}
	queue := f.control
	if binary.BigEndian.Uint16(packet) == ppp.ProtocolIPv4 {
		queue = f.data
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.ctx.Done():
		return f.ctx.Err()
	case queue <- request:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.ctx.Done():
		return f.ctx.Err()
	case err := <-request.result:
		return err
	}
}

// writeFrames gives queued control priority and caps every write to three seconds.
// Any incomplete frame poisons the stream and stops admission instead of retrying.
func (f *frameTransport) writeFrames() {
	defer close(f.done)
	var pending *frameWrite
	for {
		if f.ctx.Err() != nil {
			return
		}
		var request frameWrite
		select {
		case request = <-f.control:
		default:
			if pending != nil {
				request = *pending
				pending = nil
			} else {
				select {
				case <-f.ctx.Done():
					return
				case request = <-f.control:
				case request = <-f.data:
					// Retain one selected data frame locally rather than requeueing it.
					select {
					case control := <-f.control:
						data := request
						pending = &data
						request = control
					default:
					}
				}
			}
		}
		if err := request.ctx.Err(); err != nil {
			request.result <- err
			continue
		}
		ctx, cancel := context.WithTimeout(request.ctx, 3*time.Second)
		stop := context.AfterFunc(f.ctx, cancel)
		finish, err := frameDeadline(ctx, f.conn.SetWriteDeadline)
		if err == nil {
			err = WriteFrame(f.conn, request.packet)
			finish()
		}
		stop()
		cancel()
		request.result <- err
		if err != nil {
			f.cancel()
			_ = f.conn.SetReadDeadline(time.Now())
			return
		}
	}
}

// frameDeadline joins cancellation before clearing a directional I/O deadline.
// The caller serializes operations in that direction and always invokes the cleanup.
func frameDeadline(ctx context.Context, set func(time.Time) error) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := set(deadline); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = set(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
		_ = set(time.Time{})
	}, nil
}

// contextualDevice interrupts blocked packet I/O while keeping the kernel link alive.
// This capability is required for transport completion before route teardown.
type contextualDevice interface {
	ReadContext(context.Context, []byte) (int, error)
	WriteContext(context.Context, []byte) (int, error)
}

// packetPump owns exactly two data workers and no per-packet goroutines. PPP handles
// the sole TLS writer, keepalive and bounded inbound queue independently of this pump.
type packetPump struct {
	cancel  context.CancelFunc
	done    chan struct{}
	workers sync.WaitGroup
	errOnce sync.Once
	err     error
}

// startPump begins IPv4 forwarding only after the helper activates the link. Invalid
// or IPv6 packets are dropped; bounded writes cannot starve PPP control indefinitely.
// Device ownership stays with the tunnel, and cancellation never closes the device.
func startPump(ctx context.Context, device tun.Device, link *ppp.Link, mtu int) (*packetPump, error) {
	ioDevice, ok := device.(contextualDevice)
	if !ok {
		return nil, errors.New("native device lacks cancellable packet I/O")
	}
	ctx, cancel := context.WithCancel(ctx)
	pump := &packetPump{cancel: cancel, done: make(chan struct{})}
	pump.workers.Add(2)
	go func() {
		defer pump.workers.Done()
		buffer := make([]byte, mtu)
		for {
			n, err := ioDevice.ReadContext(ctx, buffer)
			if errors.Is(err, tun.ErrInvalidPacket) || errors.Is(err, tun.ErrPacketTooLarge) {
				continue
			}
			if err != nil {
				pump.fail(ctx, err)
				return
			}
			if !validIPv4Packet(buffer[:n], mtu) {
				continue
			}
			writeCtx, finish := context.WithTimeout(ctx, 3*time.Second)
			err = link.WriteIPv4(writeCtx, buffer[:n])
			finish()
			if err != nil {
				pump.fail(ctx, err)
				return
			}
		}
	}()
	go func() {
		defer pump.workers.Done()
		for {
			packet, err := link.ReadIPv4(ctx)
			if err != nil {
				pump.fail(ctx, err)
				return
			}
			if !validIPv4Packet(packet, mtu) {
				continue
			}
			writeCtx, finish := context.WithTimeout(ctx, 3*time.Second)
			n, err := ioDevice.WriteContext(writeCtx, packet)
			finish()
			if err == nil && n != len(packet) {
				err = io.ErrShortWrite
			}
			if err != nil {
				pump.fail(ctx, err)
				return
			}
		}
	}()
	go func() { pump.workers.Wait(); close(pump.done) }()
	return pump, nil
}

// fail records the first unexpected I/O failure and interrupts the sibling worker.
// Routine context cancellation leaves a graceful stop's terminal outcome unchanged.
func (p *packetPump) fail(ctx context.Context, err error) {
	p.errOnce.Do(func() {
		if ctx.Err() == nil {
			p.err = err
		}
		p.cancel()
	})
}

// stop cancels both data workers and joins them without closing the owned device.
func (p *packetPump) stop() { p.cancel(); <-p.done }

// validIPv4Packet rejects unsupported versions, invalid headers and inconsistent
// total lengths before any packet can reach either the gateway or kernel device.
func validIPv4Packet(packet []byte, mtu int) bool {
	if len(packet) < 20 || len(packet) > mtu || packet[0]>>4 != 4 {
		return false
	}
	header := int(packet[0]&15) * 4
	return header >= 20 && header <= len(packet) && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet)
}
