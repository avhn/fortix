package tun

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
)

// fakeQueueSize bounds each fake packet queue to sixteen MTU-sized packets.
const fakeQueueSize = 16

// Fake is an in-memory Device for packet-pump tests. Inject supplies incoming
// kernel packets and Receive observes packets written by the caller. Each queue
// is bounded, all packets are copied, and closing the fake unblocks all I/O.
type Fake struct {
	*packetDevice
	packets *fakePackets
}

// NewFake creates an unprivileged fake with the supplied immutable link identity
// and packet limit. Empty names, nonpositive indices, and invalid MTUs fail.
// No kernel interfaces or background workers are created.
func NewFake(name string, index, mtu int) (*Fake, error) {
	if name == "" || index <= 0 {
		return nil, errors.New("fake tunnel requires a name and positive index")
	}
	if err := validateMTU(mtu); err != nil {
		return nil, err
	}
	packets := &fakePackets{
		incoming: make(chan []byte, fakeQueueSize), outgoing: make(chan []byte, fakeQueueSize),
		done: make(chan struct{}),
	}
	device, err := newPacketDevice(context.Background(), packets, name, index, mtu, false)
	if err != nil {
		return nil, err
	}
	return &Fake{packetDevice: device, packets: packets}, nil
}

// Inject copies packet into the incoming queue. It returns packet validation,
// cancellation, or os.ErrClosed errors; a full queue blocks until space exists.
func (f *Fake) Inject(ctx context.Context, packet []byte) error {
	if err := validatePacket(packet, f.MTU()); err != nil {
		return err
	}
	return f.packets.send(ctx, f.packets.incoming, packet)
}

// Receive returns an owned copy of the next packet written through Device.Write.
// An empty queue blocks until a packet arrives, ctx ends, or the device closes.
func (f *Fake) Receive(ctx context.Context) ([]byte, error) {
	return f.packets.receive(ctx, f.packets.outgoing)
}

// fakePackets implements a packet transport with close-unblocking bounded queues.
// The queues remain open on close so concurrent sends cannot panic.
type fakePackets struct {
	incoming  chan []byte
	outgoing  chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

// Read consumes one injected packet without preserving an unread tail.
func (f *fakePackets) Read(p []byte) (int, error) {
	packet, err := f.receive(context.Background(), f.incoming)
	if err != nil {
		return 0, err
	}
	if len(p) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}

// Write copies p into the outbound queue and returns its packet length or error.
func (f *fakePackets) Write(p []byte) (int, error) {
	if err := f.send(context.Background(), f.outgoing, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// send copies one packet and waits for queue space, cancellation, or close.
// Calls beginning after cancellation or close never enqueue another packet.
func (f *fakePackets) send(ctx context.Context, queue chan<- []byte, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-f.done:
		return os.ErrClosed
	default:
	}
	owned := append([]byte(nil), packet...)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.done:
		return os.ErrClosed
	case queue <- owned:
		return nil
	}
}

// receive waits for a queued packet, cancellation, or close. Packets retained in
// queues after close are not delivered by calls beginning after close.
func (f *fakePackets) receive(ctx context.Context, queue <-chan []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-f.done:
		return nil, os.ErrClosed
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
		return nil, os.ErrClosed
	case packet := <-queue:
		return packet, nil
	}
}

// Close broadcasts closure once, unblocking queue readers and writers.
func (f *fakePackets) Close() error {
	f.closeOnce.Do(func() { close(f.done) })
	return nil
}
