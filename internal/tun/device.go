// Package tun provides packet-oriented, nonpersistent IP tunnel devices.
// Interface addresses, link MTU, routes, and link activation remain caller-owned.
package tun

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// Device carries one IP packet per Read or Write, without platform framing.
// Concurrent reads and writes are safe, with each direction serialized. Read
// consumes an entire packet or returns an error, never a truncated success.
// Close is idempotent and unblocks pending I/O with os.ErrClosed. Context
// cancellation after Create closes the device. Link identity remains available
// after close, but must not be used to authorize mutations of a reused link.
type Device interface {
	// Read copies one packet into p, returning its length or a packet/I/O error.
	// A short buffer discards the packet and returns io.ErrShortBuffer.
	Read(p []byte) (int, error)
	// Write sends one nonempty IPv4 or IPv6 packet within the requested MTU.
	// It returns the packet length or a validation/I/O error without retrying.
	Write(p []byte) (int, error)
	// Name returns the kernel-assigned interface name.
	Name() string
	// Index returns the interface index captured at creation.
	Index() int
	// MTU returns the requested packet limit, not a live kernel MTU query.
	MTU() int
	// Close releases the device and returns the first close result on every call.
	Close() error
}

// ErrInvalidPacket identifies an empty packet, unsupported IP version, or an
// inconsistent or incomplete platform address-family prefix.
var ErrInvalidPacket = errors.New("invalid tunnel packet")

// ErrPacketTooLarge identifies a packet exceeding the requested MTU.
var ErrPacketTooLarge = errors.New("tunnel packet exceeds mtu")

// Create opens a kernel-selected utun or fortix interface with a packet limit
// of mtu bytes (1 through 65535). It returns validation, cancellation, or OS
// errors and requires privileges for kernel creation. It does not assign an
// address, configure the link MTU, bring the interface up, or install routes.
// The caller must configure the link only after registering its identity.
func Create(ctx context.Context, mtu int) (Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateMTU(mtu); err != nil {
		return nil, err
	}
	return createPlatform(ctx, mtu)
}

// validateMTU bounds packet storage to the maximum unframed IP packet size.
func validateMTU(mtu int) error {
	if mtu < 1 || mtu > 65535 {
		return errors.New("tunnel mtu must be between 1 and 65535")
	}
	return nil
}

// packetDevice owns a close-unblocking transport, immutable identity, and
// separate bounded buffers so one reader and writer can progress together.
type packetDevice struct {
	transport io.ReadWriteCloser
	name      string
	index     int
	mtu       int
	prefix    bool
	readMu    sync.Mutex
	writeMu   sync.Mutex
	readBuf   []byte
	writeBuf  []byte
	closed    atomic.Bool
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// newPacketDevice takes ownership of transport, whose Close must unblock I/O.
// It closes the transport on cancellation and allocates only MTU-bounded buffers.
func newPacketDevice(ctx context.Context, transport io.ReadWriteCloser, name string, index, mtu int, prefix bool) (*packetDevice, error) {
	if err := ctx.Err(); err != nil {
		_ = transport.Close()
		return nil, err
	}
	headerSize := 0
	if prefix {
		headerSize = familyPrefixSize
	}
	d := &packetDevice{
		transport: transport, name: name, index: index, mtu: mtu, prefix: prefix,
		// An extra byte detects oversized datagrams instead of accepting truncation.
		readBuf: make([]byte, mtu+headerSize+1), writeBuf: make([]byte, mtu+headerSize),
		done: make(chan struct{}),
	}
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = d.Close()
			case <-d.done:
			}
		}()
	}
	return d, nil
}

// Name returns the immutable kernel-assigned interface name.
func (d *packetDevice) Name() string { return d.name }

// Index returns the immutable interface index captured before configuration.
func (d *packetDevice) Index() int { return d.index }

// MTU returns the requested packet size budget, independent of kernel settings.
func (d *packetDevice) MTU() int { return d.mtu }

// Read strips platform framing and copies a single complete IP packet into p.
// Invalid, oversized, or short-buffer packets are consumed but not delivered.
func (d *packetDevice) Read(p []byte) (int, error) {
	return d.ReadContext(context.Background(), p)
}

// ReadContext reads one packet with cancellable I/O while retaining the device.
// Cancellation interrupts the pending read without removing the kernel interface,
// allowing route teardown to verify its identity before Close.
func (d *packetDevice) ReadContext(ctx context.Context, p []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	n, err := readContext(ctx, d.transport, d.readBuf)
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	if err != nil {
		return 0, err
	}
	packet := d.readBuf[:n]
	if d.prefix {
		packet, err = stripFamilyPrefix(packet)
		if err != nil {
			return 0, err
		}
	}
	if err := validatePacket(packet, d.mtu); err != nil {
		return 0, err
	}
	if len(p) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}

// Write validates one packet and prepends a Darwin family header when needed.
// A short transport write is an error and is never retried as another packet.
func (d *packetDevice) Write(p []byte) (int, error) {
	return d.WriteContext(context.Background(), p)
}

// WriteContext sends one packet under a finite caller budget without closing the
// device on cancellation. Partial writes remain errors and are never retried.
func (d *packetDevice) WriteContext(ctx context.Context, p []byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	if err := validatePacket(p, d.mtu); err != nil {
		return 0, err
	}
	frame := p
	if d.prefix {
		putFamilyPrefix(d.writeBuf, p)
		copy(d.writeBuf[familyPrefixSize:], p)
		frame = d.writeBuf[:len(p)+familyPrefixSize]
	}
	n, err := writeContext(ctx, d.transport, frame)
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	if err != nil {
		return 0, err
	}
	if n != len(frame) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// Close releases the transport once, waking blocked readers and writers without
// acquiring their locks. Every caller receives the same transport close result.
func (d *packetDevice) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.done)
		d.closeErr = d.transport.Close()
	})
	return d.closeErr
}
