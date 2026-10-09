package tun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

// testDevice builds a queue-backed device to test platform framing and packet
// semantics without creating or configuring a kernel interface.
func testDevice(t *testing.T, ctx context.Context, mtu int, prefix bool) (*packetDevice, *fakePackets) {
	t.Helper()
	packets := &fakePackets{
		incoming: make(chan []byte, fakeQueueSize), outgoing: make(chan []byte, fakeQueueSize),
		done: make(chan struct{}),
	}
	device, err := newPacketDevice(ctx, packets, "test0", 7, mtu, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	return device, packets
}

// TestCreateRejectsInvalidInputs verifies errors occur before privileged creation.
func TestCreateRejectsInvalidInputs(t *testing.T) {
	for _, mtu := range []int{-1, 0, 65536} {
		if device, err := Create(context.Background(), mtu); err == nil || device != nil {
			t.Fatalf("Create mtu %d = %v, %v", mtu, device, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if device, err := Create(ctx, 1354); !errors.Is(err, context.Canceled) || device != nil {
		t.Fatalf("canceled Create = %v, %v", device, err)
	}
	for _, mtu := range []int{1, 1354, 65535} {
		if err := validateMTU(mtu); err != nil {
			t.Fatalf("valid mtu %d: %v", mtu, err)
		}
	}
}

// TestDevicePackets verifies packet boundaries, length accounting, and hidden
// family headers for both plain Linux packets and Darwin-style frames.
func TestDevicePackets(t *testing.T) {
	for _, prefix := range []bool{false, true} {
		device, transport := testDevice(t, context.Background(), 8, prefix)
		if device.Name() != "test0" || device.Index() != 7 || device.MTU() != 8 {
			t.Fatal("unexpected device identity")
		}
		for _, packet := range [][]byte{{0x45, 1, 2}, {0x60, 3, 4, 5, 6, 7, 8, 9}} {
			if n, err := device.Write(packet); err != nil || n != len(packet) {
				t.Fatalf("Write = %d, %v", n, err)
			}
			frame := <-transport.outgoing
			want := append([]byte(nil), packet...)
			if prefix {
				want = make([]byte, len(packet)+familyPrefixSize)
				putFamilyPrefix(want, packet)
				copy(want[familyPrefixSize:], packet)
			}
			if !bytes.Equal(frame, want) {
				t.Fatalf("wire packet = %x, want %x", frame, want)
			}
			transport.incoming <- frame
			buf := bytes.Repeat([]byte{0xff}, 12)
			n, err := device.Read(buf)
			if err != nil || n != len(packet) || !bytes.Equal(buf[:n], packet) {
				t.Fatalf("Read = %x, %d, %v", buf, n, err)
			}
			if !bytes.Equal(buf[n:], bytes.Repeat([]byte{0xff}, len(buf)-n)) {
				t.Fatal("Read overwrote bytes outside the packet")
			}
		}
	}
}

// TestDeviceRejectsPackets checks invalid framing, oversize detection, and
// short-buffer discards without letting one failed packet poison the next.
func TestDeviceRejectsPackets(t *testing.T) {
	for _, prefix := range []bool{false, true} {
		device, transport := testDevice(t, context.Background(), 4, prefix)
		for _, tc := range []struct {
			packet []byte
			want   error
		}{
			{nil, ErrInvalidPacket}, {[]byte{0x30}, ErrInvalidPacket},
			{[]byte{0x45, 1, 2, 3, 4}, ErrPacketTooLarge},
		} {
			if n, err := device.Write(tc.packet); n != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("Write rejected packet = %d, %v, want %v", n, err, tc.want)
			}
			frame := tc.packet
			if prefix && len(frame) > 0 && frame[0]>>4 == 4 {
				frame = append([]byte{0, 0, 0, utunIPv4}, frame...)
			}
			transport.incoming <- frame
			buf := []byte{0xff, 0xff, 0xff, 0xff}
			if n, err := device.Read(buf); n != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("Read rejected packet = %d, %v, want %v", n, err, tc.want)
			}
			if !bytes.Equal(buf, []byte{0xff, 0xff, 0xff, 0xff}) {
				t.Fatal("invalid packet changed caller buffer")
			}
		}
		frame := []byte{0x45, 1, 2, 3}
		if prefix {
			frame = append([]byte{0, 0, 0, utunIPv4}, frame...)
		}
		transport.incoming <- frame
		if n, err := device.Read(make([]byte, 3)); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("short-buffer Read = %d, %v", n, err)
		}
		transport.incoming <- frame
		if n, err := device.Read(make([]byte, 4)); n != 4 || err != nil {
			t.Fatalf("Read after discard = %d, %v", n, err)
		}
	}
}

// errorTransport injects short writes and underlying failures without blocking.
type errorTransport struct {
	readErr  error
	writeErr error
	closeErr error
	writes   int
	closes   int
}

// Read returns the configured underlying error without copying a packet.
func (e *errorTransport) Read([]byte) (int, error) { return 0, e.readErr }

// Write reports an incomplete datagram or the configured write failure.
func (e *errorTransport) Write(p []byte) (int, error) {
	e.writes++
	return len(p) - 1, e.writeErr
}

// Close records release attempts and returns the configured close failure.
func (e *errorTransport) Close() error {
	e.closes++
	return e.closeErr
}

// TestDeviceTransportErrors preserves underlying errors, rejects short writes
// without retrying, and returns the same close error to concurrent callers.
func TestDeviceTransportErrors(t *testing.T) {
	failure := errors.New("transport failed")
	for _, prefix := range []bool{false, true} {
		transport := &errorTransport{readErr: failure, closeErr: failure}
		device, err := newPacketDevice(context.Background(), transport, "test0", 7, 8, prefix)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := device.Read(make([]byte, 8)); n != 0 || !errors.Is(err, failure) {
			t.Fatalf("underlying Read = %d, %v", n, err)
		}
		if n, err := device.Write([]byte{0x45, 1}); n != 0 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short Write = %d, %v", n, err)
		}
		transport.writeErr = failure
		if n, err := device.Write([]byte{0x60, 1}); n != 0 || !errors.Is(err, failure) {
			t.Fatalf("underlying Write = %d, %v", n, err)
		}
		if transport.writes != 2 {
			t.Fatal("short write was retried")
		}
		var callers sync.WaitGroup
		for range 8 {
			callers.Go(func() {
				if err := device.Close(); !errors.Is(err, failure) {
					t.Errorf("Close = %v", err)
				}
			})
		}
		callers.Wait()
		if transport.closes != 1 {
			t.Fatalf("close count = %d", transport.closes)
		}
		if _, err := device.Read(nil); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("closed Read = %v", err)
		}
		if _, err := device.Write(nil); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("closed Write = %v", err)
		}
	}
}

// TestDeviceCancellation verifies cancellation releases transports both during
// construction and while a packet read is waiting.
func TestDeviceCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := &errorTransport{}
	if device, err := newPacketDevice(ctx, transport, "test0", 7, 8, false); device != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled construction = %v, %v", device, err)
	}
	if transport.closes != 1 {
		t.Fatal("canceled construction leaked transport")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	device, _ := testDevice(t, ctx, 8, false)
	result := make(chan error, 1)
	go func() {
		_, err := device.Read(make([]byte, 8))
		result <- err
	}()
	cancel()
	assertClosedResult(t, result)
}

// assertClosedResult bounds close-unblocking assertions to avoid hanging tests.
func assertClosedResult(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("pending I/O = %v, want closed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not unblock pending I/O")
	}
}
