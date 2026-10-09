//go:build darwin || linux

package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// observedTransport announces when the device enters its underlying file Read.
// It preserves the real runtime-poller and close behavior for unprivileged tests.
type observedTransport struct {
	io.ReadWriteCloser
	started chan struct{}
	once    sync.Once
}

// Read signals entry once, then delegates to the nonblocking datagram file.
func (o *observedTransport) Read(p []byte) (int, error) {
	o.once.Do(func() { close(o.started) })
	return o.ReadWriteCloser.Read(p)
}

// socketFiles creates local nonblocking datagram descriptors, never a TUN link.
// Datagram sockets model kernel packet boundaries and Go's close-unblocking poller.
func socketFiles(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
		if err := unix.SetNonblock(fd, true); err != nil {
			for _, opened := range fds {
				_ = unix.Close(opened)
			}
			t.Fatal(err)
		}
	}
	left := os.NewFile(uintptr(fds[0]), "test-left")
	right := os.NewFile(uintptr(fds[1]), "test-right")
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	return left, right
}

// TestKernelDeviceHandoff exercises index lookup, nonblocking registration, and
// descriptor ownership with a local socket and existing link, never a TUN link.
func TestKernelDeviceHandoff(t *testing.T) {
	links, err := net.Interfaces()
	if err != nil || len(links) == 0 {
		t.Fatalf("read existing interface identities: %v", err)
	}
	file, _ := socketFiles(t)
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	device, err := newKernelDevice(context.Background(), fd, links[0].Name, 1354, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	if device.Index() != links[0].Index || device.Name() != links[0].Name || device.MTU() != 1354 {
		t.Fatal("handoff changed interface identity")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("handoff did not set nonblocking: flags %x, error %v", flags, err)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("handoff leaked descriptor: %v", err)
	}
	if device, err := newKernelDevice(context.Background(), -1, links[0].Name, 1354, false); err == nil || device != nil {
		t.Fatalf("invalid descriptor handoff = %v, %v", device, err)
	}
	for _, canceled := range []bool{false, true} {
		fd, err := unix.Dup(int(file.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		unix.CloseOnExec(fd)
		ctx, cancel := context.WithCancel(context.Background())
		name := "fortix-test-missing"
		if canceled {
			cancel()
			name = links[0].Name
		}
		device, err := newKernelDevice(ctx, fd, name, 1354, false)
		cancel()
		if err == nil || device != nil {
			t.Fatalf("invalid handoff = %v, %v", device, err)
		}
		if canceled && !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled handoff = %v", err)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("failed handoff leaked descriptor: %v", err)
		}
	}
}

// TestFileCloseUnblocks verifies the production transport assumption using a
// real nonblocking file, not just a fake that was designed to unblock on close.
func TestFileCloseUnblocks(t *testing.T) {
	file, _ := socketFiles(t)
	transport := &observedTransport{ReadWriteCloser: file, started: make(chan struct{})}
	device, err := newPacketDevice(context.Background(), transport, "test0", 7, 8, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	result := make(chan error, 1)
	go func() {
		_, err := device.Read(make([]byte, 8))
		result <- err
	}()
	<-transport.started
	select {
	case err := <-result:
		t.Fatalf("file Read did not wait for a packet: %v", err)
	default:
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	assertClosedResult(t, result)
}

// TestFileOversizedDatagram checks that the extra read byte detects truncation
// of real oversized datagrams, including those much larger than the read buffer.
func TestFileOversizedDatagram(t *testing.T) {
	for _, prefix := range []bool{false, true} {
		file, peer := socketFiles(t)
		device, err := newPacketDevice(context.Background(), file, "test0", 7, 4, prefix)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = device.Close() })
		packet := make([]byte, 100)
		packet[0] = 0x45
		if prefix {
			packet = append([]byte{0, 0, 0, utunIPv4}, packet...)
		}
		if _, err := peer.Write(packet); err != nil {
			t.Fatal(err)
		}
		if n, err := device.Read(make([]byte, 4)); n != 0 || !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("oversized datagram Read = %d, %v", n, err)
		}
		packet = []byte{0x45, 1, 2, 3}
		if prefix {
			packet = append([]byte{0, 0, 0, utunIPv4}, packet...)
		}
		if _, err := peer.Write(packet); err != nil {
			t.Fatal(err)
		}
		if n, err := device.Read(make([]byte, 4)); n != 4 || err != nil {
			t.Fatalf("next datagram Read = %d, %v", n, err)
		}
	}
}
