package tun

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestContextReadRetainsDevice verifies cancelled pump I/O leaves link identity and
// subsequent packet traffic usable until the helper explicitly closes the device.
func TestContextReadRetainsDevice(t *testing.T) {
	fake, err := NewFake("utun42", 42, 1354)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fake.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	buffer := make([]byte, 1354)
	if _, err := fake.ReadContext(ctx, buffer); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read cancellation: %v", err)
	}
	packet := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if err := fake.Inject(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if n, err := fake.ReadContext(ctx2, buffer); err != nil || n != len(packet) {
		t.Fatalf("retained device: n=%d error=%v", n, err)
	}
}

// TestContextWriteRetainsDevice verifies a saturated fake queue can be interrupted
// without closing its device or retaining a blocked packet worker after stop.
func TestContextWriteRetainsDevice(t *testing.T) {
	fake, err := NewFake("utun42", 42, 1354)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fake.Close() }()
	packet := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < fakeQueueSize; i++ {
		if _, err := fake.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := fake.WriteContext(ctx, packet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write cancellation: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if _, err := fake.Receive(ctx2); err != nil {
		t.Fatalf("retained device: %v", err)
	}
}

// TestPollerContextIO verifies the kernel-style directional deadline path cancels
// stalled reads and writes without closing the underlying transport or stale resets.
func TestPollerContextIO(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	buffer := make([]byte, 20)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err := readContext(ctx, conn, buffer); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("poller read: %v", err)
	}
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err := writeContext(ctx, conn, buffer); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("poller write: %v", err)
	}
	cancel()
	completed := make(chan error, 1)
	go func() {
		ctx, finish := context.WithTimeout(context.Background(), time.Second)
		defer finish()
		_, err := writeContext(ctx, conn, []byte("retained"))
		completed <- err
	}()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := peer.Read(buffer); err != nil || string(buffer[:n]) != "retained" {
		t.Fatalf("transport retained: %d %v", n, err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
}

// TestContextUnsupportedTransport verifies cancellable callers cannot silently enter
// uncancellable legacy I/O, while background readers/writers preserve prior behavior.
func TestContextUnsupportedTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := readContext(ctx, bytes.NewReader([]byte("input")), make([]byte, 8)); err == nil {
		t.Fatal("uncancellable read accepted")
	}
	var output bytes.Buffer
	if _, err := writeContext(ctx, &output, []byte("packet")); err == nil {
		t.Fatal("uncancellable write accepted")
	}
	if n, err := readContext(context.Background(), bytes.NewReader([]byte("input")), make([]byte, 8)); err != nil || n != 5 {
		t.Fatalf("background read: %d %v", n, err)
	}
	if n, err := writeContext(context.Background(), &output, []byte("packet")); err != nil || n != 6 {
		t.Fatalf("background write: %d %v", n, err)
	}
	cancel()
	if _, err := readContext(ctx, bytes.NewReader(nil), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read: %v", err)
	}
	if _, err := writeContext(ctx, &output, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write: %v", err)
	}
}
