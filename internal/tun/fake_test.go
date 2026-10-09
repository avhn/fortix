package tun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
)

// testFake creates a packet-pump fixture and closes it even when assertions fail.
func testFake(t *testing.T) *Fake {
	t.Helper()
	fake, err := NewFake("fortix7", 7, 1354)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fake.Close() })
	return fake
}

// TestFakeIdentityAndValidation checks link metadata and rejects invalid fixture
// sizes and identities before allocating packet storage.
func TestFakeIdentityAndValidation(t *testing.T) {
	var device Device = testFake(t)
	if device.Name() != "fortix7" || device.Index() != 7 || device.MTU() != 1354 {
		t.Fatal("fake identity mismatch")
	}
	for _, tc := range []struct {
		name  string
		index int
		mtu   int
	}{
		{"", 1, 1354}, {"fortix0", 0, 1354}, {"fortix0", -1, 1354},
		{"fortix0", 1, 0}, {"fortix0", 1, 65536},
	} {
		if fake, err := NewFake(tc.name, tc.index, tc.mtu); fake != nil || err == nil {
			t.Fatalf("invalid fake = %v, %v", fake, err)
		}
	}
}

// TestFakeCopiesPackets proves callers may reuse injected and written buffers
// and that short reads discard a packet instead of delivering a partial success.
func TestFakeCopiesPackets(t *testing.T) {
	fake := testFake(t)
	ctx := context.Background()
	packet := []byte{0x45, 1, 2, 3}
	want := append([]byte(nil), packet...)
	if err := fake.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	packet[1] = 99
	buf := make([]byte, fake.MTU())
	if n, err := fake.Read(buf); err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("injected Read = %x, %v", buf[:n], err)
	}
	if n, err := fake.Write(packet); n != len(packet) || err != nil {
		t.Fatalf("fake Write = %d, %v", n, err)
	}
	want = append(want[:0], packet...)
	packet[1] = 88
	written, err := fake.Receive(ctx)
	if err != nil || !bytes.Equal(written, want) {
		t.Fatalf("written packet = %x, %v", written, err)
	}
	if err := fake.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	if n, err := fake.Read(make([]byte, len(packet)-1)); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short fake Read = %d, %v", n, err)
	}
	packet = []byte{0x60, 4, 5}
	if err := fake.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	if n, err := fake.Read(buf); err != nil || !bytes.Equal(buf[:n], packet) {
		t.Fatalf("next fake Read = %x, %v", buf[:n], err)
	}
	for _, tc := range []struct {
		packet []byte
		want   error
	}{
		{nil, ErrInvalidPacket}, {[]byte{0x10}, ErrInvalidPacket},
		{bytes.Repeat([]byte{0x45}, fake.MTU()+1), ErrPacketTooLarge},
	} {
		if err := fake.Inject(ctx, tc.packet); !errors.Is(err, tc.want) {
			t.Fatalf("invalid Inject = %v, want %v", err, tc.want)
		}
	}
}

// TestFakeCancellation verifies canceled operations do not consume or enqueue
// packets even when a queue operation is otherwise immediately ready.
func TestFakeCancellation(t *testing.T) {
	fake := testFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fake.Inject(ctx, []byte{0x45}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Inject = %v", err)
	}
	if _, err := fake.Write([]byte{0x45}); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Receive = %v", err)
	}
	if _, err := fake.Receive(context.Background()); err != nil {
		t.Fatalf("canceled Receive consumed packet: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := fake.Receive(ctx)
		result <- err
	}()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("pending canceled Receive = %v", err)
	}
	for range fakeQueueSize {
		if err := fake.Inject(context.Background(), []byte{0x45}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { result <- fake.Inject(ctx, []byte{0x45}) }()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("full queue canceled Inject = %v", err)
	}
}

// TestFakeCloseUnblocks exercises queued and empty reads and writes, including
// callers waiting for the same direction's serialization lock.
func TestFakeCloseUnblocks(t *testing.T) {
	for _, operation := range []string{"read", "write", "inject", "receive"} {
		t.Run(operation, func(t *testing.T) {
			fake := testFake(t)
			ctx := context.Background()
			for range fakeQueueSize {
				if operation == "write" {
					if _, err := fake.Write([]byte{0x45}); err != nil {
						t.Fatal(err)
					}
				}
				if operation == "inject" {
					if err := fake.Inject(ctx, []byte{0x45}); err != nil {
						t.Fatal(err)
					}
				}
			}
			results := make(chan error, 8)
			started := make(chan struct{}, 8)
			for range 8 {
				go func() {
					started <- struct{}{}
					var err error
					switch operation {
					case "read":
						_, err = fake.Read(make([]byte, fake.MTU()))
					case "write":
						_, err = fake.Write([]byte{0x45})
					case "inject":
						err = fake.Inject(ctx, []byte{0x45})
					case "receive":
						_, err = fake.Receive(ctx)
					}
					results <- err
				}()
			}
			for range 8 {
				<-started
			}
			select {
			case err := <-results:
				t.Fatalf("I/O returned before close: %v", err)
			default:
			}
			if err := fake.Close(); err != nil {
				t.Fatal(err)
			}
			for range 8 {
				assertClosedResult(t, results)
			}
			if err := fake.Close(); err != nil {
				t.Fatalf("repeated Close = %v", err)
			}
			if err := fake.Inject(ctx, []byte{0x45}); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed Inject = %v", err)
			}
			if _, err := fake.Receive(ctx); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed Receive = %v", err)
			}
		})
	}
}

// TestFakeConcurrentPackets exercises independent packet directions under the
// race detector while using bounded queues and a fixed packet count.
func TestFakeConcurrentPackets(t *testing.T) {
	fake := testFake(t)
	var workers sync.WaitGroup
	workers.Go(func() {
		for i := range 100 {
			if err := fake.Inject(context.Background(), []byte{0x45, byte(i)}); err != nil {
				t.Error(err)
				return
			}
		}
	})
	workers.Go(func() {
		for i := range 100 {
			if _, err := fake.Write([]byte{0x60, byte(i)}); err != nil {
				t.Error(err)
				return
			}
		}
	})
	workers.Go(func() {
		buf := make([]byte, fake.MTU())
		for i := range 100 {
			n, err := fake.Read(buf)
			if err != nil || !bytes.Equal(buf[:n], []byte{0x45, byte(i)}) {
				t.Errorf("concurrent Read = %x, %v", buf[:n], err)
				return
			}
		}
	})
	workers.Go(func() {
		for i := range 100 {
			packet, err := fake.Receive(context.Background())
			if err != nil || !bytes.Equal(packet, []byte{0x60, byte(i)}) {
				t.Errorf("concurrent Receive = %x, %v", packet, err)
				return
			}
		}
	})
	workers.Wait()
}
