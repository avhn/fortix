package native

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/profile"
)

// TestFrameWriterControlPriority verifies bounded queue ordering before writer start,
// including an IPv4 frame waiting behind multiple independently queued controls.
func TestFrameWriterControlPriority(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f := &frameTransport{conn: conn, ctx: ctx, cancel: cancel, control: make(chan frameWrite, 8), data: make(chan frameWrite, 32), done: make(chan struct{})}
	packets := [][]byte{{0xc0, 0x21, 1}, {0x80, 0x21, 2}, {0, 0x21, 3}}
	for i, packet := range packets {
		request := frameWrite{ctx: ctx, packet: packet, result: make(chan error, 1)}
		if i == 2 {
			f.data <- request
		} else {
			f.control <- request
		}
	}
	go f.writeFrames()
	defer f.close()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	for _, want := range packets {
		got, err := ReadFrame(peer)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("writer order: %x want %x (%v)", got, want, err)
		}
	}
}

// TestFrameWriterCancellation verifies a stalled TLS writer cannot retain stop or
// a cancelled packet indefinitely, and never needs an extra worker for each packet.
func TestFrameWriterCancellation(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	f := newFrameTransport(context.Background(), conn)
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := f.WritePacket(ctx, []byte{0xc0, 0x21, 1}); err == nil {
		t.Fatal("stalled writer reported success")
	}
	select {
	case <-f.done:
	case <-time.After(time.Second):
		t.Fatal("writer retained cancelled I/O")
	}
}

// TestIPv4PacketGate verifies protocol version, header and total-length validation.
func TestIPv4PacketGate(t *testing.T) {
	valid := make([]byte, 20)
	valid[0] = 0x45
	binary.BigEndian.PutUint16(valid[2:4], 20)
	cases := []struct {
		name   string
		packet []byte
		mtu    int
		valid  bool
	}{
		{"valid", valid, 1354, true}, {"short", valid[:19], 1354, false}, {"MTU", valid, 19, false},
		{"IPv6", append([]byte{0x65}, valid[1:]...), 1354, false},
		{"header", append([]byte{0x44}, valid[1:]...), 1354, false},
		{"length", append(append([]byte(nil), valid...), 0), 1354, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := validIPv4Packet(test.packet, test.mtu); got != test.valid {
				t.Fatalf("packet gate=%v", got)
			}
		})
	}
}

// TestBackendCredentialCancellation verifies unsupported profiles never start, and a
// cancelled broker request terminates without dialing or allocating a kernel device.
func TestBackendCredentialCancellation(t *testing.T) {
	p := profile.Profile{SchemaVersion: 1, ID: "fixture", Name: "Fixture", Backend: "native", Username: "fixture", Gateway: profile.Gateway{Host: "gateway.test"}}
	p.ApplyDefaults()
	implementation := NewBackend(BackendOptions{})
	attempt := backend.Attempt{Profile: p.ID, Generation: 1, Config: backend.Config{Profile: p}, Hooks: backend.Hooks{RegisterLink: func(context.Context, backend.LinkIdentity) error { return errors.New("unexpected registration") }}}
	tunnel, err := implementation.Start(context.Background(), attempt)
	if err != nil {
		t.Fatal(err)
	}
	request := <-tunnel.Events()
	challenge, ok := request.(backend.CredentialRequested)
	if !ok {
		t.Fatalf("missing password request: %T", request)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tunnel.Answer(ctx, challenge.Request, []byte("synthetic")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled answer: %v", err)
	}
	if err := tunnel.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range tunnel.Events() {
	}
	if err := tunnel.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.(*Tunnel).Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	attempt.Config.Profile.MFA.Mode = "push"
	if _, err := implementation.Start(context.Background(), attempt); err == nil {
		t.Fatal("native MFA accepted")
	}
}
