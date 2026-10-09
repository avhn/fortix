//go:build darwin || linux

package helper

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/protocol"
)

// assemblyStalledConn wraps a real local TLS transport with a deadline-aware,
// unread pipe for one injected write. No kernel networking or worker is required.
// Read and ordinary writes still reach the fake gateway, including setup and logout.
type assemblyStalledConn struct {
	net.Conn
	network       *assemblyNetwork
	blocked, peer net.Conn
}

// newAssemblyStalledConn owns an unread pipe until Close and borrows the test's
// serialized one-shot stall flag to interrupt only the established data transport.
func newAssemblyStalledConn(conn net.Conn, n *assemblyNetwork) *assemblyStalledConn {
	blocked, peer := net.Pipe()
	return &assemblyStalledConn{Conn: conn, network: n, blocked: blocked, peer: peer}
}

// Write consumes the one-shot stall flag and blocks that TLS record until its
// actual write deadline or cancellation, otherwise preserving the real transport.
func (c *assemblyStalledConn) Write(data []byte) (int, error) {
	c.network.mu.Lock()
	stall := c.network.stall
	c.network.stall = false
	c.network.mu.Unlock()
	if stall {
		return c.blocked.Write(data)
	}
	return c.Conn.Write(data)
}

// SetWriteDeadline propagates deadlines to both paths, including cancellation
// callbacks that shorten a blocked TLS write's existing three-second budget.
func (c *assemblyStalledConn) SetWriteDeadline(deadline time.Time) error {
	if err := c.blocked.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(deadline)
}

// Close releases both pipe endpoints and the real connection, unblocking pending I/O.
func (c *assemblyStalledConn) Close() error {
	_ = c.blocked.Close()
	_ = c.peer.Close()
	return c.Conn.Close()
}

// TestNativeRenegotiationReconnect offers changed MRU and addressing after Connected
// while outbound traffic is idle. The link must stop before a new generation can
// deliver packets under the old TUN, route and DNS snapshot, then retry cleanly.
func TestNativeRenegotiationReconnect(t *testing.T) {
	trigger := make(chan struct{})
	n := &assemblyNetwork{renegotiate: trigger}
	implementation, _ := assemblyBackend(t, n, "")
	h := startHarness(t, nil, func(o *Options) { o.Network = n; o.Backends = map[string]backend.Backend{"native": implementation} })
	c := h.client(t)
	startNativeProfile(t, c, "renew", true)
	c.event(t, "state", "renew", "connected")
	n.mu.Lock()
	old := n.device
	n.mu.Unlock()
	close(trigger)
	verifyNativeFreshRetry(t, h, c, n, "renew", old)
}

// TestNativeStalledWriteReconnect stalls a real TLS record after activation and
// verifies deadline expiry follows transport retry, not the fatal setup-timeout path.
func TestNativeStalledWriteReconnect(t *testing.T) {
	n := &assemblyNetwork{}
	implementation, _ := assemblyBackend(t, n, "stall")
	h := startHarness(t, nil, func(o *Options) { o.Network = n; o.Backends = map[string]backend.Backend{"native": implementation} })
	c := h.client(t)
	startNativeProfile(t, c, "stalled", true)
	c.event(t, "state", "stalled", "connected")
	n.mu.Lock()
	old := n.device
	n.stall = true
	n.mu.Unlock()
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := old.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	verifyNativeFreshRetry(t, h, c, n, "stalled", old)
}

// verifyNativeFreshRetry requires cleanup and journal removal before backoff, a
// generation-bound fresh password, and independent device/network assembly on retry.
// The final down verifies the new attempt also releases its device and journal.
func verifyNativeFreshRetry(t *testing.T, h *harness, c *testClient, n *assemblyNetwork, id string, old *assemblyDevice) {
	t.Helper()
	c.event(t, "state", id, "backoff")
	select {
	case <-old.closed:
	default:
		t.Fatal("old device remained live in backoff")
	}
	if _, err := os.Stat(filepath.Join(h.paths.State, id+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old journal remains in backoff: %v", err)
	}
	n.mu.Lock()
	steps := append([]string(nil), n.steps...)
	n.mu.Unlock()
	// A poisoned TLS stream cannot promise a Terminate Ack, but logout still
	// precedes network removal and the old kernel link's release.
	if len(steps) < 3 || !reflect.DeepEqual(steps[len(steps)-3:], []string{"logout", "teardown", "close"}) {
		t.Fatalf("incorrect retry cleanup order: %v", steps)
	}
	challenge := c.event(t, "challenge", id, "")
	if challenge.Attempt != 2 {
		t.Fatalf("retry generation=%d", challenge.Attempt)
	}
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fresh-synthetic-password"})
	c.event(t, "state", id, "connected")
	n.mu.Lock()
	fresh := n.device
	n.mu.Unlock()
	if fresh == old {
		t.Fatal("retry reused old device")
	}
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := fresh.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	if got, err := fresh.Receive(ctx); err != nil || !reflect.DeepEqual(got, packet) {
		t.Fatalf("fresh attempt packet round trip: %x %v", got, err)
	}
	c.success(t, protocol.Request{Op: "down", Profile: id})
	c.event(t, "state", id, "disconnected")
	if _, err := os.Stat(filepath.Join(h.paths.State, id+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh attempt journal remains: %v", err)
	}
}
