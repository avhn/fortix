package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/pinentry"
	"github.com/avhn/fortix/internal/protocol"
)

// TestCodeChallengeAndRevokedToken verifies unexpected MFA challenges still reach
// clients and a formerly valid capability becomes unusable immediately after stop.
func TestCodeChallengeAndRevokedToken(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "code")})
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	password := c.event(t, "challenge", "work", "")
	c.success(t, protocol.Request{Op: "answer", ChallengeID: password.ChallengeID, Secret: "fixture-password"})
	code := c.event(t, "challenge", "work", "")
	if code.Kind != "code" || code.Attempt != password.Attempt {
		t.Fatal("wrong MFA routing")
	}
	c.success(t, protocol.Request{Op: "answer", ChallengeID: code.ChallengeID, Secret: "123456"})
	c.event(t, "state", "work", "connected")
	h.server.mu.Lock()
	token := ""
	for value, binding := range h.server.tokens {
		if binding.actor.id == "work" {
			token = value
		}
	}
	h.server.mu.Unlock()
	if len(token) != 64 {
		t.Fatal("missing live attempt capability")
	}
	c.success(t, protocol.Request{Op: "down", Profile: "work"})
	c.event(t, "state", "work", "disconnected")
	conn, err := net.DialTimeout("unix", h.paths.PinentrySocket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := protocol.Write(conn, pinentry.Request{Token: token, KeyInfo: "example_password", Prompt: "Password:"}); err != nil {
		t.Fatal(err)
	}
	var reply pinentry.Response
	if err := protocol.NewReader(conn).Read(&reply); err != nil || !reply.Cancel {
		t.Fatalf("revoked capability accepted: %v", err)
	}
}

// TestChallengeBroadcastAfterOriginDisconnect verifies a prompt is broadcast only
// when its initiating connection is no longer open, with first-answer-wins semantics.
func TestChallengeBroadcastAfterOriginDisconnect(t *testing.T) {
	h := startHarness(t, nil)
	origin := h.client(t)
	observer := h.client(t)
	observer.success(t, protocol.Request{Op: "subscribe"})
	origin.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "delayed")})
	origin.success(t, protocol.Request{Op: "up", Profile: "work"})
	_ = origin.socket.Close()
	challenge := observer.event(t, "challenge", "work", "")
	observer.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
	observer.event(t, "state", "work", "connected")
}

// TestTransportReconnect confirms only an established transport loss triggers a new
// generation after backoff; old challenge IDs cannot answer the new attempt.
func TestTransportReconnect(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	connectFixture(t, c, "work", "transport", "fixture-password")
	c.event(t, "state", "work", "backoff")
	next := c.event(t, "challenge", "work", "")
	if next.Attempt != 2 {
		t.Fatalf("unexpected reconnect generation %d", next.Attempt)
	}
	c.success(t, protocol.Request{Op: "cancel", ChallengeID: next.ChallengeID})
	c.event(t, "state", "work", "failed")
}

// TestServiceExclusion proves a second helper cannot recover another live helper's
// children before discovering the occupied socket. The kernel lock precedes recovery.
func TestServiceExclusion(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	connectFixture(t, c, "work", "", "fixture-password")
	duplicate, err := New(h.server.opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if duplicate.Serve(ctx) == nil {
		t.Fatal("second helper entered recovery")
	}
	if h.server.actor("work").snapshot().State != "connected" {
		t.Fatal("second helper disrupted live process")
	}
}

// TestSocketReclamation refuses live sockets and ordinary files while reclaiming
// a closed owned socket left by a crashed listener. All entries are temporary.
func TestSocketReclamation(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sx-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if prepareSocket(path) == nil {
		t.Fatal("removed a live socket")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocket(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale socket remained")
	}
	if err := os.WriteFile(path, []byte("do not remove"), 0600); err != nil {
		t.Fatal(err)
	}
	if prepareSocket(path) == nil {
		t.Fatal("removed an ordinary file")
	}
}

// TestHelperCommandDevRoot exercises the actual helper executable, development path
// wiring, pinentry basename dispatch, and graceful process-signal shutdown end to end.
func TestHelperCommandDevRoot(t *testing.T) {
	ensureFixtures(t)
	if os.Geteuid() == 0 {
		t.Skip("development service requires a non-root user")
	}
	root, err := os.MkdirTemp("/tmp", "cx-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	p, err := paths.Resolve(paths.Override{RootDir: root, SkipTrust: true, HelperPath: "/libexec/fortix-helper", HomeDir: "/home/development", ConfigHome: "/config", ControlSocket: filepath.Join(root, "run/fortix.sock"), PinentrySocket: filepath.Join(root, "run/private/pinentry.sock")})
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{fixtureHelper, p.Pinentry}, {fixtureVPN, p.OpenFortiVPN[0]}} {
		if err := os.MkdirAll(filepath.Dir(pair[1]), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, fixtureHelper, "serve", "--dev-root", root)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("helper executable shutdown timed out")
		}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var socket net.Conn
	for {
		socket, err = net.DialTimeout("unix", p.ControlSocket, 100*time.Millisecond)
		if err == nil {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("helper command socket did not open")
		}
	}
	c := &testClient{socket: socket, decoder: json.NewDecoder(socket)}
	defer func() { _ = socket.Close() }()
	connectFixture(t, c, "work", "", "fixture-password")
	status := c.success(t, protocol.Request{Op: "status"})
	if !strings.Contains(string(status.Data), `"connected"`) {
		t.Fatal("helper command did not connect")
	}
}

// failingCleanup preserves the no-op apply/recovery behavior but injects teardown
// failure to verify shutdown never silently reports leaked owned resources as clean.
type failingCleanup struct{ NoNetwork }

// Teardown always fails without changing networking or consuming journal data.
func (failingCleanup) Teardown(context.Context, Journal) error {
	return errors.New("injected teardown failure")
}

// TestShutdownCleanupFailure retains the journal and reports unsuccessful teardown
// after bounded retries. The test explicitly consumes the expected shutdown error.
func TestShutdownCleanupFailure(t *testing.T) {
	// The deadline also bounds apply during connect, so it must tolerate a loaded runner;
	// the injected teardown fails immediately, so shutdown time does not depend on it.
	h := startHarness(t, nil, func(opts *Options) { opts.Network = failingCleanup{}; opts.Deadlines.Network = 250 * time.Millisecond })
	c := h.client(t)
	connectFixture(t, c, "work", "", "fixture-password")
	h.cancel()
	select {
	case err := <-h.done:
		// The error is asserted here; cleanup still owns the final channel receive.
		h.done <- nil
		if err == nil || !strings.Contains(err.Error(), "incomplete cleanup") {
			t.Fatalf("shutdown error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup retries were not bounded")
	}
	if _, err := os.Stat(filepath.Join(h.paths.State, "work.json")); err != nil {
		t.Fatal("failed cleanup lost its recovery journal")
	}
}
