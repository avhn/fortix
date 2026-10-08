// Package client tests correlation, cancellation, authorization, and bounded framing without privileges.
package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/protocol"
)

// pipeClient opens a fake helper transport and serves a caller-controlled protocol script.
// Cleanup closes both ends and joins the server so no reader survives the test.
func pipeClient(t *testing.T, serve func(net.Conn)) (*Client, error) {
	t.Helper()
	local, remote := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); defer func() { _ = remote.Close() }(); serve(remote) }()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close(); <-done })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return Dial(ctx, Options{Socket: "/tmp/fortix-test.sock", Dial: func(context.Context, string, string) (net.Conn, error) { return local, nil }})
}

// hello serves the mandatory handshake and returns a buffered reader retaining subsequent records.
func hello(t *testing.T, conn net.Conn) *protocol.Reader {
	t.Helper()
	reader := protocol.NewReader(conn)
	var req protocol.Request
	if err := reader.Read(&req); err != nil {
		t.Error(err)
		return reader
	}
	if req.Op != "hello" || req.Version == "" {
		t.Errorf("invalid hello: %s", req.Op)
	}
	if err := protocol.Write(conn, protocol.Result{Type: "result", ID: req.ID, OK: true, Data: map[string]any{"helper_version": "test", "protocol": 1}}); err != nil {
		t.Error(err)
	}
	return reader
}

// TestCorrelation verifies out-of-order results and events are independently delivered to callers.
func TestCorrelation(t *testing.T) {
	c, err := pipeClient(t, func(conn net.Conn) {
		reader := hello(t, conn)
		var first, second protocol.Request
		if err := reader.Read(&first); err != nil {
			t.Error(err)
			return
		}
		if err := reader.Read(&second); err != nil {
			t.Error(err)
			return
		}
		messages := []any{
			protocol.Event{Type: "state", Profile: "work", Attempt: 3, State: "connected"},
			protocol.Result{Type: "result", ID: second.ID, OK: true, Data: second.Op},
			protocol.Result{Type: "result", ID: first.ID, OK: true, Data: first.Op},
		}
		for _, message := range messages {
			if err := protocol.Write(conn, message); err != nil {
				t.Error(err)
				return
			}
		}
		_, _ = io.Copy(io.Discard, conn)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var wg sync.WaitGroup
	for _, op := range []string{"status", "profile.list"} {
		wg.Go(func() {
			var data string
			if err := c.Call(t.Context(), protocol.Request{Op: op}, &data); err != nil || data != op {
				t.Errorf("correlation: %q, %v", data, err)
			}
		})
	}
	wg.Wait()
	select {
	case e := <-c.Events():
		if e.Profile != "work" || e.State != "connected" {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("missing event")
	}
}

// TestCancellationAndClose ensures cancelled waits discard late replies and clean close wakes pending calls.
func TestCancellationAndClose(t *testing.T) {
	c, err := pipeClient(t, func(conn net.Conn) {
		reader := hello(t, conn)
		var req protocol.Request
		for {
			if err := reader.Read(&req); err != nil {
				return
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := c.Call(ctx, protocol.Request{Op: "status"}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Call(t.Context(), protocol.Request{Op: "status"}, nil) }()
	_ = c.Close()
	_ = c.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, ok := <-c.Events(); ok {
		t.Fatal("events not closed")
	}
}

// TestDialFailures checks OS permission failures, unavailable helpers, and handshake rejection diagnostics.
func TestDialFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"permission", os.ErrPermission, "group fortix"}, {"unreachable", os.ErrNotExist, "install and start fortix-helper"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Dial(t.Context(), Options{Socket: "/tmp/fortix-test.sock", Dial: func(context.Context, string, string) (net.Conn, error) { return nil, tc.err }})
			if tc.name == "permission" && !errors.Is(err, os.ErrPermission) {
				t.Fatal("permission identity lost")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct {
		name     string
		response any
		want     string
	}{
		{"authorization before request", protocol.Result{Type: "result", Error: &protocol.Error{Code: protocol.Unauthorized, Message: "denied"}}, "group fortix"},
		{"version mismatch", protocol.Result{Type: "result", ID: "1", OK: true, Data: map[string]any{"protocol": 2}}, "incompatible"},
		{"malformed result", protocol.Result{Type: "result", ID: "1", OK: false}, "invalid result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pipeClient(t, func(conn net.Conn) {
				if tc.name != "authorization before request" {
					var req protocol.Request
					if err := protocol.NewReader(conn).Read(&req); err != nil {
						t.Error(err)
						return
					}
				}
				_ = protocol.Write(conn, tc.response)
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
}

// TestSocketOverride verifies the single environment entry point and explicit option precedence.
func TestSocketOverride(t *testing.T) {
	t.Setenv("FORTIX_SOCKET", "/tmp/environment.sock")
	path, err := socketPath(Options{})
	if err != nil || path != "/tmp/environment.sock" {
		t.Fatalf("%q %v", path, err)
	}
	path, err = socketPath(Options{Socket: "/tmp/explicit.sock"})
	if err != nil || path != "/tmp/explicit.sock" {
		t.Fatalf("%q %v", path, err)
	}
	t.Setenv("FORTIX_SOCKET", "relative.sock")
	if _, err := socketPath(Options{}); err == nil {
		t.Fatal("accepted relative socket")
	}
}

// FuzzFrame exercises strict incoming envelope decoding with arbitrary bounded or malformed bytes.
// Errors are acceptable; successful decoding must never panic on subsequent field inspection.
func FuzzFrame(f *testing.F) {
	f.Add([]byte(`{"type":"result","id":"1","ok":true,"data":[]}`))
	f.Add([]byte(`{"type":"challenge","profile":"work","attempt":1,"challenge_id":"c","kind":"password","prompt":"Password"}`))
	f.Fuzz(func(t *testing.T, data []byte) { var message frame; _ = protocol.Decode(data, &message) })
}

// TestLateResult verifies a cancelled request's late result cannot satisfy a later request.
func TestLateResult(t *testing.T) {
	release := make(chan struct{})
	c, err := pipeClient(t, func(conn net.Conn) {
		reader := hello(t, conn)
		var first, second protocol.Request
		if err := reader.Read(&first); err != nil {
			return
		}
		<-release
		if err := protocol.Write(conn, protocol.Result{Type: "result", ID: first.ID, OK: true, Data: "late"}); err != nil {
			return
		}
		if err := reader.Read(&second); err != nil {
			return
		}
		_ = protocol.Write(conn, protocol.Result{Type: "result", ID: second.ID, OK: true, Data: "current"})
		_, _ = io.Copy(io.Discard, conn)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := c.Call(ctx, protocol.Request{Op: "status"}, nil); !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatal(err)
	}
	close(release)
	var got string
	if err := c.Call(t.Context(), protocol.Request{Op: "status"}, &got); err != nil || got != "current" {
		t.Fatalf("%q %v", got, err)
	}
}

// TestWriteCancellation checks a helper that stops reading cannot trap a caller writing a credential.
func TestWriteCancellation(t *testing.T) {
	release := make(chan struct{})
	c, err := pipeClient(t, func(conn net.Conn) { hello(t, conn); <-release })
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	err = c.Call(ctx, protocol.Request{Op: "answer", ChallengeID: "c", Secret: "test-password"}, nil)
	close(release)
	_ = c.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

// TestEventOverflow closes a stalled consumer rather than dropping a credential challenge silently.
func TestEventOverflow(t *testing.T) {
	c, err := pipeClient(t, func(conn net.Conn) {
		hello(t, conn)
		for i := 0; i < 257; i++ {
			if err := protocol.Write(conn, protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "starting"}); err != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, conn)
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("overflow did not close connection")
	}
	if !strings.Contains(c.Err().Error(), "overflow") {
		t.Fatal(c.Err())
	}
	_ = c.Close()
}

// TestInvalidResponseData checks decoding failures remain sanitized and invalid requests never reach the helper.
func TestInvalidResponseData(t *testing.T) {
	c, err := pipeClient(t, func(conn net.Conn) {
		reader := hello(t, conn)
		var req protocol.Request
		if err := reader.Read(&req); err != nil {
			return
		}
		if req.Op != "status" {
			t.Error("invalid request reached helper")
		}
		_ = protocol.Write(conn, protocol.Result{Type: "result", ID: req.ID, OK: true, Data: "private-payload"})
		_, _ = io.Copy(io.Discard, conn)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Call(t.Context(), protocol.Request{Op: "invalid"}, nil); err == nil {
		t.Fatal("invalid request accepted")
	}
	var result []string
	if err := c.Call(t.Context(), protocol.Request{Op: "status"}, &result); err == nil || strings.Contains(err.Error(), "private-payload") {
		t.Fatal("invalid response diagnostic")
	}
}

// TestLogSelection verifies diagnostic opt-out drops only logs and preserves state delivery.
// Default clients still receive logs; both modes keep the transport open for later requests.
func TestLogSelection(t *testing.T) {
	for _, discard := range []bool{false, true} {
		t.Run(map[bool]string{false: "deliver logs", true: "discard logs"}[discard], func(t *testing.T) {
			local, remote := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = remote.Close() }()
				reader := hello(t, remote)
				for _, event := range []protocol.Event{{Type: "log", Profile: "work", Line: "diagnostic"}, {Type: "state", Profile: "work", State: "connected"}} {
					if err := protocol.Write(remote, event); err != nil {
						return
					}
				}
				var req protocol.Request
				if err := reader.Read(&req); err != nil {
					return
				}
				_ = protocol.Write(remote, protocol.Result{Type: "result", ID: req.ID, OK: true})
				_, _ = io.Copy(io.Discard, remote)
			}()
			t.Cleanup(func() { _ = local.Close(); _ = remote.Close(); <-done })
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			c, err := Dial(ctx, Options{Socket: "/tmp/example.sock", DiscardLogs: discard, Dial: func(context.Context, string, string) (net.Conn, error) { return local, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			want := []string{"state"}
			if !discard {
				want = []string{"log", "state"}
			}
			for _, kind := range want {
				select {
				case event := <-c.Events():
					if event.Type != kind {
						t.Fatalf("event %s, want %s", event.Type, kind)
					}
				case <-ctx.Done():
					t.Fatal("event delivery timed out")
				}
			}
			if err := c.Call(ctx, protocol.Request{Op: "status"}, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}
