package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/protocol"
)

// pipeClient supplies a verified in-memory transport for portable protocol and wait regressions.
// Production Dial still always verifies SCM identity; only this private test seam substitutes it.
func pipeClient(t *testing.T, serve func(net.Conn)) (*Client, error) {
	t.Helper()
	t.Setenv("FORTIX_SOCKET", "")
	local, remote := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); defer remote.Close(); serve(remote) }()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close(); <-done })
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	return dialVerified(ctx, Options{Dial: func(context.Context, string, string) (net.Conn, error) { return local, nil }}, func(context.Context, net.Conn) error { return nil })
}

// hello consumes the secret-free handshake and returns the buffered reader for subsequent requests.
func hello(t *testing.T, conn net.Conn) *protocol.Reader {
	t.Helper()
	reader := protocol.NewReader(conn)
	var request protocol.Request
	if err := reader.Read(&request); err != nil {
		t.Error(err)
		return reader
	}
	if request.Op != "hello" || request.Version == "" {
		t.Error("invalid hello")
	}
	if err := protocol.Write(conn, protocol.Result{Type: "result", ID: request.ID, OK: true, Data: map[string]any{"protocol": protocol.Version}}); err != nil {
		t.Error(err)
	}
	return reader
}
