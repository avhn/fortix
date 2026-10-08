package client

import (
	"net"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/protocol"
)

// TestCodedFailurePreservesConnection decodes a helper failure carrying its stable
// code and verifies the same transport still correlates later status responses.
func TestCodedFailurePreservesConnection(t *testing.T) {
	c, err := pipeClient(t, func(conn net.Conn) {
		reader := hello(t, conn)
		var r protocol.Request
		if err := reader.Read(&r); err != nil {
			t.Error(err)
			return
		}
		e := protocol.Event{Type: "state", Profile: "work", Attempt: 2, State: "failed", Code: protocol.Conflict, Detail: "route overlaps another profile", Wanted: true}
		if err := protocol.Write(conn, e); err != nil {
			t.Error(err)
			return
		}
		if err := protocol.Write(conn, protocol.Result{Type: "result", ID: r.ID, OK: true}); err != nil {
			t.Error(err)
			return
		}
		if err := reader.Read(&r); err != nil {
			t.Error(err)
			return
		}
		if err := protocol.Write(conn, protocol.Result{Type: "result", ID: r.ID, OK: true, Data: "still connected"}); err != nil {
			t.Error(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Call(t.Context(), protocol.Request{Op: "subscribe"}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-c.Events():
		if e.Code != protocol.Conflict || !e.Wanted || e.Detail == "" {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("missing coded failure")
	}
	var result string
	if err := c.Call(t.Context(), protocol.Request{Op: "status"}, &result); err != nil || result != "still connected" {
		t.Fatalf("connection lost: %s %v", result, err)
	}
}

// TestLogsRequireExplicitSubscription keeps ordinary clients state-only and sends
// the opt-in flag only when a consumer requests live diagnostic events.
func TestLogsRequireExplicitSubscription(t *testing.T) {
	for _, logs := range []bool{false, true} {
		c, err := pipeClient(t, func(conn net.Conn) {
			reader := hello(t, conn)
			var r protocol.Request
			if err := reader.Read(&r); err != nil {
				t.Error(err)
				return
			}
			if r.Op != "subscribe" || r.Logs != logs {
				t.Errorf("unexpected subscription: %+v", r)
			}
			if err := protocol.Write(conn, protocol.Result{Type: "result", ID: r.ID, OK: true}); err != nil {
				t.Error(err)
			}
			// Hold the server side open until the client closes, so the result is
			// never raced by an early pipe close.
			_ = reader.Read(&r)
		})
		if err != nil {
			t.Fatal(err)
		}
		c.subscribeLogs = logs
		if err := c.Call(t.Context(), protocol.Request{Op: "subscribe"}, nil); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
}
