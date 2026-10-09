package client

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/protocol"
)

// TestWaitStopped verifies all targets, including an already idle profile, and
// requires a fresh snapshot rather than accepting a buffered disconnected event.
func TestWaitStopped(t *testing.T) {
	calls := make(chan int, 1)
	c, err := pipeClient(t, func(conn net.Conn) {
		reader := hello(t, conn)
		count := 0
		for {
			var req protocol.Request
			if err := reader.Read(&req); err != nil {
				calls <- count
				return
			}
			count++
			if req.Op != "status" {
				t.Errorf("unexpected operation %s", req.Op)
			}
			entries := []stopStatus{{Profile: "work", Attempt: 3, State: "stopping"}, {Profile: "other", Attempt: 7, State: "stopping"}, {Profile: "idle", State: "disconnected"}}
			if count >= 2 {
				entries[0].State = "disconnected"
			}
			if count >= 3 {
				entries[1].State = "disconnected"
			}
			if count == 1 {
				// These were queued before the first snapshot and cannot finish it.
				for _, event := range []protocol.Event{
					{Type: "state", Profile: "work", Attempt: 2, State: "disconnected"},
					{Type: "state", Profile: "work", Attempt: 3, State: "disconnected"},
					{Type: "state", Profile: "other", Attempt: 7, State: "connected", Wanted: true},
					{Type: "state", Profile: "unrelated", Attempt: 100, State: "starting", Wanted: true},
				} {
					if err := protocol.Write(conn, event); err != nil {
						return
					}
				}
			}
			if err := protocol.Write(conn, protocol.Result{Type: "result", ID: req.ID, OK: true, Data: entries}); err != nil {
				return
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := c.WaitStopped(ctx, map[string]uint64{"work": 3, "other": 7, "idle": 0}); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if count := <-calls; count < 3 {
		t.Fatalf("returned before all targets stopped: %d snapshots", count)
	}
}

// TestWaitStoppedFailures covers dirty cleanup, competing starts, incomplete
// snapshots, helper loss, and bounded cancellation without privileged operations.
func TestWaitStoppedFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entry   stopStatus
		event   protocol.Event
		omit    bool
		lost    bool
		want    string
		timeout bool
	}{
		{name: "cleanup exhausted", entry: stopStatus{State: "failed", CleanupPending: true}, want: "cleanup failed"},
		{name: "cleanup retry", entry: stopStatus{State: "stopping", Detail: "network cleanup failed"}, want: "cleanup failed"},
		{name: "dirty disconnected", entry: stopStatus{State: "disconnected", CleanupPending: true}, want: "cleanup failed"},
		{name: "failed clean", entry: stopStatus{State: "failed"}, want: "cleanup failed"},
		{name: "queued up", entry: stopStatus{State: "stopping", Wanted: true}, want: "competing start"},
		{name: "new attempt", entry: stopStatus{State: "disconnected", Attempt: 4}, want: "competing start"},
		{name: "missing target", omit: true, want: "omitted stop status"},
		{name: "helper loss", lost: true, want: "waiting for profiles to stop"},
		{name: "timeout", entry: stopStatus{State: "stopping"}, timeout: true},
		{name: "quick up down", entry: stopStatus{State: "disconnected"}, event: protocol.Event{Type: "state", Profile: "work", Attempt: 4, State: "starting", Wanted: true}, want: "competing start"},
		{name: "transient cleanup failure", entry: stopStatus{State: "disconnected"}, event: protocol.Event{Type: "state", Profile: "work", Attempt: 3, State: "stopping", Detail: "network cleanup failed"}, want: "cleanup failed"},
		{name: "queued up event", entry: stopStatus{State: "disconnected"}, event: protocol.Event{Type: "state", Profile: "work", Attempt: 3, State: "stopping", Wanted: true}, want: "competing start"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := pipeClient(t, func(conn net.Conn) {
				reader := hello(t, conn)
				first := true
				for {
					var req protocol.Request
					if err := reader.Read(&req); err != nil || tc.lost {
						return
					}
					entry := tc.entry
					entry.Profile = "work"
					if entry.Attempt == 0 {
						entry.Attempt = 3
					}
					entries := []stopStatus{entry}
					if tc.omit {
						entries = []stopStatus{}
					}
					if first && tc.event.Type != "" {
						if err := protocol.Write(conn, tc.event); err != nil {
							return
						}
					}
					first = false
					if err := protocol.Write(conn, protocol.Result{Type: "result", ID: req.ID, OK: true, Data: entries}); err != nil {
						return
					}
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			err = c.WaitStopped(ctx, map[string]uint64{"work": 3})
			if tc.timeout {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("timeout: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %s", err, tc.want)
			}
		})
	}
}

// TestWaitStoppedCancellation checks cancellation before any status request and
// during an unresponsive helper response, preserving the caller's context error.
func TestWaitStoppedCancellation(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before call", false: "waiting for reply"}[before], func(t *testing.T) {
			c, err := pipeClient(t, func(conn net.Conn) {
				hello(t, conn)
				_, _ = io.Copy(io.Discard, conn)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			if before {
				cancel()
			}
			err = c.WaitStopped(ctx, map[string]uint64{"work": 3})
			want := context.DeadlineExceeded
			if before {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatalf("cancellation: %v", err)
			}
		})
	}
}
