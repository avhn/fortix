// Package tray tests click worker lifetimes without a native desktop.
package tray

import (
	"context"
	"testing"
	"time"
)

// TestClickRemoval verifies removal joins idle and blocked forwarding workers even
// when the toolkit keeps its click channel open. No GUI or privileged I/O is used.
func TestClickRemoval(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "blocked send"}[blocked], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			removed, clicked := make(chan struct{}), make(chan struct{})
			actions, done := make(chan string), make(chan struct{})
			go func() {
				defer close(done)
				forwardClicks(ctx, removed, clicked, actions, "profile:work")
			}()
			if blocked {
				select {
				case clicked <- struct{}{}:
				case <-time.After(time.Second):
					t.Fatal("worker did not receive click")
				}
			}
			close(removed)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("removed item left a forwarding worker")
			}
		})
	}
}
