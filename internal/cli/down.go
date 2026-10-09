package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avhn/fortix/internal/protocol"
)

// down subscribes before stopping and waits for verified exit and network cleanup.
// c selects explicit profiles or all profiles in the initial snapshot. One overall
// deadline bounds subscription, snapshot, stop requests, and completion, regardless
// of profile count. Rejected requests do not prevent stopping the remaining targets.
func (r *runner) down(c command) error {
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	if err := r.downCall(ctx, protocol.Request{Op: "subscribe"}, nil); err != nil {
		return err
	}
	var entries []statusEntry
	if err := r.downCall(ctx, protocol.Request{Op: "status"}, &entries); err != nil {
		return err
	}
	targets := make(map[string]uint64, len(entries))
	if !c.all {
		for _, id := range c.ids {
			targets[id] = 0
		}
	}
	for _, entry := range entries {
		if _, target := targets[entry.Profile]; c.all || target {
			targets[entry.Profile] = entry.Attempt
		}
	}
	// Subscription may have queued pre-stop progress. The initial status response
	// is our baseline; only subsequent stop observations should fail the wait.
	if err := r.discardBeforeStop(ctx); err != nil {
		return err
	}
	if c.all {
		if len(targets) == 0 {
			if _, err := fmt.Fprintln(r.errout, "no profiles"); err != nil {
				return err
			}
		}
		if err := r.downCall(ctx, protocol.Request{Op: "down", All: true}, nil); err != nil {
			return err
		}
		return r.conn.WaitStopped(ctx, targets)
	}
	var failures []error
	for _, id := range c.ids {
		if err := r.downCall(ctx, protocol.Request{Op: "down", Profile: id}, nil); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", id, err))
			delete(targets, id)
		}
	}
	if len(targets) != 0 {
		failures = append(failures, r.conn.WaitStopped(ctx, targets))
	}
	return errors.Join(failures...)
}

// downCall keeps the ordinary ten-second response limit within the overall stop
// deadline, rather than granting a fresh shutdown budget to each profile.
func (r *runner) downCall(ctx context.Context, request protocol.Request, dst any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return r.conn.Call(ctx, request, dst)
}

// discardBeforeStop drops only buffered pre-stop notifications. A lost helper or
// cancelled invocation remains an error, even when the event queue is empty.
func (r *runner) discardBeforeStop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-r.conn.Events():
			if !ok {
				return r.conn.Err()
			}
		default:
			return r.conn.Err()
		}
	}
}
