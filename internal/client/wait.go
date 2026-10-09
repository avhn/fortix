package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avhn/fortix/internal/protocol"
)

// stopWaitTimeout bounds shutdown verification even when the caller has no deadline.
// stopPollInterval refreshes snapshots when a helper emits no transition for an idle profile.
const (
	stopWaitTimeout  = 30 * time.Second
	stopPollInterval = 100 * time.Millisecond
)

// stopStatus decodes only the public fields needed to verify exit and network cleanup.
// Disconnected is the helper's acknowledgement that both have completed.
type stopStatus struct {
	Profile        string `json:"profile"`
	State          string `json:"state"`
	Detail         string `json:"detail"`
	Attempt        uint64 `json:"attempt"`
	Wanted         bool   `json:"wanted"`
	CleanupPending bool   `json:"cleanup_pending"`
}

// WaitStopped waits until every target is disconnected, unwanted, and clean.
// targets maps profile IDs to attempts captured before stopping. The caller must
// subscribe before issuing down and exclusively consume this connection's Events
// during the wait. Events wake authoritative status checks; an event alone cannot
// prove completion. Queued starts, changed attempts, cleanup failures, missing
// profiles, helper loss, and cancellation return errors. The wait is capped at
// thirty seconds, or the earlier ctx deadline, without modifying targets.
func (c *Client) WaitStopped(ctx context.Context, targets map[string]uint64) error {
	ctx, cancel := context.WithTimeout(ctx, stopWaitTimeout)
	defer cancel()
	ticker := time.NewTicker(stopPollInterval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("waiting for profiles to stop: %w", err)
		}
		clean, err := c.stoppedSnapshot(ctx, targets)
		if err != nil {
			return err
		}
		// Consume buffered transitions before accepting a snapshot, so a quick
		// competing up/down or a transient cleanup failure cannot look successful.
		changed, err := c.drainStopEvents(ctx, targets)
		if err != nil {
			return err
		}
		if clean && !changed {
			return c.Err()
		}
		if changed {
			continue
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for profiles to stop: %w", ctx.Err())
		case event, ok := <-c.Events():
			if !ok {
				return c.stopConnectionError()
			}
			if err := checkStopEvent(event, targets); err != nil {
				return err
			}
		case <-ticker.C:
		}
	}
}

// stoppedSnapshot verifies every requested generation using a bounded status call.
// Missing targets fail conservatively instead of treating an incomplete list as clean.
func (c *Client) stoppedSnapshot(ctx context.Context, targets map[string]uint64) (bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var entries []stopStatus
	if err := c.Call(callCtx, protocol.Request{Op: "status"}, &entries); err != nil {
		return false, fmt.Errorf("waiting for profiles to stop: %w", err)
	}
	seen := make(map[string]bool, len(targets))
	clean := true
	for _, entry := range entries {
		attempt, target := targets[entry.Profile]
		if !target {
			continue
		}
		if seen[entry.Profile] {
			return false, fmt.Errorf("%s: helper returned duplicate stop status", entry.Profile)
		}
		seen[entry.Profile] = true
		if entry.Attempt != attempt || entry.Wanted {
			return false, fmt.Errorf("%s: competing start while waiting for stop", entry.Profile)
		}
		if entry.State == "failed" || entry.CleanupPending || cleanupFailed(entry.Detail) {
			return false, fmt.Errorf("%s: stop or network cleanup failed", entry.Profile)
		}
		clean = clean && entry.State == "disconnected"
	}
	for id := range targets {
		if !seen[id] {
			return false, fmt.Errorf("%s: helper omitted stop status", id)
		}
	}
	return clean, nil
}

// drainStopEvents checks already queued transitions without blocking and reports
// whether another snapshot is needed. Cancellation also bounds a busy event queue.
func (c *Client) drainStopEvents(ctx context.Context, targets map[string]uint64) (bool, error) {
	changed := false
	for {
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("waiting for profiles to stop: %w", ctx.Err())
		case event, ok := <-c.Events():
			if !ok {
				return false, c.stopConnectionError()
			}
			if err := checkStopEvent(event, targets); err != nil {
				return false, err
			}
			if attempt, target := targets[event.Profile]; target && event.Type == "state" && event.Attempt == attempt {
				changed = true
			}
		default:
			return changed, c.Err()
		}
	}
}

// checkStopEvent rejects newer generations, queued starts during cleanup, and
// cleanup failure notifications even if a later snapshot has already recovered.
// Pre-stop connected events and older generations cannot satisfy the wait.
func checkStopEvent(event protocol.Event, targets map[string]uint64) error {
	attempt, target := targets[event.Profile]
	if !target || event.Type != "state" || event.Attempt < attempt {
		return nil
	}
	if event.Attempt > attempt || (event.Wanted && (event.State == "stopping" || event.State == "disconnected")) {
		return fmt.Errorf("%s: competing start while waiting for stop", event.Profile)
	}
	if event.CleanupPending || cleanupFailed(event.Detail) {
		return fmt.Errorf("%s: stop or network cleanup failed", event.Profile)
	}
	return nil
}

// cleanupFailed recognizes the helper's public retry diagnostic because cleanup
// retries remain in stopping and CleanupPending is only set after exhaustion.
func cleanupFailed(detail string) bool {
	return strings.HasPrefix(detail, "network cleanup failed")
}

// stopConnectionError preserves a transport error and never treats channel closure
// without an error as a successful acknowledgement of network cleanup.
func (c *Client) stopConnectionError() error {
	if err := c.Err(); err != nil {
		return fmt.Errorf("waiting for profiles to stop: %w", err)
	}
	return errors.New("helper disconnected while waiting for profiles to stop")
}
