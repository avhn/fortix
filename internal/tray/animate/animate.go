// Package animate owns cancellable tray frame scheduling and live motion preferences.
package animate

import (
	"context"
	"errors"
	"time"

	"github.com/avhn/fortix/internal/tray/icon"
	"github.com/avhn/fortix/internal/tray/model"
)

// Motion expresses system motion policy; unknown intentionally disables animation.
type Motion uint8

// Motion settings distinguish a positive permission to animate from safer defaults.
const (
	Unknown Motion = iota
	Reduce
	Allow
)

// Update is a complete presentation snapshot, including the user's animation toggle.
type Update struct {
	Status      model.Status
	AnimateIcon bool
}

// IconSetter applies PNG data synchronously; implementations must return promptly.
// An error stops Run, allowing a caller to report a failed desktop integration.
type IconSetter interface{ SetIcon([]byte) error }

// Ticker exposes a clock-owned event stream and idempotent cleanup operation.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// Clock supplies injectable tickers. NewTicker receives a strictly positive duration.
type Clock interface{ NewTicker(time.Duration) Ticker }

// MotionSource reads current policy, respecting cancellation and bounding external I/O.
type MotionSource interface{ Read(context.Context) Motion }

// Animator serially consumes snapshots and sets icons, owning one preference worker.
// Platform and Size select cached icons; nil Clock uses real time. A nil Source
// means unknown motion policy. Setter and non-nil update stream are required.
type Animator struct {
	Platform string
	Size     int
	Setter   IconSetter
	Clock    Clock
	Source   MotionSource
}

// Run displays initial state, consumes updates, and polls motion policy every 10s.
// It returns nil on cancellation or stream close, and returns validation/setter errors.
// The caller owns its goroutine. Both tickers are stopped on every exit; the frame
// ticker exists only while connecting and both system and user allow animation.
// Preference I/O runs in one worker, cancelled and joined before returning, so
// a slow desktop command never delays a connection status or user preference change.
func (a Animator) Run(ctx context.Context, updates <-chan Update, initial Update) error {
	if a.Setter == nil || updates == nil {
		return errors.New("animate: setter and status stream required")
	}
	clock := a.Clock
	if clock == nil {
		clock = realClock{}
	}
	var frames Ticker
	var ticks <-chan time.Time
	defer func() {
		if frames != nil {
			frames.Stop()
		}
	}()
	poll := clock.NewTicker(10 * time.Second)
	defer poll.Stop()
	current, frame, motion := initial, 0, Unknown
	if ctx.Err() != nil {
		return nil
	}
	probeCtx, cancel := context.WithCancel(ctx)
	requests := make(chan struct{}, 1)
	policies := make(chan Motion)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-probeCtx.Done():
				return
			case <-requests:
				next := Unknown
				if a.Source != nil {
					next = a.Source.Read(probeCtx)
				}
				select {
				case policies <- next:
				case <-probeCtx.Done():
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	requests <- struct{}{}
	show := func() error {
		data, err := icon.PNG(a.Platform, a.Size, current.Status, frame)
		if err != nil {
			return err
		}
		return a.Setter.SetIcon(data)
	}
	reconcile := func() error {
		if frames != nil {
			frames.Stop()
			frames = nil
			ticks = nil
		}
		frame = 0
		if err := show(); err != nil {
			return err
		}
		if current.Status == model.Connecting && current.AnimateIcon && motion == Allow {
			frames = clock.NewTicker(time.Second / icon.Frames)
			ticks = frames.C()
		}
		return nil
	}
	if err := reconcile(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case update, ok := <-updates:
			if !ok {
				return nil
			}
			if update != current {
				current = update
				if err := reconcile(); err != nil {
					return err
				}
			}
		case <-poll.C():
			// Coalesce polls if a desktop service is still answering the last one.
			select {
			case requests <- struct{}{}:
			default:
			}
		case next := <-policies:
			if next != motion {
				motion = next
				if err := reconcile(); err != nil {
					return err
				}
			}
		case <-ticks:
			// Prefer an already queued state change over drawing another stale frame.
			select {
			case <-ctx.Done():
				return nil
			case update, ok := <-updates:
				if !ok {
					return nil
				}
				if update != current {
					current = update
					if err := reconcile(); err != nil {
						return err
					}
					continue
				}
			default:
			}
			frame = (frame + 1) % icon.Frames
			if err := show(); err != nil {
				return err
			}
		}
	}
}

// realClock creates standard-library tickers without additional goroutines of its own.
type realClock struct{}

// NewTicker returns a stoppable standard-library ticker for positive duration d.
func (realClock) NewTicker(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} }

// realTicker adapts time.Ticker's channel field to the injectable Ticker interface.
type realTicker struct{ ticker *time.Ticker }

// C returns the ticker's receive-only event channel without consuming an event.
func (t realTicker) C() <-chan time.Time { return t.ticker.C }

// Stop releases scheduling resources; repeated calls are safe and return nothing.
func (t realTicker) Stop() { t.ticker.Stop() }
