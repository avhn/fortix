// Package animate tests scheduling with controlled clocks and bounded test waits.
package animate

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/tray/icon"
	"github.com/avhn/fortix/internal/tray/model"
)

// fakeTicker records cleanup and permits tests to deliver ticks without sleeping.
type fakeTicker struct {
	events   chan time.Time
	stopped  atomic.Bool
	duration time.Duration
}

// C returns the controlled tick stream without creating a goroutine.
func (f *fakeTicker) C() <-chan time.Time { return f.events }

// Stop atomically records cleanup and is safe to call repeatedly.
func (f *fakeTicker) Stop() { f.stopped.Store(true) }

// fakeClock publishes each created ticker so tests can coordinate with Run.
type fakeClock struct{ created chan *fakeTicker }

// NewTicker returns a manually driven ticker and records its requested duration.
func (f *fakeClock) NewTicker(d time.Duration) Ticker {
	ticker := &fakeTicker{events: make(chan time.Time, 1), duration: d}
	f.created <- ticker
	return ticker
}

// fakeMotion holds a race-safe live system policy for poll-driven tests.
type fakeMotion struct{ value atomic.Uint32 }

// Read returns the current policy without I/O or additional goroutines.
func (f *fakeMotion) Read(context.Context) Motion { return Motion(f.value.Load()) }

// fakeSetter records complete PNG frames or returns its configured error.
type fakeSetter struct {
	images chan []byte
	err    error
}

// SetIcon records immutable PNG bytes synchronously unless a failure was requested.
func (f *fakeSetter) SetIcon(data []byte) error {
	if f.err != nil {
		return f.err
	}
	f.images <- data
	return nil
}

// receive bounds all test synchronization so a scheduling regression cannot hang tests.
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for animator")
		var zero T
		return zero
	}
}

// expectFrame compares a received image to the named cached frame, failing on mismatch.
func expectFrame(t *testing.T, setter *fakeSetter, status model.Status, frame int) {
	t.Helper()
	want, err := icon.PNG("darwin", 22, status, frame)
	if err != nil {
		t.Fatal(err)
	}
	if got := receive(t, setter.images); !bytes.Equal(got, want) {
		t.Fatalf("wrong frame, want %s/%d", status, frame)
	}
}

// TestAnimator exercises a complete loop, status changes, live system policy, and user flips.
func TestAnimator(t *testing.T) {
	clock := &fakeClock{created: make(chan *fakeTicker, 16)}
	setter := &fakeSetter{images: make(chan []byte, 32)}
	source := &fakeMotion{}
	source.value.Store(uint32(Allow))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan Update, 8)
	done := make(chan error, 1)
	a := Animator{Platform: "darwin", Size: 22, Setter: setter, Clock: clock, Source: source}
	go func() { done <- a.Run(ctx, updates, Update{Status: model.Connecting, AnimateIcon: true}) }()
	poll := receive(t, clock.created)
	expectFrame(t, setter, model.Connecting, 0)
	expectFrame(t, setter, model.Connecting, 0)
	frames := receive(t, clock.created)
	if poll.duration != 10*time.Second || frames.duration != time.Second/12 {
		t.Fatal("incorrect cadence")
	}
	for frame := 1; frame <= 12; frame++ {
		frames.events <- time.Time{}
		expectFrame(t, setter, model.Connecting, frame%12)
	}
	updates <- Update{Status: model.Partial, AnimateIcon: true}
	expectFrame(t, setter, model.Partial, 0)
	if !frames.stopped.Load() {
		t.Fatal("status change leaked frame ticker")
	}
	updates <- Update{Status: model.Connecting, AnimateIcon: true}
	expectFrame(t, setter, model.Connecting, 0)
	frames = receive(t, clock.created)
	updates <- Update{Status: model.Connecting, AnimateIcon: false}
	expectFrame(t, setter, model.Connecting, 0)
	if !frames.stopped.Load() {
		t.Fatal("user preference did not stop motion")
	}
	updates <- Update{Status: model.Connecting, AnimateIcon: true}
	expectFrame(t, setter, model.Connecting, 0)
	frames = receive(t, clock.created)
	source.value.Store(uint32(Reduce))
	poll.events <- time.Time{}
	expectFrame(t, setter, model.Connecting, 0)
	if !frames.stopped.Load() {
		t.Fatal("system reduce did not stop motion")
	}
	source.value.Store(uint32(Allow))
	poll.events <- time.Time{}
	expectFrame(t, setter, model.Connecting, 0)
	frames = receive(t, clock.created)
	source.value.Store(uint32(Unknown))
	poll.events <- time.Time{}
	expectFrame(t, setter, model.Connecting, 0)
	if !frames.stopped.Load() {
		t.Fatal("unknown policy did not stop motion")
	}
	updates <- Update{Status: model.Connected, AnimateIcon: true}
	expectFrame(t, setter, model.Connected, 0)
	close(updates)
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
	if !poll.stopped.Load() {
		t.Fatal("poll ticker leaked")
	}
}

// TestCleanup repeats cancellation and stream closure, ensuring Run joins and stops tickers.
func TestCleanup(t *testing.T) {
	for i := range 30 {
		clock := &fakeClock{created: make(chan *fakeTicker, 4)}
		setter := &fakeSetter{images: make(chan []byte, 4)}
		source := &fakeMotion{}
		source.value.Store(uint32(Allow))
		ctx, cancel := context.WithCancel(context.Background())
		updates := make(chan Update)
		done := make(chan error, 1)
		go func() {
			done <- (Animator{Platform: "darwin", Size: 22, Setter: setter, Clock: clock, Source: source}).Run(ctx, updates, Update{Status: model.Connecting, AnimateIcon: true})
		}()
		poll := receive(t, clock.created)
		expectFrame(t, setter, model.Connecting, 0)
		expectFrame(t, setter, model.Connecting, 0)
		frames := receive(t, clock.created)
		if i%2 == 0 {
			cancel()
		} else {
			close(updates)
		}
		err := receive(t, done)
		cancel()
		if err != nil || !frames.stopped.Load() || !poll.stopped.Load() {
			t.Fatalf("cleanup failed: %v", err)
		}
	}
}

// TestStaticAndFailures covers safe defaults, cancellation, invalid inputs, and setter errors.
func TestStaticAndFailures(t *testing.T) {
	for _, status := range []model.Status{model.NotConnected, model.Connecting, model.Connected, model.Partial, model.Attention} {
		clock := &fakeClock{created: make(chan *fakeTicker, 4)}
		setter := &fakeSetter{images: make(chan []byte, 4)}
		updates := make(chan Update)
		close(updates)
		a := Animator{Platform: "darwin", Size: 22, Setter: setter, Clock: clock}
		if err := a.Run(context.Background(), updates, Update{Status: status, AnimateIcon: true}); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, setter, status, 0)
		ticker := receive(t, clock.created)
		if !ticker.stopped.Load() || len(clock.created) != 0 {
			t.Fatal("static mode created or leaked extra ticker")
		}
	}
	updates := make(chan Update)
	close(updates)
	failure := errors.New("setter failure")
	a := Animator{Platform: "darwin", Size: 22, Setter: &fakeSetter{err: failure}}
	if err := a.Run(context.Background(), updates, Update{Status: model.Connected}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	a.Size = 1
	if err := a.Run(context.Background(), updates, Update{Status: model.Connected}); err == nil {
		t.Fatal("invalid size accepted")
	}
	if err := (Animator{}).Run(context.Background(), updates, Update{}); err == nil {
		t.Fatal("nil setter accepted")
	}
	if err := a.Run(context.Background(), nil, Update{}); err == nil {
		t.Fatal("nil updates accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Run(ctx, updates, Update{}); err != nil {
		t.Fatal(err)
	}
}

// blockingMotion announces each probe and waits for explicit release or cancellation.
// It models a desktop service that stalls without preventing connection updates.
type blockingMotion struct {
	entered chan struct{}
	release chan Motion
	exited  chan struct{}
}

// Read returns the released policy or Unknown on cancellation, reporting worker exit.
func (b *blockingMotion) Read(ctx context.Context) Motion {
	b.entered <- struct{}{}
	defer func() { b.exited <- struct{}{} }()
	select {
	case motion := <-b.release:
		return motion
	case <-ctx.Done():
		return Unknown
	}
}

// TestBlockedProbeDoesNotBlockStatus verifies that slow probes cannot delay static icons
// and that Run cancels and joins an outstanding probe before reporting completion.
func TestBlockedProbeDoesNotBlockStatus(t *testing.T) {
	clock := &fakeClock{created: make(chan *fakeTicker, 4)}
	setter := &fakeSetter{images: make(chan []byte, 4)}
	source := &blockingMotion{entered: make(chan struct{}, 2), release: make(chan Motion), exited: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan Update, 4)
	done := make(chan error, 1)
	go func() {
		done <- (Animator{Platform: "darwin", Size: 22, Setter: setter, Clock: clock, Source: source}).Run(ctx, updates, Update{Status: model.Connecting, AnimateIcon: true})
	}()
	poll := receive(t, clock.created)
	expectFrame(t, setter, model.Connecting, 0)
	receive(t, source.entered)
	updates <- Update{Status: model.Connected, AnimateIcon: true}
	expectFrame(t, setter, model.Connected, 0)
	source.release <- Allow
	receive(t, source.exited)
	expectFrame(t, setter, model.Connected, 0)
	updates <- Update{Status: model.Connecting, AnimateIcon: true}
	expectFrame(t, setter, model.Connecting, 0)
	frames := receive(t, clock.created)
	poll.events <- time.Time{}
	receive(t, source.entered)
	updates <- Update{Status: model.Attention, AnimateIcon: true}
	expectFrame(t, setter, model.Attention, 0)
	if !frames.stopped.Load() {
		t.Fatal("blocked probe delayed ticker cleanup")
	}
	cancel()
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
	receive(t, source.exited)
	if !poll.stopped.Load() {
		t.Fatal("poll leaked")
	}
}

// failAfterSetter applies two startup icons then fails the first animated frame.
type failAfterSetter struct {
	fakeSetter
	calls   int
	failure error
}

// SetIcon returns the injected error on its third call; earlier calls record images.
func (s *failAfterSetter) SetIcon(data []byte) error {
	s.calls++
	if s.calls == 3 {
		return s.failure
	}
	return s.fakeSetter.SetIcon(data)
}

// TestFrameFailure checks error propagation and worker/ticker cleanup after motion starts.
func TestFrameFailure(t *testing.T) {
	clock := &fakeClock{created: make(chan *fakeTicker, 4)}
	failure := errors.New("animated frame rejected")
	setter := &failAfterSetter{fakeSetter: fakeSetter{images: make(chan []byte, 4)}, failure: failure}
	source := &fakeMotion{}
	source.value.Store(uint32(Allow))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan Update)
	done := make(chan error, 1)
	go func() {
		done <- (Animator{Platform: "darwin", Size: 22, Setter: setter, Clock: clock, Source: source}).Run(ctx, updates, Update{Status: model.Connecting, AnimateIcon: true})
	}()
	poll := receive(t, clock.created)
	expectFrame(t, &setter.fakeSetter, model.Connecting, 0)
	expectFrame(t, &setter.fakeSetter, model.Connecting, 0)
	frames := receive(t, clock.created)
	frames.events <- time.Time{}
	if err := receive(t, done); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if !frames.stopped.Load() || !poll.stopped.Load() {
		t.Fatal("failure leaked a ticker")
	}
}

// TestIdenticalUpdatesKeepFrames verifies queued duplicate snapshots never restart
// a running loop, whether selected directly or drained alongside a frame tick.
func TestIdenticalUpdatesKeepFrames(t *testing.T) {
	clock := &fakeClock{created: make(chan *fakeTicker, 16)}
	setter := &fakeSetter{images: make(chan []byte, 32)}
	source := &fakeMotion{}
	source.value.Store(uint32(Allow))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan Update, 8)
	done := make(chan error, 1)
	initial := Update{Status: model.Connecting, AnimateIcon: true}
	go func() {
		done <- (Animator{Platform: "darwin", Size: 22, Setter: setter, Clock: clock, Source: source}).Run(ctx, updates, initial)
	}()
	poll := receive(t, clock.created)
	expectFrame(t, setter, model.Connecting, 0)
	expectFrame(t, setter, model.Connecting, 0)
	frames := receive(t, clock.created)
	for frame := 1; frame <= 120; frame++ {
		updates <- initial
		frames.events <- time.Time{}
		expectFrame(t, setter, model.Connecting, frame%icon.Frames)
		if frames.stopped.Load() || len(clock.created) != 0 {
			t.Fatal("identical update restarted animation")
		}
	}
	cancel()
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
	if !frames.stopped.Load() || !poll.stopped.Load() {
		t.Fatal("cancellation leaked ticker")
	}
}
