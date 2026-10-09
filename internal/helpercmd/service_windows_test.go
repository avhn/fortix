package helpercmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// serviceExit captures both SCM exit-code fields without starting a real service.
type serviceExit struct {
	specific bool
	code     uint32
}

// nextStatus bounds state assertions so a broken handler cannot hang a test worker.
func nextStatus(t *testing.T, changes <-chan svc.Status, want svc.State) svc.Status {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case status := <-changes:
			if status.State == want {
				return status
			}
			if status.State != svc.StartPending && status.State != svc.StopPending {
				t.Fatalf("state %v, want %v", status.State, want)
			}
		case <-timer.C:
			t.Fatalf("missing state %v", want)
			return svc.Status{}
		}
	}
}

// TestServiceReadinessAndDrain verifies checkpoints, listener readiness, control masks and joined stop.
func TestServiceReadinessAndDrain(t *testing.T) {
	ready, drain := make(chan struct{}), make(chan struct{})
	canceled := make(chan struct{})
	changes := make(chan svc.Status, 32)
	requests := make(chan svc.ChangeRequest, 1)
	result := make(chan serviceExit, 1)
	h := serviceHandler{ctx: t.Context(), tick: time.Millisecond, run: func(ctx context.Context, notify func()) error {
		<-ready
		notify()
		<-ctx.Done()
		close(canceled)
		<-drain
		return nil
	}}
	go func() { specific, code := h.Execute(nil, requests, changes); result <- serviceExit{specific, code} }()
	first := nextStatus(t, changes, svc.StartPending)
	second := nextStatus(t, changes, svc.StartPending)
	if first.CheckPoint == 0 || second.CheckPoint <= first.CheckPoint {
		t.Fatal("startup checkpoint did not advance")
	}
	select {
	case exit := <-result:
		t.Fatalf("early exit: %+v", exit)
	default:
	}
	close(ready)
	status := nextStatus(t, changes, svc.Running)
	if status.Accepts != svc.AcceptStop|svc.AcceptShutdown {
		t.Fatal("unexpected controls")
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	nextStatus(t, changes, svc.StopPending)
	// Keep consuming checkpoints while the fake backend deliberately blocks cleanup.
	consumeDone := make(chan struct{})
	defer close(consumeDone)
	go func() {
		for {
			select {
			case <-changes:
			case <-consumeDone:
				return
			}
		}
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("stop did not cancel")
	}
	select {
	case <-result:
		t.Fatal("stop returned before drain")
	default:
	}
	close(drain)
	select {
	case exit := <-result:
		if exit.specific || exit.code != 0 {
			t.Fatal(exit)
		}
	case <-time.After(time.Second):
		t.Fatal("drain did not finish")
	}
}

// TestServiceFailureExit covers startup, cleanup and unresponsive shutdown without native SCM calls.
func TestServiceFailureExit(t *testing.T) {
	for _, phase := range []string{"startup", "cleanup", "timeout", "early return"} {
		t.Run(phase, func(t *testing.T) {
			changes := make(chan svc.Status, 32)
			requests := make(chan svc.ChangeRequest, 1)
			done := make(chan serviceExit, 1)
			release := make(chan struct{})
			defer close(release)
			h := serviceHandler{ctx: t.Context(), tick: time.Second, stopTimeout: 10 * time.Millisecond, run: func(ctx context.Context, ready func()) error {
				if phase == "startup" {
					return errors.New("storage unavailable")
				}
				if phase == "early return" {
					return nil
				}
				ready()
				<-ctx.Done()
				if phase == "timeout" {
					<-release
					return nil
				}
				return errors.New("incomplete cleanup")
			}}
			go func() { specific, code := h.Execute(nil, requests, changes); done <- serviceExit{specific, code} }()
			nextStatus(t, changes, svc.StartPending)
			if phase == "cleanup" || phase == "timeout" {
				nextStatus(t, changes, svc.Running)
				requests <- svc.ChangeRequest{Cmd: svc.Shutdown}
				nextStatus(t, changes, svc.StopPending)
			}
			select {
			case exit := <-done:
				if !exit.specific || exit.code == 0 {
					t.Fatal(exit)
				}
			case <-time.After(time.Second):
				t.Fatal("handler did not fail")
			}
		})
	}
}

// TestServiceStopBeforeReady prevents delayed initialization from advertising Running after StopPending.
func TestServiceStopBeforeReady(t *testing.T) {
	changes := make(chan svc.Status, 32)
	requests := make(chan svc.ChangeRequest, 1)
	done := make(chan serviceExit, 1)
	h := serviceHandler{ctx: t.Context(), run: func(ctx context.Context, ready func()) error { <-ctx.Done(); ready(); return nil }}
	go func() { specific, code := h.Execute(nil, requests, changes); done <- serviceExit{specific, code} }()
	nextStatus(t, changes, svc.StartPending)
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	nextStatus(t, changes, svc.StopPending)
	select {
	case exit := <-done:
		if exit.code != 0 {
			t.Fatal(exit)
		}
	case <-time.After(time.Second):
		t.Fatal("startup cancellation hung")
	}
	for len(changes) > 0 {
		if (<-changes).State == svc.Running {
			t.Fatal("advertised readiness after stop")
		}
	}
}
