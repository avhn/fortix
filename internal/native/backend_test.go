package native

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/ppp"
)

// TestOutcomeTimeoutPhase distinguishes fatal setup deadlines from retryable data
// transport loss, preserving graceful cancellation after an explicit Stop.
func TestOutcomeTimeoutPhase(t *testing.T) {
	for _, activated := range []bool{false, true} {
		for _, err := range []error{context.DeadlineExceeded, fmt.Errorf("TLS write: %w", os.ErrDeadlineExceeded)} {
			tunnel := &Tunnel{ctx: context.Background(), activated: activated}
			want := backend.TimeoutFailure
			if activated {
				want = backend.TransportFailure
			}
			if got := tunnel.outcome(err); got.Failure != want {
				t.Fatalf("activated=%v error=%v outcome=%+v, want %s", activated, err, got, want)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tunnel := &Tunnel{ctx: ctx, activated: true}
	if got := tunnel.outcome(context.Canceled); got != (backend.Outcome{}) {
		t.Fatalf("explicit stop produced failure: %+v", got)
	}
	if got := tunnel.outcome(ppp.ErrRenegotiation); got.Failure != backend.TransportFailure {
		t.Fatalf("renegotiation is not transport loss: %+v", got)
	}
}
