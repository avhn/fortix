package helper

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestAcceptRetries verifies transient resource and aborted-connection failures do
// not terminate the service; listener closure and context cancellation still do.
func TestAcceptRetries(t *testing.T) {
	for _, cause := range []error{unix.EMFILE, unix.ENFILE, unix.ECONNABORTED} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s := &Server{ctx: ctx, opts: Options{MaxConnections: 1, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
			calls := 0
			err := s.accept(func() (*net.UnixConn, error) {
				calls++
				if calls == 1 {
					return nil, cause
				}
				return nil, net.ErrClosed
			}, false)
			if !errors.Is(err, net.ErrClosed) || calls != 2 {
				t.Fatalf("accept stopped early: %v (%d calls)", err, calls)
			}
			cancel()
			err = s.accept(func() (*net.UnixConn, error) { return nil, cause }, false)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}
