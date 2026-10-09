package helper

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// fakePipeListener keeps real closeable handles while replacing only native pipe operations.
func fakePipeListener(t *testing.T) (*pipeListener, *int) {
	t.Helper()
	create, connect, disconnect := nativeCreatePipe, nativeConnectPipe, nativeDisconnectPipe
	t.Cleanup(func() {
		nativeCreatePipe, nativeConnectPipe, nativeDisconnectPipe = create, connect, disconnect
	})
	nativeCreatePipe = func(_ *uint16, _, _, _, _, _, _ uint32, _ *windows.SecurityAttributes) (windows.Handle, error) {
		return windows.CreateEvent(nil, 1, 0, nil)
	}
	resets := new(int)
	nativeDisconnectPipe = func(windows.Handle) error { *resets++; return nil }
	listener, err := listenPipe("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, resets
}

// TestPipeAcceptAbandonedClient reuses the instance after immediate or completed disconnect errors.
func TestPipeAcceptAbandonedClient(t *testing.T) {
	for _, failure := range []error{windows.ERROR_NO_DATA, windows.ERROR_BROKEN_PIPE} {
		t.Run(failure.Error(), func(t *testing.T) {
			listener, resets := fakePipeListener(t)
			original := listener.next
			calls := 0
			nativeConnectPipe = func(handle windows.Handle, _ *windows.Overlapped) error {
				calls++
				if handle != original.handle {
					t.Fatal("abandoned instance was replaced")
				}
				if calls == 1 {
					return failure
				}
				return nil
			}
			accepted, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			if accepted != original || listener.next == original || calls != 2 || *resets != 1 {
				t.Fatalf("incorrect instance lifecycle: calls=%d resets=%d", calls, *resets)
			}
		})
	}
}

// TestPipeAcceptReplacementFailure disconnects the client and retains the instance for retry.
func TestPipeAcceptReplacementFailure(t *testing.T) {
	listener, resets := fakePipeListener(t)
	original := listener.next
	create := nativeCreatePipe
	nativeConnectPipe = func(windows.Handle, *windows.Overlapped) error { return nil }
	nativeCreatePipe = func(_ *uint16, _, _, _, _, _, _ uint32, _ *windows.SecurityAttributes) (windows.Handle, error) {
		return windows.InvalidHandle, windows.ERROR_NOT_ENOUGH_MEMORY
	}
	if _, err := listener.Accept(); !errors.Is(err, windows.ERROR_NOT_ENOUGH_MEMORY) {
		t.Fatalf("replacement error lost: %v", err)
	}
	if *resets != 1 || listener.next != original || original.closed {
		t.Fatal("connected client retained or namespace ownership lost")
	}
	nativeCreatePipe = create
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if accepted != original {
		t.Fatal("retry did not reuse retained instance")
	}
}

// TestServerAcceptTransientErrors proves Serve's accept loop survives abandoned and failed clients.
func TestServerAcceptTransientErrors(t *testing.T) {
	listener, _ := fakePipeListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := &Server{ctx: ctx, opts: Options{MaxConnections: 1}}
	calls := 0
	nativeConnectPipe = func(windows.Handle, *windows.Overlapped) error {
		calls++
		switch calls {
		case 1:
			return windows.ERROR_NO_DATA
		case 2:
			return windows.ERROR_ACCESS_DENIED
		default:
			cancel()
			return windows.ERROR_ACCESS_DENIED
		}
	}
	if err := s.accept(listener); !errors.Is(err, context.Canceled) || calls != 3 {
		t.Fatalf("accept stopped before cancellation or leaked its only slot: calls=%d err=%v", calls, err)
	}
}

// TestServerAcceptClosedListener exits rather than retrying an intentional listener shutdown.
func TestServerAcceptClosedListener(t *testing.T) {
	listener, _ := fakePipeListener(t)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	s := &Server{ctx: context.Background(), opts: Options{MaxConnections: 1}}
	if err := s.accept(listener); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed listener did not stop acceptance: %v", err)
	}
}
