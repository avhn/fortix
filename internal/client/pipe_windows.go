package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pipeConn joins every overlapped completion before releasing its event or native handle.
type pipeConn struct {
	name                        string
	handle                      windows.Handle
	mu                          sync.Mutex
	readMu, writeMu             sync.Mutex
	pending                     sync.WaitGroup
	closed                      bool
	readDeadline, writeDeadline time.Time
	closeOnce                   sync.Once
	closeErr                    error
}

// pipeAddress supplies stable local endpoint metadata without claiming a TCP identity.
type pipeAddress string

// Network identifies the local named-pipe transport.
func (pipeAddress) Network() string { return "pipe" }

// String returns the fixed endpoint name without user-derived data.
func (p pipeAddress) String() string { return string(p) }

// LocalAddr exposes the fixed named-pipe endpoint.
func (p *pipeConn) LocalAddr() net.Addr { return pipeAddress(p.name) }

// RemoteAddr does not expose unauthenticated client claims.
func (*pipeConn) RemoteAddr() net.Addr { return pipeAddress("local") }

// SetDeadline changes both pending and future I/O deadlines under the state lock.
func (p *pipeConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	p.readDeadline = t
	p.writeDeadline = t
	return nil
}

// SetReadDeadline also applies to a read already waiting for kernel completion.
func (p *pipeConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	p.readDeadline = t
	return nil
}

// SetWriteDeadline also applies to a blocked writer without racing its OVERLAPPED.
func (p *pipeConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	p.writeDeadline = t
	return nil
}

// operation cancels timed-out work and drains completion before its stack state can disappear.
func (p *pipeConn) operation(write bool, start func(*windows.Overlapped, *uint32) error) (uint32, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := windows.Overlapped{HEvent: event}
	var transferred uint32
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	deadline := p.readDeadline
	if write {
		deadline = p.writeDeadline
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		p.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	p.pending.Add(1)
	err = start(&overlapped, &transferred)
	p.mu.Unlock()
	defer p.pending.Done()
	if err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return transferred, nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	for {
		p.mu.Lock()
		closed := p.closed
		deadline = p.readDeadline
		if write {
			deadline = p.writeDeadline
		}
		p.mu.Unlock()
		var cause error
		if closed {
			cause = net.ErrClosed
		} else if !deadline.IsZero() && !time.Now().Before(deadline) {
			cause = os.ErrDeadlineExceeded
		}
		if cause != nil {
			_ = windows.CancelIoEx(p.handle, &overlapped)
			_ = windows.GetOverlappedResult(p.handle, &overlapped, &transferred, true)
			return transferred, cause
		}
		wait, waitErr := windows.WaitForSingleObject(event, 25)
		if waitErr != nil || wait != uint32(windows.WAIT_TIMEOUT) {
			if waitErr != nil {
				_ = windows.CancelIoEx(p.handle, &overlapped)
				_ = windows.GetOverlappedResult(p.handle, &overlapped, &transferred, true)
				return 0, waitErr
			}
			err = windows.GetOverlappedResult(p.handle, &overlapped, &transferred, true)
			if errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
				p.mu.Lock()
				if p.closed {
					err = net.ErrClosed
				}
				p.mu.Unlock()
			}
			return transferred, err
		}
	}
}

// Read serializes reads and converts the pipe disconnect signal to stream EOF.
func (p *pipeConn) Read(data []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	if len(data) == 0 {
		return 0, nil
	}
	n, err := p.operation(false, func(o *windows.Overlapped, n *uint32) error { return windows.ReadFile(p.handle, data, n, o) })
	runtime.KeepAlive(data)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || err == nil && n == 0 {
		err = io.EOF
	}
	return int(n), err
}

// Write serializes frames and holds their buffer until native I/O has completed.
func (p *pipeConn) Write(data []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if len(data) == 0 {
		return 0, nil
	}
	n, err := p.operation(true, func(o *windows.Overlapped, n *uint32) error { return windows.WriteFile(p.handle, data, n, o) })
	runtime.KeepAlive(data)
	if err == nil && int(n) != len(data) {
		err = io.ErrShortWrite
	}
	return int(n), err
}

// Close prevents new operations, cancels pending I/O and joins it before closing the handle.
func (p *pipeConn) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		_ = windows.CancelIoEx(p.handle, nil)
		p.mu.Unlock()
		p.pending.Wait()
		p.closeErr = windows.CloseHandle(p.handle)
	})
	return p.closeErr
}

// waitNamedPipeW is the narrow binding absent from the Windows syscall package.
var waitNamedPipeW = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")

// nativeOpenPipe keeps access and SQOS flags observable in transport tests.
var nativeOpenPipe = windows.CreateFile

// nativeWaitPipe permits bounded busy/cancellation tests without a live service.
var nativeWaitPipe = waitNamedPipe

// waitNamedPipe waits at most the caller's slice for an available local instance.
func waitNamedPipe(name *uint16, milliseconds uint32) error {
	result, _, err := waitNamedPipeW.Call(uintptr(unsafe.Pointer(name)), uintptr(milliseconds))
	runtime.KeepAlive(name)
	if result == 0 {
		if err == windows.ERROR_SUCCESS {
			return windows.ERROR_GEN_FAILURE
		}
		return err
	}
	return nil
}

// dialPipe opens a local overlapped handle with identification-only SQOS.
// Busy instances are retried under a finite budget with short, cancellable native waits.
// FILE_WRITE_DATA avoids GENERIC_WRITE's pipe-instance creation and attribute rights,
// which the member DACL intentionally withholds; GENERIC_READ already includes synchronization.
func dialPipe(ctx context.Context, network, name string) (net.Conn, error) {
	if network != "pipe" || name != `\\.\pipe\Fortix.Control.v1` {
		return nil, errors.New("invalid local Fortix pipe endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		handle, err := nativeOpenPipe(path, windows.GENERIC_READ|windows.FILE_WRITE_DATA, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			return &pipeConn{handle: handle, name: name}, nil
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, err
		}
		deadline, _ := ctx.Deadline()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		wait := min(uint32(50), uint32(max(int64(1), remaining.Milliseconds())))
		if err := nativeWaitPipe(path, wait); err != nil && !errors.Is(err, windows.ERROR_SEM_TIMEOUT) && !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, err
		}
		// Availability is advisory. Back off even when another client wins the instance.
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
