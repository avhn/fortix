package helper

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// controlPipe is a fixed local-only namespace, independent of filesystem overrides.
const controlPipe = `\\.\pipe\Fortix.Control.v1`

// pipeMemberRights deliberately excludes FILE_CREATE_PIPE_INSTANCE and security writes.
const pipeMemberRights = windows.FILE_GENERIC_READ | windows.FILE_WRITE_DATA | windows.SYNCHRONIZE

// pipeDescriptor grants the service and administrators full access, members data I/O only.
func pipeDescriptor(group string) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if group != "" {
		sid, err := windows.StringToSid(group)
		if err != nil {
			return nil, err
		}
		sddl += fmt.Sprintf("(A;;0x%x;;;%s)", pipeMemberRights, sid.String())
	}
	return windows.SecurityDescriptorFromString(sddl)
}

// nativeCreatePipe isolates creation flags for deterministic namespace-squatting tests.
var nativeCreatePipe = windows.CreateNamedPipe

// nativeConnectPipe isolates clients that disconnect before the connect completes.
var nativeConnectPipe = windows.ConnectNamedPipe

// nativeDisconnectPipe resets an abandoned instance without surrendering its namespace.
var nativeDisconnectPipe = windows.DisconnectNamedPipe

// createPipe refuses a squatted first instance and creates only bounded byte-mode local pipes.
func createPipe(first bool, group string) (*pipeConn, error) {
	sd, err := pipeDescriptor(group)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(controlPipe)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := nativeCreatePipe(name, flags, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 16, 64*1024, 64*1024, 0, &sa)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, err
	}
	return &pipeConn{handle: h}, nil
}

// pipeConn joins every overlapped completion before releasing its event or native handle.
type pipeConn struct {
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
func (*pipeConn) LocalAddr() net.Addr { return pipeAddress(controlPipe) }

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
		_ = windows.DisconnectNamedPipe(p.handle)
		p.closeErr = windows.CloseHandle(p.handle)
	})
	return p.closeErr
}

// pipeListener retains a replacement instance before handing an accepted pipe to a worker.
type pipeListener struct {
	mu     sync.Mutex
	next   *pipeConn
	group  string
	closed bool
}

// listenPipe claims the first instance before exposing any service endpoint.
func listenPipe(group string) (*pipeListener, error) {
	pipe, err := createPipe(true, group)
	if err != nil {
		return nil, err
	}
	return &pipeListener{next: pipe, group: group}, nil
}

// Accept joins a cancellable connect operation and keeps the namespace continuously owned.
func (l *pipeListener) Accept() (*pipeConn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		p := l.next
		l.mu.Unlock()
		_, err := p.operation(false, func(o *windows.Overlapped, _ *uint32) error { return nativeConnectPipe(p.handle, o) })
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		if err != nil {
			// Completion has been drained. Keep ownership while resetting the abandoned client.
			resetErr := nativeDisconnectPipe(p.handle)
			l.mu.Unlock()
			if resetErr != nil && !errors.Is(resetErr, windows.ERROR_PIPE_NOT_CONNECTED) {
				return nil, resetErr
			}
			if errors.Is(err, windows.ERROR_NO_DATA) || errors.Is(err, windows.ERROR_BROKEN_PIPE) {
				continue
			}
			return nil, err
		}
		next, err := createPipe(false, l.group)
		if err != nil {
			// Retain this instance for the next accept, but never retain its connected client.
			resetErr := nativeDisconnectPipe(p.handle)
			l.mu.Unlock()
			return nil, errors.Join(err, resetErr)
		}
		l.next = next
		l.mu.Unlock()
		return p, nil
	}
}

// Close cancels the outstanding accept while accepted clients remain worker-owned.
func (l *pipeListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	p := l.next
	l.mu.Unlock()
	return p.Close()
}
