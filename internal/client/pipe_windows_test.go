package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// replacePipeDial restores native hooks after each serialized transport test.
func replacePipeDial(t *testing.T) {
	t.Helper()
	open, wait := nativeOpenPipe, nativeWaitPipe
	t.Cleanup(func() { nativeOpenPipe, nativeWaitPipe = open, wait })
}

// TestWindowsPipeOpenFlags checks overlapped I/O and identification-only security before retrying.
func TestWindowsPipeOpenFlags(t *testing.T) {
	replacePipeDial(t)
	opens, waits := 0, 0
	nativeOpenPipe = func(name *uint16, access, mode uint32, sa *windows.SecurityAttributes, disposition, flags uint32, template windows.Handle) (windows.Handle, error) {
		opens++
		if windows.UTF16PtrToString(name) != `\\.\pipe\Fortix.Control.v1` || access != windows.GENERIC_READ|windows.FILE_WRITE_DATA || mode != 0 || sa != nil || disposition != windows.OPEN_EXISTING || template != 0 ||
			flags != windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION {
			t.Fatal("unexpected named-pipe open flags")
		}
		if opens == 1 {
			return windows.InvalidHandle, windows.ERROR_PIPE_BUSY
		}
		return windows.CreateEvent(nil, 1, 0, nil)
	}
	nativeWaitPipe = func(_ *uint16, milliseconds uint32) error {
		waits++
		if milliseconds == 0 || milliseconds > 50 {
			t.Fatal("unbounded wait")
		}
		return nil
	}
	conn, err := dialPipe(t.Context(), "pipe", `\\.\pipe\Fortix.Control.v1`)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if opens != 2 || waits != 1 || conn.LocalAddr().Network() != "pipe" {
		t.Fatalf("retry: opens=%d waits=%d", opens, waits)
	}
}

// TestWindowsPipeBusyCancellation bounds retry and handles context cancellation before open.
func TestWindowsPipeBusyCancellation(t *testing.T) {
	replacePipeDial(t)
	calls := 0
	nativeOpenPipe = func(_ *uint16, _, _ uint32, _ *windows.SecurityAttributes, _, _ uint32, _ windows.Handle) (windows.Handle, error) {
		calls++
		return windows.InvalidHandle, windows.ERROR_PIPE_BUSY
	}
	ctx, cancel := context.WithCancel(t.Context())
	nativeWaitPipe = func(_ *uint16, _ uint32) error { cancel(); return windows.ERROR_SEM_TIMEOUT }
	if _, err := dialPipe(ctx, "pipe", `\\.\pipe\Fortix.Control.v1`); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("busy cancellation: calls=%d err=%v", calls, err)
	}
	if _, err := dialPipe(ctx, "pipe", `\\.\pipe\Fortix.Control.v1`); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancelled dial reached CreateFile")
	}
}

// connectedTestPipes creates isolated local handles without claiming the installed service namespace.
// Cleanup cancels and joins pending operations before native handles are released.
func connectedTestPipes(t *testing.T) (*pipeConn, *pipeConn) {
	t.Helper()
	name := fmt.Sprintf(`\\.\pipe\Fortix.ClientTest.%d.%d`, os.Getpid(), time.Now().UnixNano())
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := &pipeConn{handle: handle, name: name}
	t.Cleanup(func() { _ = server.Close() })
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	connected := make(chan error, 1)
	go func() {
		_, err := server.operation(false, func(o *windows.Overlapped, _ *uint32) error { return windows.ConnectNamedPipe(server.handle, o) })
		connected <- err
	}()
	handle, err = windows.CreateFile(path, windows.GENERIC_READ|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		_ = server.Close()
		<-connected
		t.Fatal(err)
	}
	client := &pipeConn{handle: handle, name: name}
	t.Cleanup(func() { _ = client.Close() })
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return client, server
}

// TestWindowsPipeReadDeadlineAndClose exercises real pending reads and changed deadlines.
func TestWindowsPipeReadDeadlineAndClose(t *testing.T) {
	client, server := connectedTestPipes(t)
	read := make(chan error, 1)
	go func() { _, err := client.Read(make([]byte, 1)); read <- err }()
	if err := client.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-read:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending read did not observe deadline")
	}
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _, err := server.Write([]byte("x")); read <- err }()
	data := make([]byte, 1)
	if _, err := io.ReadFull(client, data); err != nil || string(data) != "x" {
		t.Fatalf("read after cancellation: %q %v", data, err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() { _, err := client.Read(make([]byte, 1)); read <- err }()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-read:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not drain pending read")
	}
	if err := client.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed pipe accepted a deadline")
	}
}

// TestWindowsPipeWriteDeadline cancels an unconsumed large write and drains its OVERLAPPED.
func TestWindowsPipeWriteDeadline(t *testing.T) {
	client, _ := connectedTestPipes(t)
	if err := client.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := client.Write(make([]byte, 1024*1024)); written <- err }()
	select {
	case err := <-written:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write deadline did not drain completion")
	}
}
