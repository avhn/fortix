package tun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// fakeWintun records ownership transitions without loading a DLL or creating a link.
type fakeWintun struct {
	mu                                                                             sync.Mutex
	event                                                                          windows.Handle
	packet                                                                         []byte
	startErr, allocateErr                                                          error
	created, started, released, allocated, sent, ended, closed, unloaded, afterEnd int
	order                                                                          []string
	receiveEntered                                                                 chan struct{}
	receiveBlock                                                                   <-chan struct{}
}

// newFakeWintun owns only a test event; no privileged network APIs are invoked.
func newFakeWintun(t *testing.T) *fakeWintun {
	t.Helper()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(event) })
	return &fakeWintun{event: event, receiveEntered: make(chan struct{}, 1)}
}

// create records that the durable allocation hook already permitted creation.
func (f *fakeWintun) create(string, *windows.GUID) (uintptr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created++
	f.order = append(f.order, "create")
	return 1, nil
}

// identity supplies a stable synthetic LUID and interface index.
func (f *fakeWintun) identity(uintptr) (uint64, uint32, error) { return 42, 7, nil }

// start makes rollback observable without allocating a real ring.
func (f *fakeWintun) start(_ uintptr, capacity uint32) (uintptr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started++
	if capacity != wintunRingCapacity {
		return 0, errors.New("unexpected ring size")
	}
	if f.startErr != nil {
		return 0, f.startErr
	}
	return 2, nil
}

// readEvent lends the fixture's event so tests detect accidental handle closure.
func (f *fakeWintun) readEvent(uintptr) (windows.Handle, error) { return f.event, nil }

// receive optionally stalls a borrowed packet to prove Close drains active readers.
func (f *fakeWintun) receive(uintptr) ([]byte, error) {
	select {
	case f.receiveEntered <- struct{}{}:
	default:
	}
	if f.receiveBlock != nil {
		<-f.receiveBlock
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended != 0 {
		f.afterEnd++
	}
	if f.packet == nil {
		return nil, windows.ERROR_NO_MORE_ITEMS
	}
	p := f.packet
	f.packet = nil
	return p, nil
}

// release records every borrowed receive and invalidates its storage after copying.
func (f *fakeWintun) release(_ uintptr, packet []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended != 0 {
		f.afterEnd++
	}
	f.released++
	f.order = append(f.order, "release")
	clear(packet)
}

// allocate reports saturation or lends a correctly sized test packet.
func (f *fakeWintun) allocate(_ uintptr, size uint32) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended != 0 {
		f.afterEnd++
	}
	f.allocated++
	if f.allocateErr != nil {
		return nil, f.allocateErr
	}
	return make([]byte, size), nil
}

// send records the transfer of an allocated packet back to the ring.
func (f *fakeWintun) send(uintptr, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended != 0 {
		f.afterEnd++
	}
	f.sent++
}

// end records session destruction separately from adapter closure.
func (f *fakeWintun) end(uintptr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ended++
	f.order = append(f.order, "end")
}

// closeAdapter records the final adapter-handle release.
func (f *fakeWintun) closeAdapter(uintptr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	f.order = append(f.order, "close")
}

// unload records that no code pointers remain usable after teardown.
func (f *fakeWintun) unload() error { f.mu.Lock(); defer f.mu.Unlock(); f.unloaded++; return nil }

// testWintun creates an unprivileged device with a successful in-memory ledger hook.
func testWintun(t *testing.T, f *fakeWintun) *wintunDevice {
	t.Helper()
	d, err := newWintunDevice(context.Background(), 1280, f, func(Allocation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
	})
	return d
}

// TestWintunExportFailure refuses each missing export without invoking a null pointer.
func TestWintunExportFailure(t *testing.T) {
	exports, err := resolveWintunExports(func(string) (uintptr, error) { return 1, nil })
	if err != nil {
		t.Fatal(err)
	}
	for missing := range exports {
		t.Run(missing, func(t *testing.T) {
			_, err := resolveWintunExports(func(name string) (uintptr, error) {
				if name == missing {
					return 0, windows.ERROR_PROC_NOT_FOUND
				}
				return 1, nil
			})
			if !errors.Is(err, windows.ERROR_PROC_NOT_FOUND) || !strings.Contains(err.Error(), missing) {
				t.Fatalf("missing export: %v", err)
			}
		})
	}
	if _, err := resolveWintunExports(func(string) (uintptr, error) { return 0, nil }); err == nil {
		t.Fatal("null export accepted")
	}
}

// TestWintunHashRefusal ensures neither supported architecture accepts substituted bytes.
func TestWintunHashRefusal(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64", "386"} {
		if err := verifyWintunHash(bytes.NewReader([]byte("substituted DLL")), arch); err == nil {
			t.Fatalf("accepted %s", arch)
		}
	}
}

// TestWintunPathRefusal excludes relative paths, remote shares, device paths and ADS.
func TestWintunPathRefusal(t *testing.T) {
	for _, path := range []string{"wintun.dll", `C:wintun.dll`, `\\server\share\wintun.dll`, `\\?\C:\wintun.dll`, `C:\safe\..\wintun.dll`, `C:\safe:wintun.dll`} {
		if err := validateDLLPath(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
	if err := validateDLLPath(`C:\Program Files\Fortix\wintun.dll`); err != nil {
		t.Fatal(err)
	}
}

// TestWintunAllocationRefusal proves ledger failure and missing hooks prevent creation.
func TestWintunAllocationRefusal(t *testing.T) {
	denied := errors.New("ledger unavailable")
	for _, hook := range []func(Allocation) error{nil, func(Allocation) error { return denied }} {
		f := newFakeWintun(t)
		if _, err := newWintunDevice(context.Background(), 1280, f, hook); err == nil {
			t.Fatal("missing ledger accepted")
		}
		if f.created != 0 || f.unloaded != 1 {
			t.Fatalf("creation=%d unload=%d", f.created, f.unloaded)
		}
	}
}

// TestWintunAllocationOrdering checks intent precedes creation and LUID follows it.
func TestWintunAllocationOrdering(t *testing.T) {
	f := newFakeWintun(t)
	var records []Allocation
	d, err := newWintunDevice(context.Background(), 1280, f, func(a Allocation) error {
		if len(records) == 0 && (f.created != 0 || a.LUID != 0 || a.GUID == (windows.GUID{}) || a.Name == "" || a.Nonce == "") {
			t.Fatal("invalid pre-create intent")
		}
		records = append(records, a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].GUID != records[1].GUID || records[1].LUID != 42 || d.Allocation() != records[1] {
		t.Fatalf("records: %+v", records)
	}
}

// TestWintunSessionRollback closes the adapter and DLL when session creation fails.
func TestWintunSessionRollback(t *testing.T) {
	f := newFakeWintun(t)
	f.startErr = windows.ERROR_NOT_ENOUGH_MEMORY
	if _, err := newWintunDevice(context.Background(), 1280, f, func(Allocation) error { return nil }); !errors.Is(err, f.startErr) {
		t.Fatalf("start: %v", err)
	}
	if f.created != 1 || f.closed != 1 || f.ended != 0 || f.unloaded != 1 {
		t.Fatalf("rollback: %+v", f)
	}
}

// TestWintunIdentityRollback retains ledger intent when the LUID update fails.
func TestWintunIdentityRollback(t *testing.T) {
	f := newFakeWintun(t)
	denied := errors.New("identity write failed")
	_, err := newWintunDevice(context.Background(), 1280, f, func(a Allocation) error {
		if a.LUID != 0 {
			return denied
		}
		return nil
	})
	if !errors.Is(err, denied) || f.started != 0 || f.closed != 1 || f.unloaded != 1 {
		t.Fatalf("identity rollback: %v %+v", err, f)
	}
}

// TestWintunReceiveRelease checks success, invalid packets and short buffers all release once.
func TestWintunReceiveRelease(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet []byte
		size   int
		want   error
	}{
		{"copy", []byte{0x45, 1, 2}, 16, nil},
		{"short", []byte{0x45, 1, 2}, 1, io.ErrShortBuffer},
		{"invalid", []byte{0}, 16, ErrInvalidPacket},
		{"large", append([]byte{0x45}, make([]byte, 1280)...), 1400, ErrPacketTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeWintun(t)
			f.packet = tc.packet
			want := append([]byte(nil), tc.packet...)
			d := testWintun(t, f)
			output := make([]byte, tc.size)
			n, err := d.Read(output)
			if !errors.Is(err, tc.want) || f.released != 1 {
				t.Fatalf("read=%d %v releases=%d", n, err, f.released)
			}
			if err == nil && !bytes.Equal(output[:n], want) {
				t.Fatal("borrowed bytes were not copied")
			}
		})
	}
}

// observedReadContext exposes callback registration without spawning a waiter.
// Its never-cancelled signal keeps AfterFunc observable on a ready-packet read.
type observedReadContext struct {
	context.Context
	done          chan struct{}
	registrations int
}

// Done makes cancellation registration observable without cancelling the read.
func (c *observedReadContext) Done() <-chan struct{} { return c.done }

// AfterFunc counts registrations; this context never fires the callback.
func (c *observedReadContext) AfterFunc(func()) func() bool {
	c.registrations++
	return func() bool { return true }
}

// TestWintunReadyReadSkipsCancellationSetup keeps ready packets on the fast path.
func TestWintunReadyReadSkipsCancellationSetup(t *testing.T) {
	f := newFakeWintun(t)
	d := testWintun(t, f)
	ctx := &observedReadContext{Context: context.Background(), done: make(chan struct{})}
	for i := 0; i < 3; i++ {
		f.packet = []byte{0x45}
		if n, err := d.ReadContext(ctx, make([]byte, 32)); n != 1 || err != nil {
			t.Fatalf("ready read: %d %v", n, err)
		}
	}
	if ctx.registrations != 0 || f.released != 3 {
		t.Fatalf("callbacks=%d releases=%d", ctx.registrations, f.released)
	}
}

// TestWintunWriteValidation rejects malformed lengths before touching the send ring.
func TestWintunWriteValidation(t *testing.T) {
	f := newFakeWintun(t)
	d := testWintun(t, f)
	for _, packet := range [][]byte{nil, {0}, make([]byte, 1281)} {
		if _, err := d.Write(packet); err == nil {
			t.Fatal("invalid packet accepted")
		}
	}
	if f.allocated != 0 {
		t.Fatal("invalid packet allocated ring storage")
	}
	if n, err := d.Write([]byte{0x45}); err != nil || n != 1 || f.sent != 1 {
		t.Fatalf("write: %d %v", n, err)
	}
}

// TestWintunRingCancellation cancels a saturated ring without destroying the adapter.
func TestWintunRingCancellation(t *testing.T) {
	f := newFakeWintun(t)
	f.allocateErr = windows.ERROR_BUFFER_OVERFLOW
	d := testWintun(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := d.WriteContext(ctx, []byte{0x45}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write cancellation: %v", err)
	}
	if f.allocated == 0 || f.ended != 0 || f.closed != 0 {
		t.Fatalf("ring cancellation: %+v", f)
	}
	f.allocateErr = nil
	if _, err := d.Write([]byte{0x45}); err != nil {
		t.Fatal(err)
	}
}

// TestWintunReadCancellation checks cancellation retains session and borrowed event.
func TestWintunReadCancellation(t *testing.T) {
	f := newFakeWintun(t)
	d := testWintun(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := d.ReadContext(ctx, make([]byte, 32)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read cancellation: %v", err)
	}
	if f.ended != 0 || f.closed != 0 {
		t.Fatal("cancellation destroyed adapter")
	}
	if _, err := windows.WaitForSingleObject(f.event, 0); err != nil {
		t.Fatalf("borrowed event closed: %v", err)
	}
	// A second empty-ring read must own fresh cancellation state.
	next, cancelNext := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelNext()
	if _, err := d.ReadContext(next, make([]byte, 32)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("next read cancellation: %v", err)
	}
	f.packet = []byte{0x45}
	if n, err := d.Read(make([]byte, 32)); n != 1 || err != nil {
		t.Fatalf("retained read: %d %v", n, err)
	}
}

// TestWintunCloseDrainsRead proves EndSession cannot overtake a borrowed packet.
func TestWintunCloseDrainsRead(t *testing.T) {
	f := newFakeWintun(t)
	unblock := make(chan struct{})
	f.receiveBlock = unblock
	f.packet = []byte{0x45}
	d := testWintun(t, f)
	readDone := make(chan error, 1)
	go func() { _, err := d.Read(make([]byte, 32)); readDone <- err }()
	select {
	case <-f.receiveEntered:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("read did not enter")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- d.Close() }()
	select {
	case <-d.done:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("close did not start")
	}
	f.mu.Lock()
	ended := f.ended
	f.mu.Unlock()
	close(unblock)
	if ended != 0 {
		t.Fatal("session ended before read drained")
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("read stuck")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close stuck")
	}
	if _, err := d.Read(make([]byte, 32)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("post-close read: %v", err)
	}
	if _, err := d.Write([]byte{0x45}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("post-close write: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if f.ended != 1 || f.closed != 1 || f.unloaded != 1 || f.afterEnd != 0 || strings.Join(f.order, ",") != "create,release,end,close" {
		t.Fatalf("teardown order: %+v", f)
	}
}

// TestWintunCloseWakesWaiters unblocks waiting and queued readers without ending twice.
func TestWintunCloseWakesWaiters(t *testing.T) {
	f := newFakeWintun(t)
	d := testWintun(t, f)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := d.Read(make([]byte, 32)); results <- err }()
	}
	select {
	case <-f.receiveEntered:
	case <-time.After(time.Second):
		t.Fatal("read did not enter")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed read: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("reader stuck")
		}
	}
	if f.afterEnd != 0 || f.ended != 1 {
		t.Fatalf("session lifetime: %+v", f)
	}
}
