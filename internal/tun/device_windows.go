package tun

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const wintunRingCapacity = 0x400000

// Allocation identifies an owned adapter before creation and after LUID discovery.
// The hook must durably upsert by GUID, preserving intent when LUID is still zero.
// Records survive Close and failed creation until network recovery removes them.
type Allocation struct {
	GUID  windows.GUID
	Name  string
	Nonce string
	LUID  uint64
}

// wintunConfiguration holds process-wide helper configuration, snapshotted per creation.
var wintunConfiguration struct {
	sync.RWMutex
	path string
	hook func(Allocation) error
}

// SetAllocationHook installs the durable allocation ledger writer. A nil hook
// disables creation. The helper must set it before accepting tunnel requests.
func SetAllocationHook(hook func(Allocation) error) {
	wintunConfiguration.Lock()
	defer wintunConfiguration.Unlock()
	wintunConfiguration.hook = hook
}

// SetDLLPath configures an absolute installed DLL path, never a search-path name.
// Without an override the DLL is resolved next to the running helper executable.
func SetDLLPath(path string) error {
	if err := validateDLLPath(path); err != nil {
		return err
	}
	wintunConfiguration.Lock()
	defer wintunConfiguration.Unlock()
	wintunConfiguration.path = path
	return nil
}

// createPlatform loads the pinned driver API only after helper configuration exists.
func createPlatform(ctx context.Context, mtu int) (Device, error) {
	wintunConfiguration.RLock()
	path, hook := wintunConfiguration.path, wintunConfiguration.hook
	wintunConfiguration.RUnlock()
	if hook == nil {
		return nil, errors.New("wintun allocation hook is required")
	}
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(filepath.Dir(exe), "wintun.dll")
	}
	api, err := loadWintun(path)
	if err != nil {
		return nil, err
	}
	device, err := newWintunDevice(ctx, mtu, api, hook)
	if err != nil {
		// A typed nil inside Device would make the backend attempt to close it.
		return nil, err
	}
	return device, nil
}

// wintunBinding isolates borrowed packet storage and DLL ownership for lifecycle tests.
type wintunBinding interface {
	create(string, *windows.GUID) (uintptr, error)
	identity(uintptr) (uint64, uint32, error)
	start(uintptr, uint32) (uintptr, error)
	readEvent(uintptr) (windows.Handle, error)
	receive(uintptr) ([]byte, error)
	release(uintptr, []byte)
	allocate(uintptr, uint32) ([]byte, error)
	send(uintptr, []byte)
	end(uintptr)
	closeAdapter(uintptr)
	unload() error
}

// wintunDevice retains the adapter until Close and drains directional I/O before
// ending its session. The read event is borrowed; only the stop event is owned.
type wintunDevice struct {
	api                  wintunBinding
	allocation           Allocation
	adapter, session     uintptr
	index, mtu           int
	readEvent, stopEvent windows.Handle
	readGate, writeGate  chan struct{}
	done                 chan struct{}
	life                 sync.RWMutex
	closeOnce            sync.Once
	closeErr             error
}

// Compile-time contracts keep packet cancellation available to the native pump.
var (
	_ Device              = (*wintunDevice)(nil)
	_ packetContextReader = (*wintunDevice)(nil)
	_ packetContextWriter = (*wintunDevice)(nil)
)

// newWintunDevice takes ownership of api, persisting intent before any adapter call.
func newWintunDevice(ctx context.Context, mtu int, api wintunBinding, hook func(Allocation) error) (_ *wintunDevice, err error) {
	var adapter, session uintptr
	var stop windows.Handle
	defer func() {
		if err != nil {
			if session != 0 {
				api.end(session)
			}
			if adapter != 0 {
				api.closeAdapter(adapter)
			}
			if stop != 0 {
				_ = windows.CloseHandle(stop)
			}
			err = errors.Join(err, api.unload())
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = validateMTU(mtu); err != nil {
		return nil, err
	}
	if hook == nil {
		return nil, errors.New("wintun allocation hook is required")
	}
	guid, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	allocation := Allocation{GUID: guid, Nonce: hex.EncodeToString(nonce[:])}
	allocation.Name = "fortix-" + allocation.Nonce[:16]
	if err = hook(allocation); err != nil {
		return nil, fmt.Errorf("persist wintun allocation: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	adapter, err = api.create(allocation.Name, &allocation.GUID)
	if err != nil {
		return nil, err
	}
	luid, index, err := api.identity(adapter)
	if err != nil {
		return nil, err
	}
	allocation.LUID = luid
	if err = hook(allocation); err != nil {
		return nil, fmt.Errorf("persist wintun identity: %w", err)
	}
	session, err = api.start(adapter, wintunRingCapacity)
	if err != nil {
		return nil, err
	}
	event, err := api.readEvent(session)
	if err != nil {
		return nil, err
	}
	stop, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	d := &wintunDevice{api: api, allocation: allocation, adapter: adapter, session: session,
		index: int(index), mtu: mtu, readEvent: event, stopEvent: stop,
		readGate: make(chan struct{}, 1), writeGate: make(chan struct{}, 1), done: make(chan struct{})}
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = d.Close()
			case <-d.done:
			}
		}()
	}
	return d, nil
}

// Name returns the allocation's immutable interface alias.
func (d *wintunDevice) Name() string { return d.allocation.Name }

// Index returns the interface index captured before caller-owned configuration.
func (d *wintunDevice) Index() int { return d.index }

// MTU returns the requested packet limit, not a live adapter query.
func (d *wintunDevice) MTU() int { return d.mtu }

// Allocation returns retained ledger identity, including after Close.
func (d *wintunDevice) Allocation() Allocation { return d.allocation }

// Read receives one packet without a caller deadline.
func (d *wintunDevice) Read(p []byte) (int, error) { return d.ReadContext(context.Background(), p) }

// Write sends one packet with a bounded ring-full retry budget.
func (d *wintunDevice) Write(p []byte) (int, error) { return d.WriteContext(context.Background(), p) }

// enter serializes a direction cancellably and pins the session against Close.
func (d *wintunDevice) enter(ctx context.Context, gate chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		return os.ErrClosed
	case gate <- struct{}{}:
	}
	d.life.RLock()
	if err := d.interrupted(ctx); err != nil {
		d.leave(gate)
		return err
	}
	return nil
}

// leave releases session ownership before allowing the next directional operation.
func (d *wintunDevice) leave(gate chan struct{}) { d.life.RUnlock(); <-gate }

// interrupted gives caller cancellation precedence over concurrent device shutdown.
func (d *wintunDevice) interrupted(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-d.done:
		return os.ErrClosed
	default:
		return nil
	}
}

// ReadContext copies and releases each received packet exactly once. Cancellation
// wakes a private event and never closes the session or its borrowed read event.
func (d *wintunDevice) ReadContext(ctx context.Context, p []byte) (int, error) {
	if err := d.enter(ctx, d.readGate); err != nil {
		return 0, err
	}
	defer d.leave(d.readGate)
	var cancelEvent windows.Handle
	for {
		if err := d.interrupted(ctx); err != nil {
			return 0, err
		}
		packet, err := d.api.receive(d.session)
		if err == nil {
			// Validation and copying finish before the borrowed storage is released.
			packetErr := validatePacket(packet, d.mtu)
			n := 0
			if packetErr == nil {
				if len(p) < len(packet) {
					packetErr = io.ErrShortBuffer
				} else {
					n = copy(p, packet)
				}
			}
			d.api.release(d.session, packet)
			return n, packetErr
		}
		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return 0, err
		}
		if cancelEvent == 0 {
			// Ready packets need no kernel event or cancellation callback allocation.
			cancelEvent, err = windows.CreateEvent(nil, 1, 0, nil)
			if err != nil {
				return 0, err
			}
			joined := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { _ = windows.SetEvent(cancelEvent); close(joined) })
			defer func() {
				if !stop() {
					<-joined
				}
				_ = windows.CloseHandle(cancelEvent)
			}()
		}
		// A finite fallback also guarantees shutdown if signalling an event fails.
		_, err = windows.WaitForMultipleObjects([]windows.Handle{cancelEvent, d.stopEvent, d.readEvent}, false, 100)
		if err != nil {
			return 0, err
		}
	}
}

// WriteContext validates before allocation, then retries ring saturation for at
// most one second. Once allocated, a packet must be sent even if cancellation races.
func (d *wintunDevice) WriteContext(ctx context.Context, p []byte) (int, error) {
	if err := validatePacket(p, d.mtu); err != nil {
		return 0, err
	}
	if err := d.enter(ctx, d.writeGate); err != nil {
		return 0, err
	}
	defer d.leave(d.writeGate)
	for attempt := 0; attempt < 100; attempt++ {
		if err := d.interrupted(ctx); err != nil {
			return 0, err
		}
		packet, err := d.api.allocate(d.session, uint32(len(p)))
		if err == nil {
			copy(packet, p)
			d.api.send(d.session, packet)
			return len(p), nil
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return 0, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-d.done:
			timer.Stop()
			return 0, os.ErrClosed
		case <-timer.C:
		}
	}
	return 0, windows.ERROR_BUFFER_OVERFLOW
}

// Close prevents new I/O, wakes and joins active operations, then ends the session
// before closing the adapter and unloading the DLL. Ledger identity is retained.
func (d *wintunDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		_ = windows.SetEvent(d.stopEvent)
		d.life.Lock()
		defer d.life.Unlock()
		d.api.end(d.session)
		d.api.closeAdapter(d.adapter)
		d.closeErr = errors.Join(windows.CloseHandle(d.stopEvent), d.api.unload())
	})
	return d.closeErr
}
