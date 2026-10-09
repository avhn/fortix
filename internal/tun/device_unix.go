//go:build darwin || linux

package tun

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// newKernelDevice takes ownership of an already-created kernel descriptor,
// captures its interface index, and registers nonblocking I/O with the runtime
// poller. Every failure closes fd; cancellation closes the resulting device.
func newKernelDevice(ctx context.Context, fd int, name string, mtu int, prefix bool) (Device, error) {
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(fd)
		}
	}()
	link, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("get tunnel interface index: %w", err)
	}
	// A blocking file would make Close wait for a kernel packet instead of
	// interrupting Read. Both platforms must hand the poller a nonblocking fd.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("set tunnel nonblocking: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	owned = false
	device, err := newPacketDevice(ctx, file, name, link.Index, mtu, prefix)
	if err != nil {
		return nil, err
	}
	return device, nil
}
