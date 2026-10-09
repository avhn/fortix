//go:build darwin

package tun

import (
	"context"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// Darwin's kernel-control protocol and utun interface-name socket option are
// stable ABI values not exported by the syscall bindings.
const (
	sysprotoControl = 2
	utunOptIfName   = 2
)

// createPlatform opens a nonblocking utun control socket with kernel-selected
// unit zero. All setup failures release the socket, removing the transient link.
func createPlatform(ctx context.Context, mtu int) (Device, error) {
	// Darwin lacks SOCK_CLOEXEC. Hold the fork lock until FD_CLOEXEC is set.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("open utun control socket: %w", err)
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(fd)
		}
	}()

	var info unix.CtlInfo
	copy(info.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &info); err != nil {
		return nil, fmt.Errorf("resolve utun control: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		return nil, fmt.Errorf("connect utun control: %w", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfName)
	if err != nil {
		return nil, fmt.Errorf("get utun interface name: %w", err)
	}
	owned = false
	return newKernelDevice(ctx, fd, name, mtu, true)
}
