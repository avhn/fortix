//go:build linux

package tun

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// createPlatform opens a close-on-exec, nonblocking Linux TUN descriptor without
// packet-info headers. The kernel chooses fortix%d and removes it on close;
// persistence, address configuration, and link activation are never requested.
func createPlatform(ctx context.Context, mtu int) (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open tun device: %w", err)
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(fd)
		}
	}()
	request, err := unix.NewIfreq("fortix%d")
	if err != nil {
		return nil, fmt.Errorf("prepare tun interface: %w", err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		return nil, fmt.Errorf("create tun interface: %w", err)
	}
	name := request.Name()
	owned = false
	return newKernelDevice(ctx, fd, name, mtu, false)
}
