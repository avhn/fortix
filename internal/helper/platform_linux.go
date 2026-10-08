//go:build linux

package helper

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// socketPeer retrieves immutable credentials attached to a Linux Unix connection.
// Kernel failures propagate without accepting any peer-provided identity.
func socketPeer(fd int) (Peer, error) {
	p, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Peer{}, err
	}
	return Peer{UID: p.Uid, GID: p.Gid}, nil
}

// trustedLibraries needs no Mach-O inspection on Linux, where system packages own
// the executable and loader paths. Executable and ancestor checks run on both OSes.
func trustedLibraries(_ string) error { return nil }

// processStart combines the kernel boot identity with process start ticks, so stale
// journals cannot match a reused PID after a reboot. Read/format failures propagate
// instead of falling back to a weaker PID-only or boot-relative identity.
func processStart(pid int) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	start, _, err := parseProcessStat(data)
	if err != nil {
		return "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	identity := strings.TrimSpace(string(boot))
	if len(identity) != 36 {
		return "", errors.New("kernel boot identity unavailable")
	}
	return identity + ":" + start, nil
}

// waitChild blocks on child exit without reaping the reserved PID. Interrupts are
// retried; an unavailable wait syscall falls back to conservative kernel inspection.
// True confirms exit with the PID reserved; an already-reaped child returns false.
func waitChild(pid int) bool {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err == nil {
			return true
		}
		if errors.Is(err, unix.ECHILD) {
			return false
		}
		if !errors.Is(err, unix.EINTR) {
			return waitUntilFinished(pid, processFinished, 100*time.Millisecond)
		}
	}
}

// processFinished inspects a child without reaping it, preserving its PID until
// the supervisor has signalled its group. Read or parse failures propagate unchanged.
func processFinished(pid int) (bool, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false, err
	}
	_, exited, err := parseProcessStat(data)
	return exited, err
}
