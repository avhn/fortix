//go:build darwin || linux

package prompt

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// hiddenPassword reads a bounded canonical terminal line with echo disabled.
// Interrupt and termination signals cancel the read without terminating the process.
// The original terminal state is restored on every exit, including context cancellation;
// restoration failures discard the response and return an error.
func hiddenPassword(ctx context.Context, fd int) (password []byte, err error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer func() {
		if restoreErr := term.Restore(fd, state); restoreErr != nil {
			clear(password)
			password, err = nil, restoreErr
		}
	}()
	if err := disableEcho(fd); err != nil {
		return nil, err
	}
	return readHiddenLine(ctx, interrupted, fd)
}

// readHiddenLine polls canonical input so signals and context cancellation cannot leave
// a blocked reader behind. It never closes the caller's descriptor or echoes input.
// Empty EOF, oversized lines, and descriptor failures return no password.
func readHiddenLine(ctx, interrupted context.Context, fd int) ([]byte, error) {
	data := make([]byte, 0, 128)
	defer func() { clear(data) }()
	for len(data) <= maxInput {
		if interrupted.Err() != nil {
			return nil, ErrCancelled
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if ready == 0 {
			continue
		}
		if fds[0].Revents&unix.POLLNVAL != 0 {
			return nil, unix.EBADF
		}
		var one [1]byte
		n, err := unix.Read(fd, one[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.EOF
		}
		if one[0] == '\n' {
			line := data
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			return append([]byte(nil), line...), nil
		}
		data = append(data, one[0])
	}
	return nil, ErrFailed
}
