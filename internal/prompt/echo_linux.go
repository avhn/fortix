package prompt

import "golang.org/x/sys/unix"

// disableEcho preserves canonical line editing and signal generation on Linux,
// suppressing all terminal echo. Descriptor and terminal setup errors propagate.
func disableEcho(fd int) error {
	state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	state.Lflag &^= unix.ECHO | unix.ECHONL
	state.Lflag |= unix.ICANON | unix.ISIG
	return unix.IoctlSetTermios(fd, unix.TCSETS, state)
}
