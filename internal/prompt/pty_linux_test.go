package prompt

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// testPTY opens an isolated Linux pseudo terminal without using the user's terminal.
// Setup failures fail the test; both descriptors close during cleanup.
func testPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

// terminalEcho reports the pseudo terminal's current echo flag, failing on ioctl errors.
func terminalEcho(t *testing.T, fd int) bool {
	t.Helper()
	state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	return state.Lflag&unix.ECHO != 0
}
