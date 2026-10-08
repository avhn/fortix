package prompt

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// testPTY opens an isolated macOS pseudo terminal without using the user's terminal.
// Setup failures fail the test; both descriptors close during cleanup.
func testPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	for _, request := range []uint{unix.TIOCPTYGRANT, unix.TIOCPTYUNLK} {
		if err := unix.IoctlSetInt(int(master.Fd()), request, 0); err != nil {
			t.Fatal(err)
		}
	}
	var name [128]byte
	// x/sys has no public wrapper for the 128-byte TIOCPTYGNAME buffer.
	//nolint:staticcheck // This test-only ioctl needs a buffer larger than the exported typed wrappers.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, master.Fd(), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
		t.Fatal(errno)
	}
	end := 0
	for end < len(name) && name[end] != 0 {
		end++
	}
	slave, err := os.OpenFile(string(name[:end]), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

// terminalEcho reports the pseudo terminal's current echo flag, failing on ioctl errors.
func terminalEcho(t *testing.T, fd int) bool {
	t.Helper()
	state, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		t.Fatal(err)
	}
	return state.Lflag&unix.ECHO != 0
}
