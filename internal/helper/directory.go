//go:build darwin || linux

package helper

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// openDirectory pins a helper-owned directory inode without following its final
// component. Writable or special directories fail before any relative file I/O.
func openDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&(0022|unix.S_ISVTX|unix.S_ISUID|unix.S_ISGID) != 0 {
		_ = f.Close()
		return nil, errors.New("unsafe helper directory")
	}
	return f, nil
}

// privateFileAt opens one filename relative to a pinned directory and verifies its
// regular-file type, private mode and ownership. Links and special files fail closed.
func privateFileAt(dir *os.File, name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) {
		_ = f.Close()
		return nil, errors.New("unsafe private file")
	}
	return f, nil
}

// directoryEntries reads a bounded independent stream from a pinned directory,
// preserving the original handle's offset and refusing unbounded state inventories.
func directoryEntries(dir *os.File, limit int) ([]os.DirEntry, error) {
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "directory")
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(limit + 1)
	if len(entries) > limit {
		return nil, errors.New("too many directory entries")
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return entries, err
}
