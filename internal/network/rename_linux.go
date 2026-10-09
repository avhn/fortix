package network

import "golang.org/x/sys/unix"

// renameNoReplace atomically moves a staged file into place and fails with EEXIST
// instead of replacing an existing entry.
func renameNoReplace(dirfd int, from, to string) error {
	return unix.Renameat2(dirfd, from, dirfd, to, unix.RENAME_NOREPLACE)
}
