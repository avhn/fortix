package network

import "golang.org/x/sys/unix"

// renameNoReplace atomically moves a staged file into place and fails with EEXIST
// instead of replacing an existing entry. A rename is used rather than a hard link
// because configd stops tracking resolver files that were published by linking, so
// their later removal would leave split DNS active after disconnect.
func renameNoReplace(dirfd int, from, to string) error {
	return unix.RenameatxNp(dirfd, from, dirfd, to, unix.RENAME_EXCL)
}
