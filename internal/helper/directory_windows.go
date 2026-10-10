package helper

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/winfs"
)

// helperDirectory retains every ancestor handle while shared lifecycle code uses storage.
type helperDirectory struct {
	root     *winfs.Root
	policy   winfs.Policy
	path     string
	finalize func(Journal) error
}

// openDirectory pins existing SYSTEM-owned protected storage without repairing unsafe ACLs.
func openDirectory(path string) (*helperDirectory, error) {
	policy, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		return nil, err
	}
	root, err := winfs.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if err := winfs.CheckSecurity(root.Handle(), policy, true); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &helperDirectory{root: root, policy: policy, path: path}, nil
}

// Close releases pinned ancestors only after all dependent operations have stopped.
func (d *helperDirectory) Close() error { return d.root.Close() }

// secureDir creates missing storage with a protected SYSTEM and Administrators DACL.
func secureDir(path string, _ os.FileMode) error {
	policy, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		return err
	}
	root, err := winfs.SecureDirectory(path, policy)
	if err != nil {
		return err
	}
	return root.Close()
}

// directoryEntries bounds enumeration while ancestor handles prevent path replacement.
func directoryEntries(dir *helperDirectory, limit int) ([]os.DirEntry, error) {
	f, err := os.Open(dir.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if len(entries) > limit {
		return nil, errors.New("too many directory entries")
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return entries, err
}

// privateFileAt opens one checked regular file relative to the pinned protected directory.
func privateFileAt(dir *helperDirectory, name string, flags int) (*os.File, error) {
	if flags == os.O_RDONLY {
		return openPrivateChild(dir, name, windows.FILE_GENERIC_READ, windows.FILE_OPEN)
	}
	access := uint32(windows.FILE_GENERIC_WRITE | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
	if flags&os.O_RDWR != 0 {
		access |= windows.FILE_GENERIC_READ
	}
	disposition := uint32(windows.FILE_OPEN)
	if flags&os.O_CREATE != 0 {
		disposition = windows.FILE_OPEN_IF
	}
	if flags&os.O_EXCL != 0 {
		disposition = windows.FILE_CREATE
	}
	f, err := openPrivateChild(dir, name, access, disposition)
	if err == nil && flags&os.O_APPEND != 0 {
		_, err = f.Seek(0, io.SeekEnd)
		if err != nil {
			_ = f.Close()
		}
	}
	return f, err
}

// openPrivateChild rejects reparse points and hardlinks before any read, write or deletion.
func openPrivateChild(dir *helperDirectory, name string, access, disposition uint32) (*os.File, error) {
	if filepath.Base(name) != name || !winfs.ValidPath(`C:\`+name) {
		return nil, errors.New("invalid private filename")
	}
	sd, err := dir.policy.Descriptor(false)
	if err != nil {
		return nil, err
	}
	object, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: dir.root.Handle(), ObjectName: object, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: sd}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &oa, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	runtime.KeepAlive(sd)
	if winfs.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), name)
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &info)
	if err == nil && (info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0) {
		err = errors.New("unsafe private file")
	}
	if err == nil {
		var parent windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(dir.root.Handle(), &parent)
		if err == nil && parent.VolumeSerialNumber != info.VolumeSerialNumber {
			err = errors.New("private file changed volume")
		}
	}
	if err == nil {
		err = winfs.CheckSecurity(h, dir.policy, false)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// atomicAt publishes a flushed same-directory file with the exact protected storage policy.
func atomicAt(dir *helperDirectory, name string, data []byte, _ uint32) error {
	return dir.root.AtomicWrite(context.Background(), name, data, dir.policy)
}

// removePrivateAt deletes the verified handle rather than reopening a mutable pathname.
func removePrivateAt(dir *helperDirectory, name string) error {
	f, err := openPrivateChild(dir, name, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_OPEN)
	if err != nil {
		return err
	}
	defer f.Close()
	remove := byte(1)
	return windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfo, &remove, 1)
}

// renamePrivateAt rotates a verified handle within the pinned directory only.
func renamePrivateAt(dir *helperDirectory, from, to string) error {
	old, err := dir.root.Open(to, dir.policy)
	if err != nil && !winfs.IsNotExist(err) {
		return err
	}
	if old != nil {
		defer old.Close()
	}
	f, err := openPrivateChild(dir, from, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_OPEN)
	if err != nil {
		return err
	}
	defer f.Close()
	if filepath.Base(to) != to || strings.ContainsAny(to, `\/:`) {
		return errors.New("invalid rotation name")
	}
	return winfs.RenameRelative(windows.Handle(f.Fd()), dir.root.Handle(),
		to, windows.FILE_RENAME_REPLACE_IF_EXISTS|windows.FILE_RENAME_POSIX_SEMANTICS)
}
