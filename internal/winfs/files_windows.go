//go:build windows

package winfs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Root keeps every ancestor open without delete sharing and resolves children by handle.
// The volume serial is pinned at the drive root; mount points and reparse points are refused.
// Close must not race with another operation on this root.
type Root struct {
	handles []windows.Handle
	volume  uint32
	mu      sync.Mutex
}

// ValidPath accepts canonical local drive paths, excluding devices, streams and traversal.
// Reserved names and trailing dots or spaces are rejected to prevent Win32 aliases.
func ValidPath(path string) bool {
	if !utf8.ValidString(path) || len(path) < 3 || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path[1:3] != `:\` ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path[2:], `:/`) || strings.ContainsFunc(path, unicode.IsControl) {
		return false
	}
	if len(path) == 3 {
		return true
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if !validName(part) {
			return false
		}
	}
	return true
}

// validName limits relative opens to one ordinary component, with no normalization aliases.
func validName(name string) bool {
	if !utf8.ValidString(name) || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:*?"<>|`) || strings.ContainsFunc(name, unicode.IsControl) || strings.TrimRight(name, ". ") != name {
		return false
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	runes := []rune(base)
	return !(len(runes) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && strings.ContainsRune("123456789¹²³", runes[3]))
}

// OpenRoot pins a real local directory and all ancestors without changing their security.
// Call CheckSecurity on Handle before treating an existing root as protected storage.
func OpenRoot(path string) (*Root, error) { return openRoot(path, nil) }

// SecureDirectory creates missing components with p, then requires p on the final root.
// Existing ancestors are never chmod-equivalent targets or adopted as owned storage.
func SecureDirectory(path string, p Policy) (*Root, error) { return openRoot(path, &p) }

// openRoot starts at the drive root and walks each component relative to its pinned parent.
func openRoot(path string, policy *Policy) (root *Root, err error) {
	if !ValidPath(path) {
		return nil, errors.New("winfs: path must be a canonical local drive path")
	}
	name, err := windows.UTF16PtrFromString(path[:3])
	if err != nil {
		return nil, err
	}
	driveType := windows.GetDriveType(name)
	if driveType != windows.DRIVE_FIXED && driveType != windows.DRIVE_RAMDISK {
		return nil, errors.New("winfs: storage must be on a fixed local volume")
	}
	h, err := windows.CreateFile(name, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	r := &Root{handles: []windows.Handle{h}}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()
	info, err := inspect(h, true, nil)
	if err != nil {
		return nil, err
	}
	r.volume = info.VolumeSerialNumber
	var volume, maxComponent, flags uint32
	if err = windows.GetVolumeInformationByHandle(h, nil, 0, &volume, &maxComponent, &flags, nil, 0); err != nil {
		return nil, err
	}
	if volume != r.volume || flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return nil, errors.New("winfs: storage requires persistent ACLs on the pinned volume")
	}
	if len(path) > 3 {
		for _, part := range strings.Split(path[3:], `\`) {
			h, err = relativeOpen(r.Handle(), part, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
				windows.FILE_OPEN, true, nil, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
			if IsNotExist(err) && policy != nil {
				var sd *windows.SECURITY_DESCRIPTOR
				sd, err = policy.Descriptor(true)
				if err != nil {
					return nil, err
				}
				// FILE_CREATE refuses a concurrent occupant rather than adopting it.
				h, err = relativeOpen(r.Handle(), part, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
					windows.FILE_CREATE, true, sd, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
			}
			if err != nil {
				return nil, err
			}
			r.handles = append(r.handles, h)
			if _, err = inspect(h, true, &r.volume); err != nil {
				return nil, err
			}
		}
	}
	if policy != nil {
		if err = CheckSecurity(r.Handle(), *policy, true); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Handle exposes the pinned final directory for handle-based security and native operations.
func (r *Root) Handle() windows.Handle { return r.handles[len(r.handles)-1] }

// Close releases children before ancestors and reports the first handle-close failure.
func (r *Root) Close() error {
	var result error
	for i := len(r.handles) - 1; i >= 0; i-- {
		result = errors.Join(result, windows.CloseHandle(r.handles[i]))
	}
	r.handles = nil
	return result
}

// IsNotExist normalizes native missing-name errors without hiding other open failures.
func IsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND)
}

// relativeOpen resolves exactly one name using NtCreateFile's RootDirectory handle.
// OPEN_REPARSE_POINT allows inspecting the link itself; no operation follows its target.
func relativeOpen(parent windows.Handle, name string, access, disposition uint32, directory bool, sd *windows.SECURITY_DESCRIPTOR, share uint32) (windows.Handle, error) {
	if !validName(name) {
		return 0, errors.New("winfs: invalid relative name")
	}
	object, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: object, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: sd}
	oa.Length = uint32(unsafe.Sizeof(oa))
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access|windows.SYNCHRONIZE, &oa, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		share, disposition, options, 0, 0)
	runtime.KeepAlive(sd)
	return handle, err
}

// attributeTagInfo mirrors FILE_ATTRIBUTE_TAG_INFO for a handle-only reparse check.
type attributeTagInfo struct {
	Attributes uint32
	ReparseTag uint32
}

// inspect checks the opened object's type, link count and volume before any content access.
// A nil volume is used only when discovering the trusted drive root's serial.
func inspect(handle windows.Handle, directory bool, volume *uint32) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, err
	}
	var tag attributeTagInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return info, err
	}
	if tag.ReparseTag != 0 || tag.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return info, errors.New("winfs: reparse points are forbidden")
	}
	typ, err := windows.GetFileType(handle)
	if err != nil {
		return info, err
	}
	if typ != windows.FILE_TYPE_DISK || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || info.NumberOfLinks != 1 || (volume != nil && info.VolumeSerialNumber != *volume) {
		return info, errors.New("winfs: unsafe file type, link count or volume")
	}
	return info, nil
}

// Open reads one verified regular file without allowing concurrent writes to its contents.
// Delete sharing permits atomic replacement while this handle retains the old file's bytes.
// The caller owns the returned file; policy checks happen before bytes can be read.
func (r *Root) Open(name string, p Policy) (*os.File, error) {
	h, err := relativeOpen(r.Handle(), name, windows.FILE_GENERIC_READ, windows.FILE_OPEN, false, nil, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE)
	if err != nil {
		return nil, err
	}
	if _, err = inspect(h, false, &r.volume); err == nil {
		err = CheckSecurity(h, p, false)
	}
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), name), nil
}

// renameInfo mirrors FILE_RENAME_INFO's variable UTF-16 name on amd64 and arm64.
type renameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// rename moves a staged handle to a single name under the pinned root.
// A missing destination is never replaced if another writer creates it first.
func (r *Root) rename(handle windows.Handle, name string, replace bool) error {
	var flags uint32
	if replace {
		// POSIX replacement preserves old read handles, which must allow delete sharing.
		flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	}
	return RenameRelative(handle, r.Handle(), name, flags)
}

// RenameRelative renames the object behind handle to one name inside the directory root,
// using FileRenameInfoEx with the given FILE_RENAME_* flags. Names containing separators,
// drive prefixes or reserved device names are rejected before any system call.
func RenameRelative(handle, root windows.Handle, name string, flags uint32) error {
	utf16, err := windows.UTF16FromString(name)
	if err != nil || !validName(name) {
		return errors.New("winfs: invalid rename destination")
	}
	var layout renameInfo
	length := (len(utf16) - 1) * 2
	// kernel32 requires at least sizeof(FILE_RENAME_INFO) plus FileNameLength bytes; the
	// struct's own FileName element then leaves room for the terminator.
	buffer := make([]byte, int(unsafe.Sizeof(layout))+length)
	info := (*renameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags, info.RootDirectory, info.FileNameLength = flags, root, uint32(length)
	copy(unsafe.Slice(&info.FileName[0], len(utf16)-1), utf16[:len(utf16)-1])
	return windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buffer[0], uint32(len(buffer)))
}

// AtomicWrite flushes a same-directory exclusive stage and publishes it by handle.
// Existing targets are security-checked and pinned throughout replacement. Missing targets
// use a no-replace rename, so a concurrent link cannot be overwritten. Cleanup never reopens
// a temporary path. The protected root limits mutation to the policy's trusted principals.
func (r *Root) AtomicWrite(ctx context.Context, name string, data []byte, p Policy) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := CheckSecurity(r.Handle(), p, true); err != nil {
		return fmt.Errorf("winfs: check directory security: %w", err)
	}
	old, err := r.Open(name, p)
	if err != nil && !IsNotExist(err) {
		return fmt.Errorf("winfs: open existing file: %w", err)
	}
	if old != nil {
		defer func() { _ = old.Close() }()
	}
	sd, err := p.Descriptor(false)
	if err != nil {
		return fmt.Errorf("winfs: build file descriptor: %w", err)
	}
	temporary := ".fortix-" + rand.Text()
	h, err := relativeOpen(r.Handle(), temporary, windows.FILE_GENERIC_WRITE|windows.FILE_GENERIC_READ|windows.DELETE,
		windows.FILE_CREATE, false, sd, windows.FILE_SHARE_READ)
	if err != nil {
		return fmt.Errorf("winfs: create staged file: %w", err)
	}
	f := os.NewFile(uintptr(h), temporary)
	published := false
	defer func() {
		if !published {
			// Mark this exact handle for deletion, even if its name was changed.
			remove := byte(1)
			err = errors.Join(err, windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &remove, 1))
		}
		err = errors.Join(err, f.Close())
	}()
	if _, err = inspect(h, false, &r.volume); err != nil {
		return fmt.Errorf("winfs: inspect staged file: %w", err)
	}
	if err = CheckSecurity(h, p, false); err != nil {
		return fmt.Errorf("winfs: check staged file security: %w", err)
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write staged file: %w", err)
	}
	if err = windows.FlushFileBuffers(h); err != nil {
		return fmt.Errorf("winfs: flush staged file: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = r.rename(h, name, old != nil); err != nil {
		return fmt.Errorf("winfs: publish staged file: %w", err)
	}
	published = true
	return nil
}
