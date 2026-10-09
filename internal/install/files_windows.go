package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/tun"
	"github.com/avhn/fortix/internal/winfs"
)

const maxBinaryBytes = 256 * 1024 * 1024

// binaryPolicy makes binaries administrator-owned and grants ordinary users only read and execute.
func binaryPolicy() (winfs.Policy, error) {
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return winfs.Policy{}, err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	return winfs.Policy{Owner: owner, Administrators: true, Extra: users, Rights: windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE}, err
}

// createDirectory pins the existing parent before creating one child with its final protected DACL.
// An existing foreign owner or reparse point is rejected, never repaired or adopted.
func createDirectory(path string, policy winfs.Policy) (*winfs.Root, bool, error) {
	parent, err := winfs.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, false, err
	}
	defer parent.Close()
	sd, err := policy.Descriptor(true)
	if err != nil {
		return nil, false, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(name, &attributes)
	runtime.KeepAlive(sd)
	created := err == nil
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, false, err
	}
	root, err := winfs.SecureDirectory(path, policy)
	if err != nil && created {
		err = errors.Join(err, os.Remove(path))
	}
	return root, created, err
}

// sourceBytes pins the complete source path and rejects directories, links and concurrent writers.
func sourceBytes(path string) ([]byte, error) {
	if !winfs.ValidPath(path) {
		return nil, errors.New("source must be a canonical local file")
	}
	parent, err := winfs.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name, _ := windows.UTF16PtrFromString(path)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 || info.NumberOfLinks != 1 {
		return nil, errors.New("source must be a regular single-link file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBinaryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxBinaryBytes {
		return nil, errors.New("invalid source size")
	}
	return data, nil
}

// binarySources verifies all payloads, including the architecture-pinned DLL, before stopping service.
func binarySources(helper string) (map[string][]byte, error) {
	directory := filepath.Dir(helper)
	if !equalPath(helper, filepath.Join(directory, "fortix-helper.exe")) {
		return nil, errors.New("run the installer from fortix-helper.exe")
	}
	result := make(map[string][]byte)
	for _, name := range []string{"fortix.exe", "fortix-helper.exe", "wintun.dll", "FortixApp.exe"} {
		data, err := sourceBytes(filepath.Join(directory, name))
		if name == "FortixApp.exe" && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if name == "wintun.dll" {
			if err := tun.VerifyWintunHash(bytes.NewReader(data), runtime.GOARCH); err != nil {
				return nil, err
			}
		}
		result[name] = data
	}
	return result, nil
}

// protectedBytes verifies an existing destination's owner, DACL and link metadata before reading it.
func protectedBytes(root *winfs.Root, name string, policy winfs.Policy) ([]byte, bool, error) {
	file, err := root.Open(name, policy)
	if winfs.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBinaryBytes+1))
	if err != nil {
		return nil, true, err
	}
	if len(data) > maxBinaryBytes {
		return nil, true, errors.New("installed file exceeds size limit")
	}
	return data, true, nil
}

// publish stages with the final ACL, flushes, then atomically replaces the checked destination.
// The pinned root prevents ancestor swaps; only administrators and SYSTEM can mutate its children.
func publish(ctx context.Context, root *winfs.Root, directory, name string, data []byte, policy winfs.Policy) error {
	if err := root.AtomicWrite(ctx, name, data, policy); err != nil {
		return err
	}
	copy, exists, err := protectedBytes(root, name, policy)
	if err != nil {
		return err
	}
	if !exists || sha256.Sum256(copy) != sha256.Sum256(data) {
		return errors.New("installed file hash mismatch")
	}
	return nil
}

// removeProtected checks the object immediately before deletion under its pinned protected parent.
func removeProtected(root *winfs.Root, directory, name string, policy winfs.Policy) error {
	file, err := root.Open(name, policy)
	if winfs.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	return os.Remove(filepath.Join(directory, name))
}
