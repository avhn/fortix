package install

import (
	"context"
	"errors"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockInstallation serializes install and removal across sessions using an administrator-owned mutex.
// The caller pins its OS thread until unlock because Windows mutex ownership is thread-specific.
func lockInstallation(ctx context.Context) (func() error, error) {
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(`Global\Fortix.Install`)
	handle, err := windows.CreateMutexEx(&attributes, name, 0, windows.SYNCHRONIZE|windows.MUTEX_MODIFY_STATE|windows.READ_CONTROL)
	runtime.KeepAlive(sd)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}
	security, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	owner, _, err := security.Owner()
	if err != nil || owner == nil || (!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
		windows.CloseHandle(handle)
		return nil, errors.New("foreign installation lock")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			windows.CloseHandle(handle)
			return nil, err
		}
		state, err := windows.WaitForSingleObject(handle, 100)
		if err != nil {
			windows.CloseHandle(handle)
			return nil, err
		}
		if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
			return func() error { return errors.Join(windows.ReleaseMutex(handle), windows.CloseHandle(handle)) }, nil
		}
	}
}
