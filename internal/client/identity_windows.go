package client

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/winfs"
)

// serviceIdentity contains only OS-observed facts, never claims from the pipe peer.
// A process handle pins the PID when accessible; the SCM status is always rechecked after inspection.
type serviceIdentity struct {
	pipePID, servicePID      uint32
	state, serviceType       uint32
	configType               uint32
	image, binary, directory string
	localSystem              bool
}

// unquotedServiceBinary removes only paired quotes, never arguments or path aliases.
func unquotedServiceBinary(binary string) string {
	if len(binary) >= 2 && binary[0] == '"' && binary[len(binary)-1] == '"' {
		return binary[1 : len(binary)-1]
	}
	return binary
}

// validateServiceIdentity rejects an unrelated process even if it owns the expected pipe name.
// Service arguments, path aliases and sibling directories cannot stand in for the installed image.
func validateServiceIdentity(identity serviceIdentity) error {
	if identity.pipePID == 0 || identity.pipePID != identity.servicePID ||
		identity.state != windows.SERVICE_RUNNING || identity.serviceType != windows.SERVICE_WIN32_OWN_PROCESS ||
		identity.configType != windows.SERVICE_WIN32_OWN_PROCESS || !identity.localSystem {
		return errors.New("unexpected helper service identity")
	}
	binary := unquotedServiceBinary(identity.binary)
	if !winfs.ValidPath(binary) || !winfs.ValidPath(identity.image) || !winfs.ValidPath(identity.directory) ||
		!strings.EqualFold(binary, identity.image) {
		return errors.New("unexpected helper service image")
	}
	prefix := strings.TrimSuffix(identity.directory, `\`) + `\`
	if !strings.HasPrefix(strings.ToLower(identity.image), strings.ToLower(prefix)) ||
		strings.EqualFold(filepath.Clean(identity.image), identity.directory) {
		return errors.New("helper image is outside the installation directory")
	}
	return nil
}

// queryServiceProcess reads only status data using a query-only SCM service handle.
func queryServiceProcess(service windows.Handle) (windows.SERVICE_STATUS_PROCESS, error) {
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	return status, err
}

// queryServiceBinary bounds configuration allocation and copies facts while its buffer lives.
// The service account is authoritative only for the access-denied fallback, not a token mismatch.
func queryServiceBinary(service windows.Handle) (string, uint32, string, error) {
	var needed uint32
	err := windows.QueryServiceConfig(service, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed < uint32(unsafe.Sizeof(windows.QUERY_SERVICE_CONFIG{})) || needed > 64*1024 {
		return "", 0, "", errors.New("helper service configuration unavailable")
	}
	buffer := make([]byte, needed)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err := windows.QueryServiceConfig(service, config, uint32(len(buffer)), &needed); err != nil {
		return "", 0, "", err
	}
	binary, serviceType := windows.UTF16PtrToString(config.BinaryPathName), config.ServiceType
	account := windows.UTF16PtrToString(config.ServiceStartName)
	runtime.KeepAlive(buffer)
	return binary, serviceType, account, nil
}

// processIdentity retains an accessible process handle until the final SCM status recheck.
// The access-denied fallback has no handle and derives the account from SCM instead.
type processIdentity struct {
	handle      windows.Handle
	image       string
	localSystem bool
}

// nativeInspectProcess permits access-denied tests without changing a real service's DACLs.
var nativeInspectProcess = inspectProcessIdentity

// nativeProcessImage permits tests of the handle-free fallback before any protocol I/O.
var nativeProcessImage = queryProcessImageByPID

// nativeSystemInformation exposes the narrow kernel image query for bounded-buffer tests.
var nativeSystemInformation = windows.NtQuerySystemInformation

// nativeQueryDosDevice resolves the configured drive without opening the service process.
var nativeQueryDosDevice = windows.QueryDosDevice

// inspectProcessIdentity prefers the actual image and LocalSystem token over configured facts.
// On success its caller owns the process handle; all failure paths release it and the token.
func inspectProcessIdentity(pid uint32) (identity processIdentity, err error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return identity, err
	}
	defer func() {
		if err != nil {
			_ = windows.CloseHandle(process)
		}
	}()
	image := make([]uint16, 32768)
	length := uint32(len(image))
	if err = windows.QueryFullProcessImageName(process, 0, &image[0], &length); err != nil {
		return identity, err
	}
	identity.image = windows.UTF16ToString(image[:length])
	var token windows.Token
	if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return identity, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return identity, err
	}
	identity.handle = process
	identity.localSystem = user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
	return identity, nil
}

// systemProcessIDInformation is the native SystemProcessIdInformation query layout.
// ImageName points at caller-owned bounded UTF-16 storage, not a kernel-owned allocation.
type systemProcessIDInformation struct {
	processID uintptr
	imageName windows.NTUnicodeString
}

// queryProcessImageByPID compares the kernel's native image with the configured DOS path.
// This query needs no process/token handle; any unavailable or ambiguous mapping fails closed.
func queryProcessImageByPID(pid uint32, binary string) (string, error) {
	binary = unquotedServiceBinary(binary)
	if pid == 0 || !winfs.ValidPath(binary) {
		return "", errors.New("unexpected helper service image")
	}
	buffer := make([]uint16, 32767)
	info := systemProcessIDInformation{processID: uintptr(pid), imageName: windows.NTUnicodeString{
		MaximumLength: uint16(len(buffer) * 2), Buffer: &buffer[0],
	}}
	if err := nativeSystemInformation(windows.SystemProcessIdInformation, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil); err != nil {
		runtime.KeepAlive(buffer)
		return "", err
	}
	if info.imageName.Buffer != &buffer[0] || info.imageName.Length == 0 || info.imageName.Length%2 != 0 ||
		int(info.imageName.Length) > len(buffer)*2 {
		return "", errors.New("invalid helper process image length")
	}
	image := windows.UTF16ToString(buffer[:info.imageName.Length/2])
	runtime.KeepAlive(buffer)
	drive, err := windows.UTF16PtrFromString(binary[:2])
	if err != nil {
		return "", err
	}
	device := make([]uint16, 32768)
	n, err := nativeQueryDosDevice(drive, &device[0], uint32(len(device)))
	if err != nil {
		return "", err
	}
	if n == 0 || n > uint32(len(device)) {
		return "", errors.New("invalid helper image drive mapping")
	}
	volume := windows.UTF16ToString(device[:n])
	if !strings.HasPrefix(strings.ToLower(volume), `\device\`) ||
		!strings.EqualFold(image, volume+binary[2:]) {
		return "", errors.New("unexpected helper service image")
	}
	return binary, nil
}

// queryProcessIdentity falls back only when the LocalSystem process/token DACL denies inspection.
// SCM must explicitly name LocalSystem, and the kernel must independently confirm the image.
// Other errors and observed non-System tokens never become configured-account successes.
func queryProcessIdentity(pid uint32, binary, account string) (processIdentity, error) {
	identity, err := nativeInspectProcess(pid)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return identity, err
	}
	if !strings.EqualFold(account, "LocalSystem") {
		return processIdentity{}, errors.New("unexpected helper service account")
	}
	image, err := nativeProcessImage(pid, binary)
	if err != nil {
		return processIdentity{}, err
	}
	return processIdentity{image: image, localSystem: true}, nil
}

// verifyPipeServer cross-checks pipe ownership, SCM status/configuration, process image and account.
// Every handle is least-access and closed before returning; failure occurs before any protocol I/O.
func verifyPipeServer(ctx context.Context, conn net.Conn) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pipe, ok := conn.(*pipeConn)
	if !ok {
		return errors.New("transport has no verifiable pipe handle")
	}
	var identity serviceIdentity
	if err := windows.GetNamedPipeServerProcessId(pipe.handle, &identity.pipePID); err != nil {
		return err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(paths.HelperServiceName)
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)
	status, err := queryServiceProcess(service)
	if err != nil {
		return err
	}
	identity.servicePID, identity.state, identity.serviceType = status.ProcessId, status.CurrentState, status.ServiceType
	if identity.pipePID == 0 || identity.pipePID != identity.servicePID || identity.state != windows.SERVICE_RUNNING || identity.serviceType != windows.SERVICE_WIN32_OWN_PROCESS {
		return errors.New("pipe owner is not the running helper service")
	}
	var account string
	identity.binary, identity.configType, account, err = queryServiceBinary(service)
	if err != nil {
		return err
	}
	installed, err := paths.Installation("windows", paths.Override{})
	if err != nil {
		return err
	}
	identity.directory = installed.BinaryDir
	process, err := queryProcessIdentity(identity.pipePID, identity.binary, account)
	if err != nil {
		return err
	}
	if process.handle != 0 {
		defer windows.CloseHandle(process.handle)
	}
	identity.image, identity.localSystem = process.image, process.localSystem
	// Recheck after either inspection path so a stopped or replaced service cannot be accepted.
	current, err := queryServiceProcess(service)
	if err != nil {
		return err
	}
	if current.ProcessId != status.ProcessId || current.CurrentState != status.CurrentState || current.ServiceType != status.ServiceType {
		return errors.New("helper service changed during verification")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return validateServiceIdentity(identity)
}
