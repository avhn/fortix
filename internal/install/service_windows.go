package install

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/winfs"
)

const (
	managerCreateAccess  = windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_CREATE_SERVICE
	serviceQueryAccess   = windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG | windows.SERVICE_INTERROGATE
	serviceUpdateAccess  = serviceQueryAccess | windows.READ_CONTROL | windows.SERVICE_START | windows.SERVICE_STOP
	serviceInstallAccess = serviceQueryAccess | windows.SERVICE_START | windows.SERVICE_STOP | windows.DELETE | windows.WRITE_DAC | windows.SERVICE_CHANGE_CONFIG | windows.READ_CONTROL
	serviceSDDL          = "O:BAD:P(A;;0xf01ff;;;SY)(A;;0xf01ff;;;BA)(A;;0x85;;;BU)"
)

// scmAPI exposes only service acquisition so tests can assert the actual requested access masks.
type scmAPI interface {
	openManager(uint32) (windows.Handle, error)
	openService(windows.Handle, uint32) (windows.Handle, error)
	createService(windows.Handle, string, uint32) (windows.Handle, error)
}

// nativeSCM binds low-level SCM calls without the all-access service-manager defaults.
type nativeSCM struct{}

// openManager requests only connection or creation privileges needed by this operation.
func (nativeSCM) openManager(access uint32) (windows.Handle, error) {
	return windows.OpenSCManager(nil, nil, access)
}

// openService requests an explicit operation-specific mask for the fixed service name.
func (nativeSCM) openService(manager windows.Handle, access uint32) (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString(paths.HelperServiceName)
	return windows.OpenService(manager, name, access)
}

// createService registers a quoted absolute executable as an own-process LocalSystem service.
func (nativeSCM) createService(manager windows.Handle, image string, access uint32) (windows.Handle, error) {
	if !winfs.ValidPath(image) {
		return 0, errors.New("invalid service image")
	}
	name, _ := windows.UTF16PtrFromString(paths.HelperServiceName)
	display, _ := windows.UTF16PtrFromString("Fortix Helper")
	binary, _ := windows.UTF16PtrFromString(`"` + image + `"`)
	account, _ := windows.UTF16PtrFromString("LocalSystem")
	return windows.CreateService(manager, name, display, access, windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_AUTO_START, windows.SERVICE_ERROR_NORMAL, binary, nil, nil, nil, account, nil)
}

// acquireService is shared by real installation and access-mask tests; callers close both handles.
func acquireService(api scmAPI, create bool) (windows.Handle, windows.Handle, error) {
	access := uint32(windows.SC_MANAGER_CONNECT)
	if create {
		access = managerCreateAccess
	}
	manager, err := api.openManager(access)
	if err != nil {
		return 0, 0, err
	}
	service, err := api.openService(manager, serviceUpdateAccess)
	return manager, service, err
}

// createHelperService centralizes the creation mask used by installation and access-policy tests.
func createHelperService(api scmAPI, manager windows.Handle, directory string) (windows.Handle, error) {
	return api.createService(manager, filepath.Join(directory, "fortix-helper.exe"), serviceInstallAccess)
}

// serviceConfig contains copied facts, independent of the variable-length native buffer.
type serviceConfig struct {
	image, account string
	kind, start    uint32
}

// readServiceConfig bounds the SCM allocation before dereferencing its strings.
func readServiceConfig(service windows.Handle) (serviceConfig, error) {
	var needed uint32
	err := windows.QueryServiceConfig(service, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed < uint32(unsafe.Sizeof(windows.QUERY_SERVICE_CONFIG{})) || needed > 65536 {
		return serviceConfig{}, errors.New("service configuration unavailable")
	}
	data := make([]byte, needed)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&data[0]))
	if err = windows.QueryServiceConfig(service, config, needed, &needed); err != nil {
		return serviceConfig{}, err
	}
	result := serviceConfig{image: windows.UTF16PtrToString(config.BinaryPathName), account: windows.UTF16PtrToString(config.ServiceStartName), kind: config.ServiceType, start: config.StartType}
	runtime.KeepAlive(data)
	return result, nil
}

// validateService refuses foreign images, arguments and privilege configurations before any stop.
// Existing installations must use the same canonical helper path; sibling applications are not adopted.
func validateService(config serviceConfig, directory string) error {
	image := config.image
	if len(image) >= 2 && image[0] == '"' && image[len(image)-1] == '"' {
		image = image[1 : len(image)-1]
	}
	if !winfs.ValidPath(image) || !strings.EqualFold(image, filepath.Join(directory, "fortix-helper.exe")) ||
		config.kind != windows.SERVICE_WIN32_OWN_PROCESS || config.account != "LocalSystem" || config.start != windows.SERVICE_AUTO_START {
		return errors.New("refusing an existing service with a foreign image or configuration")
	}
	return nil
}

// queryService returns the SCM state without requiring process or control privileges.
func queryService(service windows.Handle) (windows.SERVICE_STATUS, error) {
	var status windows.SERVICE_STATUS
	err := windows.QueryServiceStatus(service, &status)
	return status, err
}

// waitService observes a bounded transition and rejects unsuccessful service startup immediately.
func waitService(ctx context.Context, service windows.Handle, want uint32) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := queryService(service)
		if err != nil {
			return err
		}
		if status.CurrentState == want {
			return nil
		}
		if want == windows.SERVICE_RUNNING && status.CurrentState == windows.SERVICE_STOPPED {
			return errors.New("helper service stopped during startup")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// stopService waits for shutdown and refuses to replace files after an incomplete cleanup.
func stopService(ctx context.Context, service windows.Handle) error {
	return stopServiceWith(ctx, service, serviceStopOps{queryService, windows.ControlService, waitService})
}

// serviceStopOps isolates shutdown observations and controls for deterministic failure tests.
type serviceStopOps struct {
	query   func(windows.Handle) (windows.SERVICE_STATUS, error)
	control func(windows.Handle, uint32, *windows.SERVICE_STATUS) error
	wait    func(context.Context, windows.Handle, uint32) error
}

// stopServiceWith accepts historical failures but refuses incomplete cleanup from this shutdown.
func stopServiceWith(ctx context.Context, service windows.Handle, ops serviceStopOps) error {
	status, err := ops.query(service)
	if err != nil {
		return err
	}
	if status.CurrentState == windows.SERVICE_STOPPED {
		return nil
	}
	if status.CurrentState != windows.SERVICE_STOP_PENDING {
		if err = ops.control(service, windows.SERVICE_CONTROL_STOP, &status); err != nil {
			return err
		}
	}
	if err = ops.wait(ctx, service, windows.SERVICE_STOPPED); err != nil {
		return err
	}
	status, err = ops.query(service)
	if err != nil {
		return err
	}
	if status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
		return errors.New("helper cleanup was incomplete; installation stopped")
	}
	return nil
}

// startService waits for listener readiness, not merely successful process creation.
func startService(ctx context.Context, service windows.Handle) error {
	if err := windows.StartService(service, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return waitService(ctx, service, windows.SERVICE_RUNNING)
}

// configureService sets recovery policy and a protected query-only grant for ordinary users.
func configureService(service windows.Handle) error {
	text, _ := windows.UTF16PtrFromString("Fortix protected VPN helper")
	description := windows.SERVICE_DESCRIPTION{Description: text}
	if err := windows.ChangeServiceConfig2(service, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&description))); err != nil {
		return err
	}
	actions := []windows.SC_ACTION{{Type: windows.SC_ACTION_RESTART, Delay: 5000}, {Type: windows.SC_ACTION_RESTART, Delay: 15000}, {Type: windows.SC_ACTION_NONE}}
	failure := windows.SERVICE_FAILURE_ACTIONS{ResetPeriod: 86400, ActionsCount: uint32(len(actions)), Actions: &actions[0]}
	if err := windows.ChangeServiceConfig2(service, windows.SERVICE_CONFIG_FAILURE_ACTIONS, (*byte)(unsafe.Pointer(&failure))); err != nil {
		return err
	}
	flag := windows.SERVICE_FAILURE_ACTIONS_FLAG{FailureActionsOnNonCrashFailures: 1}
	if err := windows.ChangeServiceConfig2(service, windows.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, (*byte)(unsafe.Pointer(&flag))); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(serviceSDDL)
	if err != nil {
		return err
	}
	// SetServiceObjectSecurity takes a security descriptor, not an ACL pointer.
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("SetServiceObjectSecurity")
	ok, _, callErr := proc.Call(uintptr(service), uintptr(windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(sd)))
	runtime.KeepAlive(sd)
	if ok == 0 {
		return callErr
	}
	return nil
}

// checkServiceSecurity refuses to upgrade a service whose ordinary users can control its process.
func checkServiceSecurity(service windows.Handle) error {
	sd, err := windows.GetSecurityInfo(service, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	actual, _, err := sd.DACL()
	if err != nil || actual == nil {
		return errors.New("service DACL unavailable")
	}
	expected, err := windows.SecurityDescriptorFromString(serviceSDDL)
	if err != nil {
		return err
	}
	want, _, err := expected.DACL()
	if err != nil {
		return err
	}
	if actual.AceCount != want.AceCount {
		return errors.New("unexpected service DACL")
	}
	for n := uint32(0); n < uint32(want.AceCount); n++ {
		var a, b *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(actual, n, &a); err != nil {
			return err
		}
		if err := windows.GetAce(want, n, &b); err != nil {
			return err
		}
		if a.Header != b.Header || a.Mask != b.Mask || !(*windows.SID)(unsafe.Pointer(&a.SidStart)).Equals((*windows.SID)(unsafe.Pointer(&b.SidStart))) {
			return errors.New("unexpected service access grant")
		}
	}
	return nil
}

// Status performs only query operations and can be used without elevation.
func Status(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	api := nativeSCM{}
	manager, err := api.openManager(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(manager)
	service, err := api.openService(manager, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "not installed", nil
	}
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(service)
	status, err := queryService(service)
	if err != nil {
		return "", err
	}
	switch status.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running", nil
	case windows.SERVICE_STOPPED:
		return "stopped", nil
	default:
		return "pending", nil
	}
}

// RenderService rejects Unix service templates because Windows registration uses SCM directly.
func RenderService(string, paths.Paths) (string, error) {
	return "", errors.New("service templates are not available on Windows")
}
