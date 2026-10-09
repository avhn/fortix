package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// replaceIdentityQueries restores native hooks after each serialized identity test.
func replaceIdentityQueries(t *testing.T) {
	t.Helper()
	inspect, image := nativeInspectProcess, nativeProcessImage
	system, device := nativeSystemInformation, nativeQueryDosDevice
	t.Cleanup(func() {
		nativeInspectProcess, nativeProcessImage = inspect, image
		nativeSystemInformation, nativeQueryDosDevice = system, device
	})
}

// TestWindowsIdentityAccessDeniedFallback accepts only SCM LocalSystem plus an independent image.
// Successful token inspection remains authoritative, even when it observes a non-System account.
func TestWindowsIdentityAccessDeniedFallback(t *testing.T) {
	for _, tc := range []struct {
		name, account string
		inspectErr    error
		system        bool
		imageErr      error
		wantFallback  bool
		wantError     bool
	}{
		{"process denied", "LocalSystem", windows.ERROR_ACCESS_DENIED, false, nil, true, false},
		{"token denied", "localsystem", fmt.Errorf("token query: %w", windows.ERROR_ACCESS_DENIED), false, nil, true, false},
		{"different account", "LocalService", windows.ERROR_ACCESS_DENIED, false, nil, false, true},
		{"missing account", "", windows.ERROR_ACCESS_DENIED, false, nil, false, true},
		{"account alias", `NT AUTHORITY\SYSTEM`, windows.ERROR_ACCESS_DENIED, false, nil, false, true},
		{"other inspection error", "LocalSystem", windows.ERROR_INVALID_PARAMETER, false, nil, false, true},
		{"kernel query denied", "LocalSystem", windows.ERROR_ACCESS_DENIED, false, windows.ERROR_ACCESS_DENIED, true, true},
		{"actual System token", "LocalService", nil, true, nil, false, false},
		{"actual user token", "LocalSystem", nil, false, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replaceIdentityQueries(t)
			installed := installedIdentity()
			called := false
			nativeInspectProcess = func(pid uint32) (processIdentity, error) {
				if pid != installed.pipePID {
					t.Fatal("inspection used a different PID")
				}
				return processIdentity{image: installed.image, localSystem: tc.system}, tc.inspectErr
			}
			nativeProcessImage = func(pid uint32, binary string) (string, error) {
				called = true
				if pid != installed.pipePID || binary != installed.binary {
					t.Fatal("fallback used a different PID or binary")
				}
				return installed.image, tc.imageErr
			}
			identity, err := queryProcessIdentity(installed.pipePID, installed.binary, tc.account)
			if (err != nil) != tc.wantError || called != tc.wantFallback {
				t.Fatalf("fallback=%v err=%v", called, err)
			}
			if err == nil && (identity.image != installed.image || identity.localSystem != (tc.system || tc.wantFallback)) {
				t.Fatalf("unexpected identity: %+v", identity)
			}
		})
	}
}

// TestWindowsIdentityFallbackMismatchWritesNothing proves fallback failures still precede hello.
func TestWindowsIdentityFallbackMismatchWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name, account, image string
		imageErr             error
	}{
		{"foreign image", "LocalSystem", `C:\Program Files\Fortix\foreign.exe`, nil},
		{"non-System account", "LocalService", "", nil},
		{"kernel query failed", "LocalSystem", "", windows.ERROR_ACCESS_DENIED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replaceIdentityQueries(t)
			t.Setenv("FORTIX_SOCKET", "")
			nativeInspectProcess = func(uint32) (processIdentity, error) {
				return processIdentity{}, windows.ERROR_ACCESS_DENIED
			}
			nativeProcessImage = func(uint32, string) (string, error) { return tc.image, tc.imageErr }
			conn := &observedConn{}
			_, err := dialVerified(t.Context(), Options{Dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }},
				func(context.Context, net.Conn) error {
					identity := installedIdentity()
					process, err := queryProcessIdentity(identity.pipePID, identity.binary, tc.account)
					if err != nil {
						return err
					}
					identity.image, identity.localSystem = process.image, process.localSystem
					return validateServiceIdentity(identity)
				})
			if err == nil || err.Error() != "the Fortix helper service could not be verified" || !conn.closed || conn.writes != 0 || conn.reads != 0 {
				t.Fatalf("verification: err=%v closed=%v writes=%d reads=%d", err, conn.closed, conn.writes, conn.reads)
			}
		})
	}
}

// TestWindowsKernelImageQueryBounds checks native layout, bounded storage and drive mapping.
func TestWindowsKernelImageQueryBounds(t *testing.T) {
	for _, name := range []string{"matching image", "foreign image", "odd length", "oversized length", "changed buffer", "empty image", "query failed", "drive failed", "foreign mapping", "invalid drive length"} {
		t.Run(name, func(t *testing.T) {
			replaceIdentityQueries(t)
			calls := 0
			nativeSystemInformation = func(class int32, data unsafe.Pointer, size uint32, returned *uint32) error {
				calls++
				if class != windows.SystemProcessIdInformation || size != uint32(unsafe.Sizeof(systemProcessIDInformation{})) || returned != nil {
					t.Fatal("unexpected system query")
				}
				info := (*systemProcessIDInformation)(data)
				if info.processID != 42 || info.imageName.MaximumLength != 65534 {
					t.Fatal("unexpected PID or image allocation")
				}
				if name == "query failed" {
					return windows.STATUS_INVALID_CID
				}
				image := `\Device\HarddiskVolume3\Program Files\Fortix\fortix-helper.exe`
				if name == "foreign image" {
					image += ".foreign"
				}
				encoded, err := windows.UTF16FromString(image)
				if err != nil {
					t.Fatal(err)
				}
				copy(unsafe.Slice(info.imageName.Buffer, int(info.imageName.MaximumLength)/2), encoded)
				info.imageName.Length = uint16((len(encoded) - 1) * 2)
				switch name {
				case "odd length":
					info.imageName.Length = 3
				case "oversized length":
					info.imageName.Length = 65535
				case "changed buffer":
					info.imageName.Buffer = nil
				case "empty image":
					info.imageName.Length = 0
				}
				return nil
			}
			nativeQueryDosDevice = func(drive, target *uint16, maximum uint32) (uint32, error) {
				if windows.UTF16PtrToString(drive) != "C:" || maximum != 32768 {
					t.Fatal("unexpected drive query")
				}
				if name == "drive failed" {
					return 0, windows.ERROR_FILE_NOT_FOUND
				}
				if name == "invalid drive length" {
					return maximum + 1, nil
				}
				volume := `\Device\HarddiskVolume3`
				if name == "foreign mapping" {
					volume += "0"
				}
				encoded, err := windows.UTF16FromString(volume)
				if err != nil {
					t.Fatal(err)
				}
				copy(unsafe.Slice(target, int(maximum)), encoded)
				return uint32(len(encoded)), nil
			}
			image, err := queryProcessImageByPID(42, installedIdentity().binary)
			if (err == nil) != (name == "matching image") || calls != 1 {
				t.Fatalf("image=%q err=%v calls=%d", image, err, calls)
			}
			if err == nil && image != installedIdentity().image {
				t.Fatal(image)
			}
			for _, binary := range []string{`C:\Program Files\Fortix\..\foreign.exe`, `\\server\share\helper.exe`, installedIdentity().binary + " service"} {
				if _, err := queryProcessImageByPID(42, binary); err == nil || calls != 1 {
					t.Fatal("invalid configuration reached the kernel query")
				}
			}
			if _, err := queryProcessImageByPID(0, installedIdentity().binary); err == nil || calls != 1 {
				t.Fatal("zero PID reached the kernel query")
			}
		})
	}
}

// TestWindowsNativeProcessImageQuery exercises both identity paths against the current process.
// The handle-free query must agree with the independently known executable, not just a mock.
func TestWindowsNativeProcessImageQuery(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := inspectProcessIdentity(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(identity.handle)
	if identity.handle == 0 || !strings.EqualFold(identity.image, binary) {
		t.Fatalf("process identity: %+v", identity)
	}
	image, err := queryProcessImageByPID(uint32(os.Getpid()), binary)
	if err != nil || !strings.EqualFold(image, binary) {
		t.Fatalf("kernel image query: %q %v", image, err)
	}
	if _, err := queryProcessImageByPID(uint32(os.Getpid()), binary+".foreign"); err == nil {
		t.Fatal("kernel image query accepted a different executable")
	}
}

// TestWindowsNonAdminServiceVerification is an opt-in check against a preinstalled running helper.
// Set FORTIX_TEST_NONADMIN_SERVICE=1 in a fortix member account with no Administrators membership.
func TestWindowsNonAdminServiceVerification(t *testing.T) {
	if os.Getenv("FORTIX_TEST_NONADMIN_SERVICE") != "1" {
		t.Skip("requires a running installed helper and a non-admin fortix member account")
	}
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Fatal("this verification must run as a non-admin account, not a filtered administrator")
		}
	}
	t.Setenv("FORTIX_SOCKET", "")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, Options{})
	if errors.Is(err, os.ErrPermission) {
		t.Fatal("the non-admin account must already be an enabled fortix group member", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}
