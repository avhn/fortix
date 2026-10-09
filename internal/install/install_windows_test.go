package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/winfs"
)

// TestElevationRefusal requires both independent token facts and the actionable terminal message.
func TestElevationRefusal(t *testing.T) {
	for _, elevated := range []bool{false, true} {
		for _, member := range []bool{false, true} {
			err := checkElevation(elevated, member)
			if (err == nil) != (elevated && member) {
				t.Fatalf("%v %v: %v", elevated, member, err)
			}
			if err != nil && err.Error() != elevationMessage {
				t.Fatal(err)
			}
		}
	}
}

// aceMasks reads explicit grants for a test without assuming localized account names.
func aceMasks(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) map[string]uint32 {
	t.Helper()
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("DACL: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("unprotected DACL")
	}
	result := make(map[string]uint32)
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, n, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatal("unexpected ACE type")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		result[sid.String()] = uint32(ace.Mask)
	}
	return result
}

// TestInstallationDACLs ensures Users cannot write payloads or control the helper service.
func TestInstallationDACLs(t *testing.T) {
	policy, err := binaryPolicy()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := policy.Descriptor(true)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Fatal("wrong binary owner")
	}
	got := aceMasks(t, sd)
	want := map[string]uint32{"S-1-5-18": 0x001f01ff, "S-1-5-32-544": 0x001f01ff, "S-1-5-32-545": windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("file grants: %v", got)
	}
	service, err := windows.SecurityDescriptorFromString(serviceSDDL)
	if err != nil {
		t.Fatal(err)
	}
	grants := aceMasks(t, service)
	if len(grants) != 3 || grants["S-1-5-32-545"] != serviceQueryAccess {
		t.Fatalf("service grants: %v", grants)
	}
	private, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, err := private.Descriptor(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(aceMasks(t, state)) != 2 {
		t.Fatal("private state grants non-administrator access")
	}
}

// maskSCM records acquisition requests without creating machine service state.
type maskSCM struct {
	managerAccess, serviceAccess, createAccess uint32
	image                                      string
	missing                                    bool
}

// openManager records the precise manager mask.
func (s *maskSCM) openManager(access uint32) (windows.Handle, error) {
	s.managerAccess = access
	return 1, nil
}

// openService records query/control rights and can model a missing service.
func (s *maskSCM) openService(_ windows.Handle, access uint32) (windows.Handle, error) {
	s.serviceAccess = access
	if s.missing {
		return 0, windows.ERROR_SERVICE_DOES_NOT_EXIST
	}
	return 2, nil
}

// createService captures the image and desired access separately from manager acquisition.
func (s *maskSCM) createService(_ windows.Handle, image string, access uint32) (windows.Handle, error) {
	s.image = image
	s.createAccess = access
	return 3, nil
}

// TestSCMAccessMasks prevents accidental migration to all-access manager convenience APIs.
func TestSCMAccessMasks(t *testing.T) {
	for _, create := range []bool{false, true} {
		api := &maskSCM{}
		_, _, err := acquireService(api, create)
		if err != nil {
			t.Fatal(err)
		}
		want := uint32(windows.SC_MANAGER_CONNECT)
		if create {
			want = managerCreateAccess
		}
		wantOpen := uint32(serviceQueryAccess | windows.READ_CONTROL | windows.SERVICE_START | windows.SERVICE_STOP)
		if api.managerAccess != want || api.serviceAccess != wantOpen || api.serviceAccess&(windows.WRITE_DAC|windows.SERVICE_CHANGE_CONFIG|windows.DELETE) != 0 {
			t.Fatalf("excess access: %+v", api)
		}
		if _, err := createHelperService(api, 1, `C:\Program Files\Fortix`); err != nil || api.createAccess != serviceInstallAccess || api.image != `C:\Program Files\Fortix\fortix-helper.exe` {
			t.Fatalf("creation access: %+v, %v", api, err)
		}
	}
}

// TestForeignServiceRefusal rejects sibling-directory tricks, command arguments and wrong accounts.
func TestForeignServiceRefusal(t *testing.T) {
	good := serviceConfig{image: `"C:\Program Files\Fortix\fortix-helper.exe"`, account: "LocalSystem", kind: windows.SERVICE_WIN32_OWN_PROCESS, start: windows.SERVICE_AUTO_START}
	directory := `C:\Program Files\Fortix`
	if err := validateService(good, directory); err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{`C:\Temp\fortix-helper.exe`, `C:\Program Files\FortixOther\fortix-helper.exe`, good.image + " --serve", `C:\Program Files\Fortix\..\other.exe`, `C:\Program Files\Fortix\foreign.exe`} {
		bad := good
		bad.image = image
		if validateService(bad, directory) == nil {
			t.Fatalf("accepted %s", image)
		}
	}
	bad := good
	bad.account = "example-user"
	if validateService(bad, directory) == nil {
		t.Fatal("accepted non-system account")
	}
	bad = good
	bad.kind = windows.SERVICE_WIN32_SHARE_PROCESS
	if validateService(bad, directory) == nil {
		t.Fatal("accepted shared process")
	}
}

// TestInstallTargetRefusal verifies preexisting foreign ownership is never adopted or rewritten.
func TestInstallTargetRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Fortix")
	userPolicy, err := winfs.UserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := createDirectory(path, userPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := foreign.Close(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "unrelated.txt")
	if err := os.WriteFile(marker, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := binaryPolicy()
	if err != nil {
		t.Fatal(err)
	}
	root, created, err := createDirectory(path, policy)
	if root != nil {
		root.Close()
	}
	if err == nil || created {
		t.Fatal("adopted foreign directory")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("changed foreign directory")
	}
}

// TestInstallReparseRefusal checks links only when the host permits unprivileged symlink creation.
func TestInstallReparseRefusal(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "Fortix")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	policy, err := binaryPolicy()
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := createDirectory(link, policy)
	if root != nil {
		root.Close()
	}
	if err == nil {
		t.Fatal("adopted reparse directory")
	}
}

// TestRollbackStackPrefixes verifies reverse compensation for varying mutation prefixes.
// Stage-level fault injection is covered separately through the production installation transaction.
func TestRollbackStackPrefixes(t *testing.T) {
	for failAt := 0; failAt <= 12; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			var stack rollbackStack
			var got []int
			for step := 0; step < failAt; step++ {
				stack.add(func(ctx context.Context) error {
					if ctx.Err() != nil {
						t.Fatal(ctx.Err())
					}
					got = append(got, step)
					return nil
				})
			}
			if err := stack.rollback(); err != nil {
				t.Fatal(err)
			}
			for n, step := range got {
				if step != failAt-1-n {
					t.Fatal(got)
				}
			}
			if len(got) != failAt {
				t.Fatal(got)
			}
		})
	}
	var stack rollbackStack
	stack.add(func(context.Context) error { t.Fatal("removed metadata after failed stop"); return nil })
	stack.add(func(context.Context) error { return errors.New("stop failed") })
	if err := stack.rollback(); err == nil || !strings.Contains(err.Error(), "retained installation metadata") {
		t.Fatal(err)
	}
}

// TestAtomicPublication verifies cancellation leaves old bytes intact and successful publication hashes match.
func TestAtomicPublication(t *testing.T) {
	policy, err := winfs.UserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "payloads")
	root, _, err := createDirectory(directory, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := publish(t.Context(), root, directory, "fortix.exe", []byte("old"), policy); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := publish(ctx, root, directory, "fortix.exe", []byte("new"), policy); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	data, _, err := protectedBytes(root, "fortix.exe", policy)
	if err != nil || string(data) != "old" {
		t.Fatalf("%q %v", data, err)
	}
	if err := publish(t.Context(), root, directory, "fortix.exe", []byte("new"), policy); err != nil {
		t.Fatal(err)
	}
	data, _, err = protectedBytes(root, "fortix.exe", policy)
	if err != nil || string(data) != "new" {
		t.Fatalf("%q %v", data, err)
	}
}
