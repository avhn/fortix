//go:build windows

package winfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// privateRoot creates owned test storage without changing the temporary parent ACL.
func privateRoot(t *testing.T) (*Root, Policy, string) {
	t.Helper()
	p, err := UserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private")
	r, err := SecureDirectory(path, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r, p, path
}

// TestAtomicWrite checks replacement with open readers, snapshot reads and temporary cleanup.
func TestAtomicWrite(t *testing.T) {
	r, p, path := privateRoot(t)
	values := []string{"first", "replacement", ""}
	for i, want := range values {
		var reader *os.File
		if i > 0 {
			var err error
			reader, err = r.Open("config.json", p)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Close() }()
		}
		if err := r.AtomicWrite(context.Background(), "config.json", []byte(want), p); err != nil {
			t.Fatal(err)
		}
		if reader != nil {
			got, err := io.ReadAll(reader)
			if err != nil || string(got) != values[i-1] {
				t.Fatalf("previous reader = %q %v, want %q", got, err, values[i-1])
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
		}
		f, err := r.Open("config.json", p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(f)
		if err != nil || string(got) != want {
			t.Fatalf("read = %q %v", got, err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 1 || entries[0].Name() != "config.json" {
			t.Fatalf("temporary cleanup: %v %v", entries, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.AtomicWrite(ctx, "config.json", []byte("not published"), p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(path, "config.json")); err != nil || len(got) != 0 {
		t.Fatal("cancelled write changed destination")
	}
}

// cancelBeforePublish deterministically cancels after staging and flushing have completed.
type cancelBeforePublish struct {
	context.Context
	checks int
}

// Err allows the initial check and cancels the check immediately before publication.
func (c *cancelBeforePublish) Err() error {
	c.checks++
	if c.checks > 1 {
		return context.Canceled
	}
	return nil
}

// TestStagedCleanup checks that late cancellation deletes only the exact staged handle.
func TestStagedCleanup(t *testing.T) {
	r, p, path := privateRoot(t)
	if err := r.AtomicWrite(context.Background(), "config.json", []byte("original"), p); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelBeforePublish{Context: context.Background()}
	if err := r.AtomicWrite(ctx, "config.json", []byte("replacement"), p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary cleanup: %v %v", entries, err)
	}
	if got, err := os.ReadFile(filepath.Join(path, "config.json")); err != nil || string(got) != "original" {
		t.Fatal("late cancellation changed the previous file")
	}
}

// TestPinnedTargets rejects directory occupants, hard links, volume changes and unsafe names.
func TestPinnedTargets(t *testing.T) {
	r, p, path := privateRoot(t)
	if err := r.AtomicWrite(context.Background(), "file", []byte("original"), p); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(path, "file"), filepath.Join(path, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open("file", p); err == nil {
		t.Fatal("accepted hard link")
	}
	if err := r.AtomicWrite(context.Background(), "file", []byte("changed"), p); err == nil {
		t.Fatal("replaced hard link")
	}
	if got, err := os.ReadFile(filepath.Join(path, "alias")); err != nil || string(got) != "original" {
		t.Fatal("changed hard-link content")
	}
	if err := os.Mkdir(filepath.Join(path, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := r.AtomicWrite(context.Background(), "directory", nil, p); err == nil {
		t.Fatal("replaced directory")
	}
	for _, name := range []string{`..\escape`, `file:stream`, "NUL", "CON.json", "COM¹", "trailing.", "invalid\xff", ""} {
		if err := r.AtomicWrite(context.Background(), name, nil, p); err == nil {
			t.Fatalf("accepted unsafe name %q", name)
		}
	}
	wrong := r.volume ^ 1
	if _, err := inspect(r.Handle(), true, &wrong); err == nil {
		t.Fatal("accepted unexpected volume")
	}
}

// TestNoReplaceRename verifies a destination created after staging is never overwritten.
func TestNoReplaceRename(t *testing.T) {
	r, p, path := privateRoot(t)
	for _, name := range []string{"stage", "target"} {
		if err := r.AtomicWrite(context.Background(), name, []byte(name), p); err != nil {
			t.Fatal(err)
		}
	}
	h, err := relativeOpen(r.Handle(), "stage", windows.FILE_GENERIC_READ|windows.DELETE, windows.FILE_OPEN, false, nil, windows.FILE_SHARE_READ)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := r.rename(h, "target", false); err == nil {
		t.Fatal("overwrote concurrent occupant")
	}
	if got, err := os.ReadFile(filepath.Join(path, "target")); err != nil || string(got) != "target" {
		t.Fatal("changed existing target")
	}
}

// TestProtectedPolicies checks exact grants, owner, protection and foreign-ACL refusal.
func TestProtectedPolicies(t *testing.T) {
	r, p, _ := privateRoot(t)
	if err := CheckSecurity(r.Handle(), p, true); err != nil {
		t.Fatal(err)
	}
	system, err := SystemPolicy(p.Owner, windows.FILE_GENERIC_READ)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := system.Descriptor(false)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("missing protection")
	}
	dacl, _, err := sd.DACL()
	count := uint16(3)
	if p.Owner.IsWellKnown(windows.WinLocalSystemSid) {
		count = 2
	}
	if err != nil || dacl == nil || dacl.AceCount != count {
		t.Fatal("unexpected system grants")
	}
	if err := r.AtomicWrite(context.Background(), "file", nil, p); err != nil {
		t.Fatal(err)
	}
	h, err := relativeOpen(r.Handle(), "file", windows.WRITE_DAC|windows.WRITE_OWNER|windows.READ_CONTROL, windows.FILE_OPEN, false, nil, windows.FILE_SHARE_READ)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	broad, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := broad.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecurity(h, p, false); err == nil {
		t.Fatal("accepted foreign grant")
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecurity(h, p, false); err == nil {
		t.Fatal("accepted null DACL")
	}
	if err := Protect(h, p, false); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecurity(h, p, false); err != nil {
		t.Fatal(err)
	}
}

// TestReparseRefusal uses a junction without requiring symbolic-link privileges.
// The pinned-directory walker must refuse the junction and leave its target untouched.
func TestReparseRefusal(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	link := filepath.Join(base, "junction")
	for _, path := range []string{target, link} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	name, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Mount-point reparse data stores a kernel substitute name and a visible print name.
	substitute, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		t.Fatal(err)
	}
	printName, err := windows.UTF16FromString(target)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16+2*(len(substitute)+len(printName)))
	head := (*[8]uint16)(unsafe.Pointer(&buffer[0]))
	*(*uint32)(unsafe.Pointer(&buffer[0])) = windows.IO_REPARSE_TAG_MOUNT_POINT
	head[2] = uint16(len(buffer) - 8)
	head[4], head[5] = 0, uint16(2*(len(substitute)-1))
	head[6], head[7] = uint16(2*len(substitute)), uint16(2*(len(printName)-1))
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[16])), len(substitute)+len(printName)), append(substitute, printName...))
	var returned uint32
	err = windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil)
	closeErr := windows.CloseHandle(h)
	if err != nil || closeErr != nil {
		t.Fatalf("create junction: %v %v", err, closeErr)
	}
	if r, err := OpenRoot(link); err == nil {
		_ = r.Close()
		t.Fatal("followed junction")
	}
	p, err := UserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if r, err := SecureDirectory(filepath.Join(link, "private"), p); err == nil {
		_ = r.Close()
		t.Fatal("created directory through junction")
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatal("changed junction target")
	}
}
