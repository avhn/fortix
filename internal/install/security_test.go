//go:build darwin || linux

package install

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestRunner verifies literal argument passing, a sanitized environment, cancellation
// and a hard diagnostic size limit without running any privileged system command.
func TestRunner(t *testing.T) {
	runner := ExecRunner{}
	t.Setenv("FORTIX_INSTALL_TEST_SECRET", "must-not-inherit")
	out, err := runner.Run(context.Background(), "/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "must-not-inherit") || !strings.Contains(out, "LANG=C") || !strings.Contains(out, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Fatalf("unsafe environment: %q", out)
	}
	out, err = runner.Run(context.Background(), "/usr/bin/printf", "%s", "$PATH; literal")
	if err != nil || out != "$PATH; literal" {
		t.Fatalf("argument interpretation: %q %v", out, err)
	}
	out, err = runner.Run(context.Background(), "/usr/bin/printf", "%s", strings.Repeat("x", 70000))
	if err != nil || len(out) != 65536 {
		t.Fatalf("diagnostic limit: %d %v", len(out), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runner.Run(ctx, "/usr/bin/printf", "must not run"); err == nil {
		t.Fatal("ignored cancellation")
	}
}

// TestDylibLoadVariants ensures weak and reexported dependencies are not silently
// skipped by debug/macho's raw load-command representation. Malformed names fail.
func TestDylibLoadVariants(t *testing.T) {
	for _, command := range []uint32{0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023} {
		data := machoFixture([]string{"@loader_path/libssl.dylib"}, nil)
		binary.LittleEndian.PutUint32(data[32:], command)
		metadata, err := readImage(bytes.NewReader(data))
		if err != nil || !reflect.DeepEqual(metadata.libraries, []string{"@loader_path/libssl.dylib"}) {
			t.Fatalf("command %x: %+v %v", command, metadata, err)
		}
	}
	for _, name := range []string{"offset", "terminator", "empty", "short"} {
		raw := machoFixture([]string{"libssl.dylib"}, nil)[32:]
		switch name {
		case "offset":
			binary.LittleEndian.PutUint32(raw[8:], 0xffffffff)
		case "terminator":
			for index := 24; index < len(raw); index++ {
				raw[index] = 'x'
			}
		case "empty":
			raw[24] = 0
		case "short":
			raw = raw[:12]
		}
		if _, _, err := importedLibrary(raw, binary.LittleEndian); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

// fatFixture wraps two inert thin Mach-O slices as a universal x86_64/arm64 image.
// It uses separate aligned regions so the standard parser exercises both slices.
func fatFixture() []byte {
	a := machoFixture([]string{"/usr/lib/libSystem.B.dylib"}, []string{"@loader_path/z", "@loader_path/a"})
	b := machoFixture([]string{"@loader_path/libssl.dylib"}, nil)
	binary.LittleEndian.PutUint32(b[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(b[8:], 0)
	data := make([]byte, 8192+len(b))
	binary.BigEndian.PutUint32(data, 0xcafebabe)
	binary.BigEndian.PutUint32(data[4:], 2)
	for _, arch := range []struct {
		offset                         int
		cpu, subtype, fileOffset, size uint32
	}{{8, 0x01000007, 3, 4096, uint32(len(a))}, {28, 0x0100000c, 0, 8192, uint32(len(b))}} {
		for offset, value := range map[int]uint32{0: arch.cpu, 4: arch.subtype, 8: arch.fileOffset, 12: arch.size, 16: 12} {
			binary.BigEndian.PutUint32(data[arch.offset+offset:], value)
		}
	}
	copy(data[4096:], a)
	copy(data[8192:], b)
	return data
}

// TestUniversalMachO verifies imports from every architecture and loader search order.
func TestUniversalMachO(t *testing.T) {
	metadata, err := readImage(bytes.NewReader(fatFixture()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(metadata.libraries, []string{"/usr/lib/libSystem.B.dylib", "@loader_path/libssl.dylib"}) {
		t.Fatalf("universal imports: %v", metadata.libraries)
	}
	if !reflect.DeepEqual(metadata.rpaths, []string{"@loader_path/z", "@loader_path/a"}) {
		t.Fatalf("rpath priority changed: %v", metadata.rpaths)
	}
}

// TestEmptyProductParents ensures purging removes owned empty parent directories,
// while non-purge removal leaves profile parents and unrelated sibling files intact.
func TestEmptyProductParents(t *testing.T) {
	o, _ := testOptions(t, "linux")
	p := resolvedPaths(t, o)
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(p.State)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state parent retained: %v", err)
	}
	if _, err := os.Stat(p.Profiles); err != nil {
		t.Fatal("profiles directory removed without purge")
	}
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(filepath.Dir(p.Profiles), "other.txt")
	if err := os.WriteFile(sibling, []byte("retain"), 0644); err != nil {
		t.Fatal(err)
	}
	o.Purge = true
	if err := Uninstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatal("unrelated sibling removed")
	}
}

// TestReinstall reloads registered launchd jobs and restarts existing systemd units
// after successful replacement. A service reload failure must reach the caller.
func TestReinstall(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, fail := range []bool{false, true} {
			t.Run(platform+map[bool]string{false: "/reload", true: "/failure"}[fail], func(t *testing.T) {
				o, runner := testOptions(t, platform)
				if err := Install(context.Background(), o); err != nil {
					t.Fatal(err)
				}
				runner.calls = nil
				if fail {
					runner.fail = "restart"
					if platform == "darwin" {
						runner.fail = "bootout"
					}
				}
				err := Install(context.Background(), o)
				if (err != nil) != fail {
					t.Fatalf("reload failure=%v: %v", fail, err)
				}
				p := resolvedPaths(t, o)
				var want [][]string
				if platform == "darwin" {
					want = [][]string{{"/usr/sbin/dseditgroup", "-o", "edit", "-a", "jane.doe", "-t", "user", "fortix"}, {"/bin/launchctl", "print", "system/com.github.avhn.fortix.helper"}, {"/bin/launchctl", "bootout", "system/com.github.avhn.fortix.helper"}}
					if !fail {
						want = append(want, []string{"/bin/launchctl", "print", "system/com.github.avhn.fortix.helper"}, []string{"/bin/launchctl", "bootstrap", "system", p.ServiceFile})
					}
				} else {
					want = [][]string{{"/usr/sbin/usermod", "-a", "-G", "fortix", "jane.doe"}, {"/bin/systemctl", "daemon-reload"}, {"/bin/systemctl", "enable", "--now", "fortix-helper.service"}, {"/bin/systemctl", "restart", "fortix-helper.service"}}
				}
				if !reflect.DeepEqual(runner.calls, want) {
					t.Fatalf("reload commands: %v want %v", runner.calls, want)
				}
			})
		}
	}
}

// TestReinstallStoppedLaunchDaemon bootstraps a previously installed but unloaded
// job without issuing bootout against a job that launchd reports as absent.
func TestReinstallStoppedLaunchDaemon(t *testing.T) {
	o, runner := testOptions(t, "darwin")
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	runner.fail = "launchctl print"
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if len(call) > 1 && call[1] == "bootout" {
			t.Fatal("unloaded job was stopped")
		}
	}
	last := runner.calls[len(runner.calls)-1]
	if len(last) < 2 || last[1] != "bootstrap" {
		t.Fatalf("job was not loaded: %v", last)
	}
}

// FuzzDylibLoad checks name-offset decoding for both byte orders on arbitrary raw
// load commands. Malformed commands may error, but must never panic or overread.
func FuzzDylibLoad(f *testing.F) {
	f.Add(machoFixture([]string{"@loader_path/libssl.dylib"}, nil)[32:])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		_, _, _ = importedLibrary(data, binary.LittleEndian)
		_, _, _ = importedLibrary(data, binary.BigEndian)
	})
}
