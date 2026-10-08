package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/protocol"
)

// TestStoreSafety exercises atomic replacement, ID bounds, strict decoding, and
// descriptor-based rejection of symlinks, FIFOs, directories, and unsafe modes.
func TestStoreSafety(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	for _, id := range []string{"../work", "/work", "Work", "-work", "work.json", strings.Repeat("x", 64), ""} {
		if _, err := store.Get(id); err == nil {
			t.Errorf("accepted id %q", id)
		}
		if store.Delete(id) == nil {
			t.Errorf("deleted invalid id %q", id)
		}
	}
	raw := profileJSON("work", "")
	if _, err := store.Put(raw); err != nil {
		t.Fatal(err)
	}
	p, err := store.Get("work")
	if err != nil || p.ID != "work" {
		t.Fatalf("round trip: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "work.json"))
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("profile mode is not 0640")
	}
	if _, err := store.Put(bytes.Replace(raw, []byte(`"work"`), []byte(`"work","password":"forbidden"`), 1)); err == nil {
		t.Fatal("secret-bearing profile accepted")
	}
	if err := os.Chmod(filepath.Join(dir, "work.json"), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("work"); err == nil {
		t.Fatal("writable profile accepted")
	}
	if _, err := store.Put(raw); err == nil {
		t.Fatal("unsafe existing file replaced")
	}
	if err := os.Remove(filepath.Join(dir, "work.json")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "work.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("work"); err == nil {
		t.Fatal("followed profile symlink")
	}
	if _, err := store.Put(raw); err == nil {
		t.Fatal("replaced profile symlink")
	}
	if store.Delete("work") == nil {
		t.Fatal("deleted profile symlink")
	}
	if err := os.Remove(filepath.Join(dir, "work.json")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "work.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("work"); err == nil {
		t.Fatal("accepted FIFO")
	}
	if err := os.Remove(filepath.Join(dir, "work.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "work.json"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("work"); err == nil {
		t.Fatal("accepted directory")
	}
	if err := os.Remove(filepath.Join(dir, "work.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("other"); err == nil {
		t.Fatal("accepted mismatched embedded id")
	}
}

// TestExecutableTrust rejects user-controlled binaries, unsafe ancestors, missing
// dependencies, and symlink paths. The test never changes root-owned filesystem data.
func TestExecutableTrust(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "openfortivpn")
	if err := os.WriteFile(program, []byte("not an executable"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{program, filepath.Join(dir, "missing"), "relative", filepath.Join(dir, "..", "openfortivpn")} {
		if trustedFile(path, true) == nil {
			t.Errorf("trusted unsafe path %q", path)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	if trustedFile(link, true) == nil {
		t.Fatal("trusted user-controlled executable link")
	}
	if trustedAncestor(dir) == nil {
		t.Fatal("trusted writable development tree")
	}
	if Authorize(Peer{UID: 0}) != nil {
		t.Fatal("root was denied")
	}
	if Authorize(Peer{UID: ^uint32(0)}) == nil {
		t.Fatal("unknown uid was accepted")
	}
}

// TestLogRotation preserves only three bounded files and refuses symlink log reads.
// Input strings here represent already redacted diagnostics, not secret payloads.
func TestLogRotation(t *testing.T) {
	dir := t.TempDir()
	log, err := openLog(dir, "work")
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 1023)
	for range 3100 {
		if err := log.write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("retained %d files", len(entries))
	}
	for _, entry := range entries {
		st, err := entry.Info()
		if err != nil || st.Size() > logSize || st.Mode().Perm() != 0600 {
			t.Fatal("unsafe rotated log")
		}
	}
	lines, err := readLogs(dir, "work", 500)
	if err != nil || len(lines) != 500 {
		t.Fatalf("tail: %d %v", len(lines), err)
	}
	if err := os.Symlink(filepath.Join(dir, "work.log"), filepath.Join(dir, "other.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := readLogs(dir, "other", 10); err == nil {
		t.Fatal("followed log symlink")
	}
}

// TestJournalRecovery validates process birth matching before signalling a group.
// Only a subprocess created by this test is eligible; a mismatched record leaves it live.
func TestJournalRecovery(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture process did not exit")
		}
	})
	start, err := processStart(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	j := Journal{Profile: "work", Attempt: 1, PID: cmd.Process.Pid, StartTime: "not-the-start-time"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := recoverProcess(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("mismatched process was killed")
	}
	j.StartTime = start
	dir := t.TempDir()
	if err := writeJournal(dir, j); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "work.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored Journal
	if err := protocol.Decode(data, &stored); err != nil || !reflect.DeepEqual(stored, j) {
		t.Fatal("journal did not round trip")
	}
	if err := recoverProcess(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err := removeJournal(dir, "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "work.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal was not removed")
	}
}

// FuzzJournal checks strict decoding of untrusted persisted process metadata.
// Successfully decoded records must retain identity across JSON serialization.
func FuzzJournal(f *testing.F) {
	f.Add([]byte(`{"profile":"work","attempt":1,"pid":123,"start_time":"100"}`))
	f.Add([]byte(`{"profile":"../work","pid":1,"pid":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var j Journal
		if protocol.Decode(data, &j) != nil {
			return
		}
		encoded, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		var again Journal
		if protocol.Decode(encoded, &again) != nil {
			t.Fatal("encoded journal rejected")
		}
		roundtrip, err := json.Marshal(again)
		if err != nil || !bytes.Equal(roundtrip, encoded) {
			t.Fatal("journal identity changed")
		}
	})
}
