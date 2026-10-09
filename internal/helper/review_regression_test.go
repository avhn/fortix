//go:build darwin || linux

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/protocol"
)

// TestProcessInspectionRetry ensures transient inspection failures, even with an
// unreliable exit flag, cannot cause group termination before a confirmed child exit.
func TestProcessInspectionRetry(t *testing.T) {
	for _, terminal := range []error{nil, unix.ESRCH, os.ErrNotExist} {
		calls := 0
		reserved := waitUntilFinished(123, func(pid int) (bool, error) {
			if pid != 123 {
				t.Fatal("wrong child inspected")
			}
			calls++
			switch calls {
			case 1:
				return true, unix.EMFILE
			case 2:
				return false, errors.New("temporary kernel lookup failure")
			case 3:
				return false, nil
			default:
				return terminal == nil, terminal
			}
		}, time.Millisecond)
		if calls != 4 || reserved != (terminal == nil) {
			t.Fatalf("inspection stopped after %d calls, reserved=%v", calls, reserved)
		}
	}
}

// TestPendingChallengeTransfer exercises disconnect before and after a queued prompt
// is delivered. Only still-pending prompts transfer, and duplicate detach is harmless.
func TestPendingChallengeTransfer(t *testing.T) {
	for _, delivered := range []bool{false, true} {
		t.Run(fmt.Sprintf("delivered-%v", delivered), func(t *testing.T) {
			origin := &connection{open: true, events: make(chan protocol.Event, 1)}
			observer := &connection{open: true, subscribed: true, events: make(chan protocol.Event, 2)}
			route := &challengeRoute{}
			s := &Server{clients: map[*connection]bool{origin: true, observer: true}, challenges: map[string]*challengeRoute{"pending": route}}
			event := protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "pending", Kind: "password", Prompt: "Password:"}
			s.emit(event, origin)
			if delivered {
				<-origin.events
			}
			s.detach(origin)
			s.detach(origin)
			if origin.open || route.origin != nil {
				t.Fatal("disconnected origin retained challenge responsibility")
			}
			select {
			case got := <-observer.events:
				if got != event {
					t.Fatalf("wrong transferred prompt: %+v", got)
				}
			default:
				t.Fatal("pending prompt lost on disconnect")
			}
			if len(observer.events) != 0 {
				t.Fatal("duplicate transfer")
			}
		})
	}
}

// TestDeliveredChallengeOriginDisconnect verifies a subscriber can answer the same
// challenge after the initiating client received it but disconnected without answering.
func TestDeliveredChallengeOriginDisconnect(t *testing.T) {
	h := startHarness(t, nil)
	origin, observer := h.client(t), h.client(t)
	observer.success(t, protocol.Request{Op: "subscribe"})
	origin.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "")})
	origin.success(t, protocol.Request{Op: "up", Profile: "work"})
	first := origin.event(t, "challenge", "work", "")
	if err := origin.socket.Close(); err != nil {
		t.Fatal(err)
	}
	transferred := observer.event(t, "challenge", "work", "")
	if transferred.ChallengeID != first.ChallengeID || transferred.Attempt != first.Attempt {
		t.Fatal("disconnect created a different challenge")
	}
	observer.success(t, protocol.Request{Op: "answer", ChallengeID: transferred.ChallengeID, Secret: "fixture-password"})
	observer.event(t, "state", "work", "connected")
}

// retryCleanup allows a client to recover a profile after automatic network cleanup
// retries exhaust. Atomic failure injection keeps the test independent of host state.
type retryCleanup struct {
	NoNetwork
	fail  atomic.Bool
	calls atomic.Int32
}

// Teardown counts bounded cleanup attempts and fails only while the fixture requests
// failure. It never signals a process or touches a real route or resolver.
func (n *retryCleanup) Teardown(context.Context, Journal) error {
	n.calls.Add(1)
	if n.fail.Load() {
		return errors.New("fixture cleanup failure")
	}
	return nil
}

// TestDownRetriesExhaustedCleanup proves explicit down restarts exhausted cleanup,
// retains the journal until success, and makes the profile usable without restarting.
func TestDownRetriesExhaustedCleanup(t *testing.T) {
	n := &retryCleanup{}
	n.fail.Store(true)
	h := startHarness(t, nil, func(o *Options) { o.Network = n; o.Deadlines.Network = 250 * time.Millisecond })
	c := h.client(t)
	connectFixture(t, c, "work", "", "fixture-password")
	c.success(t, protocol.Request{Op: "down", Profile: "work"})
	c.event(t, "state", "work", "failed")
	if n.calls.Load() != 4 || h.server.actor("work").idle() {
		t.Fatal("cleanup did not exhaust safely")
	}
	if _, err := os.Stat(filepath.Join(h.paths.State, "work.json")); err != nil {
		t.Fatal("failed cleanup lost journal")
	}
	if result := c.request(t, protocol.Request{Op: "up", Profile: "work"}); result.OK || result.Error.Code != protocol.Busy {
		t.Fatal("unclean attempt allowed a child")
	}
	n.fail.Store(false)
	c.success(t, protocol.Request{Op: "down", Profile: "work"})
	c.event(t, "state", "work", "failed")
	if !h.server.actor("work").idle() || n.calls.Load() != 5 {
		t.Fatal("explicit cleanup recovery failed")
	}
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	challenge := c.event(t, "challenge", "work", "")
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
	c.event(t, "state", "work", "connected")
}

// TestUpIdempotentAndQueued checks repeated wanted Up retains its generation and an
// Up during normal stopping starts exactly one fresh attempt after successful cleanup.
func TestUpIdempotentAndQueued(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	connectFixture(t, c, "work", "ignore-term", "fixture-password")
	result := c.success(t, protocol.Request{Op: "up", Profile: "work"})
	var attempt struct {
		Attempt uint64 `json:"attempt"`
	}
	if json.Unmarshal(result.Data, &attempt) != nil || attempt.Attempt != 1 {
		t.Fatal("repeated Up changed wanted generation")
	}
	c.success(t, protocol.Request{Op: "down", Profile: "work"})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	challenge := c.event(t, "challenge", "work", "")
	if challenge.Attempt != 2 {
		t.Fatal("queued Up did not start a fresh generation")
	}
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
	c.event(t, "state", "work", "connected")
}

// TestLogsFitWireRecord proves long, heavily JSON-escaped diagnostics return the
// newest available tail rather than BUSY. The fixture writes no credential material.
func TestLogsFitWireRecord(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "")})
	log, err := openLogAt(h.server.logDir, "work")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		if err := log.write(fmt.Sprintf("%04d %s", i, strings.Repeat("\"\\", 2000))); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	result := c.success(t, protocol.Request{Op: "logs", Profile: "work", Lines: 500})
	var lines []string
	if err := json.Unmarshal(result.Data, &lines); err != nil || len(lines) == 0 || len(lines) >= 50 {
		t.Fatalf("invalid bounded tail: %v", err)
	}
	if !strings.HasPrefix(lines[len(lines)-1], "0049 ") {
		t.Fatal("newest diagnostic lost")
	}
	encoded, err := json.Marshal(protocol.Result{Type: "result", ID: result.ID, OK: result.OK, Data: lines})
	if err != nil || len(encoded)+1 > protocol.MaxLine {
		t.Fatal("tail exceeds wire limit")
	}
}

// TestListingsIgnoreBadProfiles keeps valid and active profiles visible when a manual
// file has invalid JSON, a bad filename or unsafe mode. Direct reads still fail closed.
func TestListingsIgnoreBadProfiles(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	connectFixture(t, c, "work", "", "fixture-password")
	for _, filename := range []string{"broken.json", "Invalid.json", "work.json"} {
		if err := os.WriteFile(filepath.Join(h.paths.Profiles, filename), []byte(`{"not":"a profile"}`), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, op := range []string{"profile.list", "status"} {
		result := c.success(t, protocol.Request{Op: op})
		if !strings.Contains(string(result.Data), `"work"`) || !strings.Contains(string(result.Data), `"connected"`) || strings.Contains(string(result.Data), "broken") {
			t.Fatalf("healthy actor missing from %s: %s", op, result.Data)
		}
	}
	if c.request(t, protocol.Request{Op: "profile.get", Profile: "work"}).OK {
		t.Fatal("corrupt profile read accepted")
	}
	c.success(t, protocol.Request{Op: "down", Profile: "work"})
	c.event(t, "state", "work", "disconnected")
}

// TestPinnedStorageDirectories replaces both pathname entries after opening directory
// handles. Logs, rotation and journal updates must remain in their original inodes.
func TestPinnedStorageDirectories(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"logs", "state"} {
		dirPath := filepath.Join(root, name)
		if err := os.Mkdir(dirPath, 0700); err != nil {
			t.Fatal(err)
		}
		dir, err := openDirectory(dirPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = dir.Close() }()
		moved := dirPath + "-original"
		if err := os.Rename(dirPath, moved); err != nil {
			t.Fatal(err)
		}
		target := t.TempDir()
		if err := os.Symlink(target, dirPath); err != nil {
			t.Fatal(err)
		}
		if name == "logs" {
			log, err := openLogAt(dir, "work")
			if err != nil {
				t.Fatal(err)
			}
			if err := log.write(strings.Repeat("x", logSize-1)); err != nil {
				t.Fatal(err)
			}
			if err := log.write("newest"); err != nil {
				t.Fatal(err)
			}
			if err := log.Close(); err != nil {
				t.Fatal(err)
			}
			lines, err := readLogsAt(dir, "work", 1)
			if err != nil || !reflect.DeepEqual(lines, []string{"newest"}) {
				t.Fatal("log escaped pinned directory")
			}
		} else {
			j := Journal{Profile: "work", Attempt: 1, Interface: "ppp0", Routes: []JournalRoute{{CIDR: "10.20.0.0/16", Interface: "ppp0"}}}
			if err := writeJournalAt(dir, j); err != nil {
				t.Fatal(err)
			}
			stored, err := readJournalAt(dir, "work")
			if err != nil || !reflect.DeepEqual(stored, j) {
				t.Fatal("journal escaped pinned directory")
			}
			if err := removeJournalAt(dir, "work"); err != nil {
				t.Fatal(err)
			}
		}
		entries, err := os.ReadDir(target)
		if err != nil || len(entries) != 0 {
			t.Fatal("replacement directory was modified")
		}
	}
}

// TestSecureDirectorySubset accepts stricter permissions but refuses extra write or
// access permissions, symlinks and special bits without changing existing metadata.
func TestSecureDirectorySubset(t *testing.T) {
	for _, tc := range []struct {
		mode, maximum os.FileMode
		valid         bool
	}{{0700, 0755, true}, {0750, 0755, true}, {0755, 0755, true}, {0750, 0700, false}, {0775, 0755, false}} {
		dir := filepath.Join(t.TempDir(), "directory")
		if err := os.Mkdir(dir, tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := secureDir(dir, tc.maximum); (err == nil) != tc.valid {
			t.Fatalf("mode %o, maximum %o: %v", tc.mode, tc.maximum, err)
		}
	}
}

// TestVerifiedExecutableLocation ensures library inspection and invocation use the
// same canonical executable path. The system file is read only, never executed.
func TestVerifiedExecutableLocation(t *testing.T) {
	s := &Server{opts: Options{Paths: paths.Paths{Pinentry: "/bin/ls", OpenFortiVPN: []string{"/bin/ls"}}}}
	got, err := s.verifyExecutables()
	if err != nil {
		t.Fatal(err)
	}
	want, err := trustedPath("/bin/ls", 0)
	if err != nil || got != want {
		t.Fatalf("verified executable location: got %s, want %s, error %v", got, want, err)
	}
}
