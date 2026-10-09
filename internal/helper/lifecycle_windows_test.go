package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
	"github.com/avhn/fortix/internal/winfs"
)

// windowsTestDirectory injects a protected current-user fixture without weakening production policy.
func windowsTestDirectory(t *testing.T) *helperDirectory {
	t.Helper()
	policy, err := winfs.UserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private")
	root, err := winfs.SecureDirectory(path, policy)
	if err != nil {
		t.Fatal(err)
	}
	dir := &helperDirectory{root: root, policy: policy, path: path}
	t.Cleanup(func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	})
	return dir
}

// windowsNetworkFake records cleanup and empty startup batches without touching networking.
type windowsNetworkFake struct {
	NoNetwork
	calls     []string
	err       error
	recovered []Journal
}

// RecoverAll requires bounded startup work even when no helper attempt was persisted.
func (n *windowsNetworkFake) RecoverAll(ctx context.Context, journals []Journal) error {
	n.calls = append(n.calls, "recover")
	n.recovered = append([]Journal(nil), journals...)
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("recovery is unbounded")
	}
	return n.err
}

// Teardown records the network boundary before transport can release its device.
func (n *windowsNetworkFake) Teardown(context.Context, Journal) error {
	n.calls = append(n.calls, "teardown")
	return n.err
}

// TestWindowsStartupRecovery verifies empty-ledger recovery, listener ordering and failure retention.
func TestWindowsStartupRecovery(t *testing.T) {
	for _, scenario := range []string{"empty", "journal", "invalid", "failure"} {
		t.Run(scenario, func(t *testing.T) {
			dir := windowsTestDirectory(t)
			n := &windowsNetworkFake{}
			s := &Server{stateDir: dir, opts: Options{Network: n}}
			j := Journal{Profile: "work", Attempt: 1, Backend: "native"}
			if scenario != "empty" {
				if err := writeJournalAt(dir, j); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "invalid" {
				if err := atomicAt(dir, "helper-work.json", []byte(`{"secret":"forbidden"}`), 0); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "failure" {
				n.err = errors.New("recovery failed")
			}
			original := nativeCreatePipe
			defer func() { nativeCreatePipe = original }()
			listenerFailure := errors.New("listener fixture")
			nativeCreatePipe = func(_ *uint16, _, _, _, _, _, _ uint32, _ *windows.SecurityAttributes) (windows.Handle, error) {
				n.calls = append(n.calls, "listen")
				return windows.InvalidHandle, listenerFailure
			}
			_, err := s.recoverAndListen(context.Background())
			if scenario == "empty" || scenario == "journal" {
				if !errors.Is(err, listenerFailure) || !reflect.DeepEqual(n.calls, []string{"recover", "listen"}) {
					t.Fatalf("startup order: %v %v", n.calls, err)
				}
				if _, err := readJournalAt(dir, "work"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("completed journal retained")
				}
			} else {
				if err == nil {
					t.Fatal("failed recovery accepted")
				}
				for _, call := range n.calls {
					if call == "listen" {
						t.Fatal("listener opened before recovery")
					}
				}
				if _, err := os.Stat(filepath.Join(dir.path, "helper-work.json")); err != nil {
					t.Fatal("failed recovery lost record")
				}
			}
			if scenario == "invalid" && len(n.calls) != 0 {
				t.Fatal("invalid record reached recovery")
			}
		})
	}
}

// TestWindowsUpRefusal ensures unsupported profiles cannot allocate an actor or reach a backend.
func TestWindowsUpRefusal(t *testing.T) {
	for _, mode := range []string{"none", "prompt"} {
		t.Run(mode, func(t *testing.T) {
			store := &Store{dir: windowsTestDirectory(t)}
			p := profile.Profile{SchemaVersion: 1, ID: "work", Name: "Work", Backend: "openfortivpn", Gateway: profile.Gateway{Host: "example.com", Port: 443}, Username: "fixture", MFA: profile.MFA{Mode: mode}}
			p.ApplyDefaults()
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Put(raw); err != nil {
				t.Fatal(err)
			}
			n := &windowsNetworkFake{}
			s := &Server{store: store, opts: Options{Network: n}, actors: map[string]*supervisor{}, challenges: map[string]*challengeRoute{}}
			result := s.dispatchWindows(&connection{uid: 1}, protocol.Request{ID: "1", Op: "up", Profile: "work"})
			want := openfortivpnUnavailable
			if mode != "none" {
				want = "MFA profiles are not available on Windows"
			}
			if result.Error == nil || result.Error.Message != want || len(s.actors) != 0 || len(s.challenges) != 0 || len(n.calls) != 0 {
				t.Fatalf("unsupported profile passed admission: %+v", result)
			}
		})
	}
	if _, err := (openfortivpnBackend{}).Start(context.Background(), backend.Attempt{}); err == nil || err.Error() != openfortivpnUnavailable {
		t.Fatal("external backend did not refuse")
	}
}

// windowsTunnelFake observes the retained-device release boundary after worker shutdown.
type windowsTunnelFake struct{ network *windowsNetworkFake }

// Events is unused because the cleanup test starts after the transport has stopped.
func (*windowsTunnelFake) Events() <-chan backend.Event { return nil }

// Answer refuses any accidental credential work in the cleanup-only fixture.
func (*windowsTunnelFake) Answer(context.Context, backend.Request, []byte) error {
	return errors.New("unexpected answer")
}

// Stop is already complete for the retained cleanup fixture.
func (*windowsTunnelFake) Stop(context.Context) error { return nil }

// Wait reports that no native workers remain before cleanup starts.
func (*windowsTunnelFake) Wait() error { return nil }

// Release records the point where the transport gives up its device handle.
func (t *windowsTunnelFake) Release(context.Context) error {
	t.network.calls = append(t.network.calls, "release")
	return nil
}

// TestWindowsCleanupOrder uses the unchanged supervisor to prove finalization follows release.
func TestWindowsCleanupOrder(t *testing.T) {
	dir := windowsTestDirectory(t)
	n := &windowsNetworkFake{}
	j := Journal{Profile: "work", Attempt: 1, Backend: "native"}
	if err := writeJournalAt(dir, j); err != nil {
		t.Fatal(err)
	}
	dir.finalize = func(Journal) error { n.calls = append(n.calls, "finalize"); return nil }
	a := &supervisor{id: "work", profile: &profile.Profile{ID: "work", Backend: "native"}, journal: j, server: &Server{stateDir: dir, opts: Options{Network: n}}, state: session.New("work", session.Options{}), events: make(chan session.Event, 1), stopped: make(chan struct{}), tunnel: &windowsTunnelFake{network: n}}
	a.network(session.Effect{Profile: "work", Attempt: 1}, true)
	select {
	case event := <-a.events:
		if event.Kind != session.CleanupDone {
			t.Fatalf("cleanup failed: %+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup did not finish")
	}
	a.children.Wait()
	if !reflect.DeepEqual(n.calls, []string{"teardown", "release", "finalize"}) {
		t.Fatal(n.calls)
	}
	if _, err := readJournalAt(dir, "work"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal remained after finalization")
	}
}

// TestWindowsLogRotation retains only three bounded files and preserves known-secret redaction.
func TestWindowsLogRotation(t *testing.T) {
	dir := windowsTestDirectory(t)
	log, err := openLogAt(dir, "work")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	log.protect([]byte("fixture-secret"))
	if got := log.redact("password=fixture-secret"); strings.Contains(got, "fixture-secret") {
		t.Fatal("secret retained")
	}
	for range 4 {
		if err := log.write(strings.Repeat("x", logSize-1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.write(log.redact("SVPNCOOKIE=fixture-cookie")); err != nil {
		t.Fatal(err)
	}
	lines, err := readLogsAt(dir, "work", 1)
	if err != nil || len(lines) != 1 || strings.Contains(lines[0], "fixture-cookie") {
		t.Fatalf("redacted live tail unavailable: %v %v", lines, err)
	}
	entries, err := directoryEntries(dir, 4)
	if err != nil || len(entries) != 3 {
		t.Fatalf("rotation count %d: %v", len(entries), err)
	}
}

// TestWindowsJournalStrictness rejects process identities and keeps failed finalization recoverable.
func TestWindowsJournalStrictness(t *testing.T) {
	dir := windowsTestDirectory(t)
	for _, j := range []Journal{{Profile: "work", Attempt: 1, Backend: "openfortivpn"}, {Profile: "work", Attempt: 1, Backend: "native", PID: 10}, {Profile: "con", Attempt: 1, Backend: "native"}} {
		if writeJournalAt(dir, j) == nil {
			t.Fatal("unsafe journal accepted")
		}
	}
	j := Journal{Profile: "work", Attempt: 1, Backend: "native"}
	if err := writeJournalAt(dir, j); err != nil {
		t.Fatal(err)
	}
	dir.finalize = func(Journal) error { return errors.New("finalization failed") }
	if removeJournalAt(dir, "work") == nil {
		t.Fatal("failed finalization accepted")
	}
	if _, err := readJournalAt(dir, "work"); err != nil {
		t.Fatal("failed finalization lost recovery")
	}
	if _, err := openDirectory(dir.path); err == nil {
		t.Fatal("production storage adopted a user-owned fixture")
	}
}
