package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/session"
)

// batchRecoveryNetwork records the complete startup boundary without running host
// commands. The embedded fallback hook detects accidental per-journal recovery.
type batchRecoveryNetwork struct {
	recoveryNetwork
	journals []Journal
	calls    int
}

// RecoverAll snapshots all records, requires a deadline, and injects cleanup failure
// or timeout. It does not remove journals or alter any host networking resources.
func (n *batchRecoveryNetwork) RecoverAll(ctx context.Context, journals []Journal) error {
	n.calls++
	n.journals = slices.Clone(journals)
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("unbounded batch recovery")
	}
	switch n.mode {
	case "failure":
		return errors.New("injected batch recovery failure")
	case "timeout":
		<-ctx.Done()
		return ctx.Err()
	default:
		return nil
	}
}

// TestStartupBatchRecovery wires the optional batch hook with every validated
// journal, retaining all records on failure. Invalid later records block the entire
// batch before network cleanup; successful cleanup alone authorizes record removal.
func TestStartupBatchRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "failure", "timeout", "invalid record", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			journals := []Journal{{Profile: "first", Attempt: 1}, {Profile: "second", Attempt: 2}}
			if scenario == "empty" {
				journals = nil
			}
			for _, j := range journals {
				if err := writeJournal(dir, j); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "invalid record" {
				if err := os.WriteFile(filepath.Join(dir, "second.json"), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			n := &batchRecoveryNetwork{recoveryNetwork: recoveryNetwork{mode: scenario}}
			s := &Server{opts: Options{Paths: paths.Paths{State: dir}, Network: n, Deadlines: session.Deadlines{Network: 10 * time.Millisecond}}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := s.recover(ctx)
			wantSuccess := scenario == "success" || scenario == "empty"
			if (err == nil) != wantSuccess {
				t.Fatalf("batch recovery result: %v", err)
			}
			if scenario == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("batch deadline error lost: %v", err)
			}
			if !reflect.DeepEqual(n.recovered, Journal{}) {
				t.Fatal("batch-capable network used per-journal recovery")
			}
			if scenario == "invalid record" || scenario == "empty" {
				if n.calls != 0 {
					t.Fatal("invalid or empty batch reached network recovery")
				}
			} else {
				if n.calls != 1 || len(n.journals) != len(journals) {
					t.Fatalf("incomplete startup boundary: %+v", n.journals)
				}
				for _, j := range journals {
					if !slices.ContainsFunc(n.journals, func(actual Journal) bool { return reflect.DeepEqual(actual, j) }) {
						t.Fatalf("startup journal omitted: %+v", j)
					}
				}
			}
			for _, j := range journals {
				_, statErr := os.Stat(filepath.Join(dir, j.Profile+".json"))
				if wantSuccess && !errors.Is(statErr, os.ErrNotExist) || !wantSuccess && statErr != nil {
					t.Fatalf("journal retention after batch: %v", statErr)
				}
			}
		})
	}
}
