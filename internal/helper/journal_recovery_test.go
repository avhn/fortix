//go:build darwin || linux

package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/session"
)

// recoveryNetwork observes startup reconciliation in memory and can inject an error
// or wait for its deadline. It never invokes commands or changes host networking.
type recoveryNetwork struct {
	NoNetwork
	mode      string
	recovered Journal
}

// Recover records the exact journal passed by the helper and requires a bounded
// context. Success, explicit failure, and deadline expiry are selected by mode.
func (n *recoveryNetwork) Recover(ctx context.Context, j Journal) error {
	n.recovered = j
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("unbounded network recovery")
	}
	switch n.mode {
	case "failure":
		return errors.New("injected network recovery failure")
	case "timeout":
		<-ctx.Done()
		return ctx.Err()
	default:
		return nil
	}
}

// TestStartupNetworkRecovery proves startup invokes the network hook for a stale
// process record and removes the journal only on successful reconciliation. Errors
// and deadline expiry retain the original identity for a subsequent startup.
func TestStartupNetworkRecovery(t *testing.T) {
	for _, mode := range []string{"success", "failure", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			j := Journal{Profile: "work", Attempt: 3, PID: 1 << 30, StartTime: "nonexistent", Interface: "ppp0", Routes: []JournalRoute{{CIDR: "10.20.0.0/16", Interface: "ppp0"}}, ResolverFiles: []JournalResolver{{Path: "/etc/resolver/corp.example.com", Content: "# managed by fortix profile=work\n"}}, DNSConfigured: true}
			if err := writeJournal(dir, j); err != nil {
				t.Fatal(err)
			}
			n := &recoveryNetwork{mode: mode}
			s := &Server{opts: Options{Paths: paths.Paths{State: dir}, Network: n, Deadlines: session.Deadlines{Network: 20 * time.Millisecond}}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := s.recover(ctx)
			if (err == nil) != (mode == "success") {
				t.Fatalf("recovery result: %v", err)
			}
			if mode == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline error lost: %v", err)
			}
			if !reflect.DeepEqual(n.recovered, j) {
				t.Fatalf("wrong recovery identity: %+v", n.recovered)
			}
			_, statErr := os.Stat(filepath.Join(dir, "work.json"))
			if mode == "success" {
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("clean journal remained: %v", statErr)
				}
			} else if statErr != nil {
				t.Fatalf("failed recovery lost journal: %v", statErr)
			}
		})
	}
}
