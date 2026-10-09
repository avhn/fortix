package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// Journal identifies one owned process generation without secrets. Network adapters
// can extend this record with exact owned routes/resolver entries and persist them
// before applying changes. PID alone never authorizes signalling during recovery.
type Journal = network.Journal

// JournalRoute identifies an owned route precisely enough to remove only the
// recorded destination, gateway and interface during teardown or crash recovery.
type JournalRoute = network.JournalRoute

// JournalResolver records the exact resolver path and content written by an attempt.
// Recovery must check ownership markers and content before removing the file.
type JournalResolver = network.JournalResolver

// writeJournal opens a private directory and persists one validated attempt record.
// Callers performing repeated writes use writeJournalAt with a pinned handle instead.
func writeJournal(dir string, j Journal) error {
	f, err := openDirectory(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return writeJournalAt(f, j)
}

// validJournal checks attempt identity without consulting the kernel. PID zero is
// a pre-spawn intent with no process identity; live records require a birth timestamp.
func validJournal(j Journal) bool {
	return ValidID(j.Profile) && j.Attempt > 0 && ((j.PID == 0 && j.StartTime == "") ||
		(j.PID > 1 && j.PID != os.Getpid() && j.StartTime != ""))
}

// writeJournalAt durably installs bounded process and network ownership metadata
// relative to a held directory. Invalid identities and oversized records fail closed.
func writeJournalAt(dir *os.File, j Journal) error {
	if !validJournal(j) {
		return errors.New("invalid journal identity")
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(data) > protocol.MaxLine {
		return errors.New("journal exceeds record limit")
	}
	return atomicAt(dir, j.Profile+".json", data, 0600)
}

// readJournalAt strictly decodes one private record relative to the pinned state
// directory, refusing unsafe files, oversized metadata and mismatched identifiers.
func readJournalAt(dir *os.File, id string) (Journal, error) {
	if !ValidID(id) {
		return Journal{}, errors.New("invalid journal id")
	}
	f, err := privateFileAt(dir, id+".json", unix.O_RDONLY)
	if err != nil {
		return Journal{}, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, protocol.MaxLine+1))
	if err != nil {
		return Journal{}, err
	}
	var j Journal
	if protocol.Decode(data, &j) != nil || j.Profile != id || !validJournal(j) {
		return Journal{}, errors.New("invalid journal data")
	}
	return j, nil
}

// removeJournal opens a checked directory and durably removes an attempt record.
// Missing records are already clean; unsafe directories and sync failures propagate.
func removeJournal(dir, id string) error {
	f, err := openDirectory(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return removeJournalAt(f, id)
}

// removeJournalAt durably removes an owned record through the pinned state handle.
// It never follows a replaced ancestor and treats an absent record as already clean.
func removeJournalAt(dir *os.File, id string) error {
	if !ValidID(id) {
		return errors.New("invalid journal id")
	}
	if err := unix.Unlinkat(int(dir.Fd()), id+".json", 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return dir.Sync()
}

// batchNetworkRecovery optionally rebuilds shared resource references from every
// validated startup journal before cleanup. Implementations must preserve borrowed
// resources and retain recoverable ownership metadata when reconciliation fails.
type batchNetworkRecovery interface {
	RecoverAll(context.Context, []Journal) error
}

// recover reconciles bounded private journals before opening control sockets.
// Invalid records block startup before mutation. Every recorded process is stopped
// before shared network recovery begins; a reused PID is never signalled. Batch-capable
// networks receive all journals together, and records are removed only after success.
func (s *Server) recover(ctx context.Context) error {
	dir := s.stateDir
	if dir == nil {
		// Standalone recovery callers pin the same checked directory for this operation.
		var err error
		dir, err = openDirectory(s.opts.Paths.State)
		if err != nil {
			return err
		}
		defer func() { _ = dir.Close() }()
	}
	entries, err := directoryEntries(dir, maxProfiles*2)
	if err != nil {
		return err
	}
	var journals []Journal
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !ValidID(id) {
			return errors.New("invalid journal filename")
		}
		j, err := readJournalAt(dir, id)
		if err != nil {
			return err
		}
		journals = append(journals, j)
	}
	for _, j := range journals {
		if err := recoverProcess(ctx, j); err != nil {
			return err
		}
	}
	budget := s.opts.Deadlines.Network
	if budget <= 0 {
		budget = session.DefaultDeadlines().Network
	}
	if batch, ok := s.opts.Network.(batchNetworkRecovery); ok && len(journals) > 0 {
		// Preserve the per-record budget while bounding the complete startup batch.
		recoveryCtx, cancel := context.WithTimeout(ctx, budget*time.Duration(len(journals)))
		err := batch.RecoverAll(recoveryCtx, journals)
		cancel()
		if err != nil {
			return err
		}
		for _, j := range journals {
			if err := removeJournalAt(dir, j.Profile); err != nil {
				return err
			}
		}
		return nil
	}
	for _, j := range journals {
		recoveryCtx, cancel := context.WithTimeout(ctx, budget)
		err := s.opts.Network.Recover(recoveryCtx, j)
		cancel()
		if err != nil {
			return err
		}
		if err := removeJournalAt(dir, j.Profile); err != nil {
			return err
		}
	}
	return nil
}

// recoverProcess stops only a live group leader whose birth timestamp matches the
// journal. It waits ten seconds after TERM, then KILL, with a finite final wait.
// Identity is rechecked before each signal so stale PIDs cannot target new processes.
func recoverProcess(ctx context.Context, j Journal) error {
	if j.PID == 0 {
		return nil
	}
	start, err := processStart(j.PID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return err
	}
	if start != j.StartTime {
		return nil
	}
	group, err := unix.Getpgid(j.PID)
	if err != nil {
		return err
	}
	if group != j.PID {
		return errors.New("journal process is not its group leader")
	}
	if err := unix.Kill(-j.PID, unix.SIGTERM); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	grace := time.NewTimer(10 * time.Second)
	defer grace.Stop()
	final := time.NewTimer(15 * time.Second)
	defer final.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-final.C:
			return errors.New("orphan process did not exit")
		case <-grace.C:
			start, err := processStart(j.PID)
			if err == nil && start == j.StartTime {
				if err := unix.Kill(-j.PID, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
					return err
				}
			}
		case <-tick.C:
			start, err := processStart(j.PID)
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) || (err == nil && start != j.StartTime) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
}
