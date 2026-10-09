package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// Journal preserves the network adapter's typed secret-free attempt metadata.
type Journal = network.Journal

// JournalRoute retains portable route diagnostic fields and exact Windows ownership.
type JournalRoute = network.JournalRoute

// JournalResolver preserves the shared API; Windows rejects filesystem resolver records.
type JournalResolver = network.JournalResolver

// validJournal refuses external-process identities and all unsupported transport metadata.
func validJournal(j Journal) bool {
	return ValidID(j.Profile) && j.Attempt > 0 && j.Backend == "native" && j.PID == 0 && j.StartTime == "" && len(j.ResolverFiles) == 0 && (j.Link == nil || j.Link.PID == 0 && j.Link.StartTime == "")
}

// writeJournal opens protected storage for isolated persistence callers.
func writeJournal(path string, j Journal) error {
	dir, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return writeJournalAt(dir, j)
}

// writeJournalAt persists only bounded native attempt records under a distinct namespace.
func writeJournalAt(dir *helperDirectory, j Journal) error {
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
	return atomicAt(dir, "helper-"+j.Profile+".json", data, 0)
}

// readJournalAt checks the protected file before strict bounded decoding and identity checks.
func readJournalAt(dir *helperDirectory, id string) (Journal, error) {
	if !ValidID(id) {
		return Journal{}, errors.New("invalid journal id")
	}
	f, err := privateFileAt(dir, "helper-"+id+".json", os.O_RDONLY)
	if err != nil {
		return Journal{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, protocol.MaxLine+1))
	if err != nil {
		return Journal{}, err
	}
	var j Journal
	if len(data) > protocol.MaxLine || protocol.Decode(data, &j) != nil || j.Profile != id || !validJournal(j) {
		return Journal{}, errors.New("invalid journal data")
	}
	return j, nil
}

// removeJournal opens protected storage for standalone removal callers.
func removeJournal(path, id string) error {
	dir, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return removeJournalAt(dir, id)
}

// removeJournalAt finalizes Windows ownership after shared code has released transport.
// Failure keeps the helper journal so the next cleanup retry cannot forget the generation.
func removeJournalAt(dir *helperDirectory, id string) error {
	if !ValidID(id) {
		return errors.New("invalid journal id")
	}
	j, err := readJournalAt(dir, id)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if dir.finalize != nil {
		if err := dir.finalize(j); err != nil {
			return err
		}
	}
	return removePrivateAt(dir, "helper-"+id+".json")
}

// batchNetworkRecovery reconciles allocation ledgers even when no helper journal exists.
type batchNetworkRecovery interface {
	RecoverAll(context.Context, []Journal) error
}

// recover validates helper records before network recovery and never signals Windows PIDs.
func (s *Server) recover(ctx context.Context) error {
	entries, err := directoryEntries(s.stateDir, 4096)
	if err != nil {
		return err
	}
	var journals []Journal
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "helper-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "helper-"), ".json")
		j, err := readJournalAt(s.stateDir, id)
		if err != nil {
			return err
		}
		journals = append(journals, j)
		if len(journals) > maxProfiles {
			return errors.New("too many helper journals")
		}
	}
	batch, ok := s.opts.Network.(batchNetworkRecovery)
	if !ok {
		return errors.New("Windows network requires batch recovery")
	}
	budget := s.opts.Deadlines.Network
	if budget <= 0 {
		budget = session.DefaultDeadlines().Network
	}
	recoveryCtx, cancel := context.WithTimeout(ctx, budget*time.Duration(max(1, len(journals))))
	err = batch.RecoverAll(recoveryCtx, journals)
	cancel()
	if err != nil {
		return err
	}
	for _, j := range journals {
		if err := removePrivateAt(s.stateDir, "helper-"+j.Profile+".json"); err != nil {
			return err
		}
	}
	return nil
}
