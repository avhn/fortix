package helper

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/avhn/fortix/internal/profile"
)

// maxProfiles bounds supervisors and aggregate profile replies.
const maxProfiles = 128

// Store serializes profile publication under a pinned SYSTEM-owned directory.
type Store struct {
	mu  sync.Mutex
	dir *helperDirectory
}

// OpenStore refuses foreign ownership or a broad DACL instead of adopting existing data.
func OpenStore(path string) (*Store, error) {
	dir, err := openDirectory(path)
	if err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Close waits for any publication before releasing directory handles.
func (s *Store) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.dir.Close() }

// ValidID also rejects DOS device basenames before a profile reaches filesystem APIs.
func ValidID(id string) bool {
	if !profile.ValidID(id) {
		return false
	}
	switch id {
	case "con", "prn", "aux", "nul":
		return false
	}
	return !(len(id) == 4 && (strings.HasPrefix(id, "com") || strings.HasPrefix(id, "lpt")) && id[3] >= '0' && id[3] <= '9')
}

// Get bounds decoding and binds the embedded ID to the requested protected filename.
func (s *Store) Get(id string) (*profile.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidID(id) {
		return nil, errors.New("invalid profile id")
	}
	f, err := privateFileAt(s.dir, id+".json", os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p, err := profile.Decode(f)
	if err == nil && p.ID != id {
		return nil, errors.New("profile id does not match filename")
	}
	return p, err
}

// Put strictly decodes secret-free profile data before atomically replacing protected storage.
func (s *Store) Put(raw []byte) (*profile.Profile, error) {
	p, err := profile.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if !ValidID(p.ID) {
		return nil, errors.New("invalid profile id")
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := privateFileAt(s.dir, p.ID+".json", os.O_RDONLY)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if existing != nil {
		_ = existing.Close()
	} else {
		ids, err := s.names()
		if err != nil {
			return nil, err
		}
		if len(ids) >= maxProfiles {
			return nil, errors.New("profile limit reached")
		}
	}
	if err := atomicAt(s.dir, p.ID+".json", data, 0); err != nil {
		return nil, err
	}
	return p, nil
}

// Delete removes only an exact, verified regular file with a safe profile basename.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidID(id) {
		return errors.New("invalid profile id")
	}
	return removePrivateAt(s.dir, id+".json")
}

// IDs returns bounded sorted profile identifiers, validating contents only when loaded.
func (s *Store) IDs() ([]string, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.names() }

// names enumerates an independent bounded stream while the caller holds the store lock.
func (s *Store) names() ([]string, error) {
	entries, err := directoryEntries(s.dir, maxProfiles*2)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			id := strings.TrimSuffix(entry.Name(), ".json")
			if ValidID(id) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) > maxProfiles {
		return nil, errors.New("profile limit exceeded")
	}
	sort.Strings(ids)
	return ids, nil
}
