// Package helper owns authenticated local control, child lifecycles, and private
// credential forwarding. Privileged paths and network work are injectable for tests.
package helper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/profile"
)

// maxProfiles bounds the registry and aggregate child processes on one machine.
const maxProfiles = 128

// Store holds a trusted profile directory descriptor. Operations are serialized so
// atomic replacement, listing, and deletion cannot observe a partially written file.
type Store struct {
	mu    sync.Mutex
	dir   *os.File
	owner uint32
}

// OpenStore opens a non-symlink directory with no untrusted writers, owned by the
// effective user (root in production). It never creates the directory or follows links.
func OpenStore(path string) (*Store, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open profile directory: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	stat := unix.Stat_t{}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
		_ = f.Close()
		return nil, errors.New("unsafe profile directory")
	}
	return &Store{dir: f, owner: stat.Uid}, nil
}

// Close releases the directory descriptor after all operations have completed.
func (s *Store) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.dir.Close() }

// ValidID accepts only the profile schema's ASCII filename alphabet and length.
// Invalid IDs are refused before any filesystem call and cannot escape the directory.
func ValidID(id string) bool {
	if len(id) < 1 || len(id) > 63 || id[0] == '-' {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// Get loads a validated ID through O_NOFOLLOW and verifies its descriptor's owner,
// regular-file type, and exact mode before bounded profile decoding. It rejects an
// embedded ID that differs from the requested filename and returns no partial profile.
func (s *Store) Get(id string) (*profile.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidID(id) {
		return nil, errors.New("invalid profile id")
	}
	fd, err := unix.Openat(int(s.dir.Fd()), id+".json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), id)
	defer func() { _ = f.Close() }()
	stat := unix.Stat_t{}
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != s.owner || stat.Mode&07777 != 0644 {
		return nil, errors.New("unsafe profile file")
	}
	p, err := profile.Decode(f)
	if err != nil {
		return nil, err
	}
	if p.ID != id {
		return nil, errors.New("profile id does not match filename")
	}
	return p, nil
}

// Put strictly decodes raw JSON and atomically installs a root-owned 0644 copy.
// Temporary data is written in the same directory, synced, renamed, and the directory
// is synced. Existing symlinks or special files are rejected rather than replaced.
func (s *Store) Put(raw []byte) (*profile.Profile, error) {
	p, err := profile.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name := p.ID + ".json"
	var stat unix.Stat_t
	err = unix.Fstatat(int(s.dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	if err == nil && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != s.owner || stat.Mode&07777 != 0644) {
		return nil, errors.New("unsafe existing profile")
	}
	if errors.Is(err, unix.ENOENT) {
		names, err := s.names()
		if err != nil {
			return nil, err
		}
		if len(names) >= maxProfiles {
			return nil, errors.New("profile limit reached")
		}
	}
	if err := atomicAt(s.dir, name, data, 0644); err != nil {
		return nil, err
	}
	return p, nil
}

// Delete removes only a validated regular profile file without following links.
// Missing files and failed directory syncing are reported to the caller.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidID(id) {
		return errors.New("invalid profile id")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(s.dir.Fd()), id+".json", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != s.owner || st.Mode&07777 != 0644 {
		return errors.New("unsafe profile file")
	}
	if err := unix.Unlinkat(int(s.dir.Fd()), id+".json", 0); err != nil {
		return err
	}
	return s.dir.Sync()
}

// IDs returns bounded, lexically sorted profile identifiers. Invalid JSON filenames
// and unrelated temporary files are ignored; candidate files are validated when read.
func (s *Store) IDs() ([]string, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.names() }

// names opens an independent directory stream and collects bounded JSON filenames.
// The caller holds s.mu; using a fresh descriptor avoids shared directory offsets.
func (s *Store) names() ([]string, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "profiles")
	defer func() { _ = dir.Close() }()
	names := make([]string, 0)
	for {
		entries, err := dir.ReadDir(128)
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".json") {
				id := strings.TrimSuffix(entry.Name(), ".json")
				if !ValidID(id) {
					continue
				}
				if len(names) >= maxProfiles {
					return nil, errors.New("profile limit exceeded")
				}
				names = append(names, id)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}

// atomicAt installs data using an exclusive random file relative to a held directory.
// It never follows the destination and removes the temporary file on every failure.
func atomicAt(dir *os.File, name string, data []byte, mode uint32) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	temp := ".tmp-" + token
	fd, err := unix.Openat(int(dir.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), temp)
	defer func() { _ = f.Close(); _ = unix.Unlinkat(int(dir.Fd()), temp, 0) }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(int(dir.Fd()), temp, int(dir.Fd()), name); err != nil {
		return err
	}
	return dir.Sync()
}

// secureDir creates path with a fixed mode and verifies final ownership and type.
// The caller verifies ancestor trust before creation. Final symlinks and existing
// unsafe directories are rejected, never chmodded into apparent safety.
func secureDir(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("directory must be absolute and clean")
	}
	_, beforeErr := os.Lstat(path)
	if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
		return beforeErr
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if !st.IsDir() || stat.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe directory ownership or mode")
	}
	// Set exact permissions only for a directory this call created, independent of umask.
	if errors.Is(beforeErr, os.ErrNotExist) {
		return os.Chmod(path, mode)
	}
	if st.Mode().Perm() & ^mode != 0 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("unsafe directory mode")
	}
	return nil
}
