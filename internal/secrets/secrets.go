// Package secrets stores profile passwords in the OS keyring or an explicit test fake.
// Missing entries and inaccessible keyrings are distinct errors; no disk fallback exists.
package secrets

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"regexp"
	"sync"

	"github.com/avhn/fortix/internal/profile"

	"github.com/zalando/go-keyring"
)

// Credential errors distinguish a missing password from an unavailable secure store.
// ErrInvalidID rejects identifiers outside the profile identifier alphabet.
// ErrTooLong rejects passwords exceeding the provider's safe input limit.
var (
	ErrNotFound    = errors.New("password not found")
	ErrUnavailable = errors.New("secure keyring unavailable")
	ErrInvalidID   = errors.New("invalid profile id")
	ErrTooLong     = errors.New("password exceeds secure storage size limit")
	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}(:[a-f0-9]{64})?$`)
)

// maxPasswordBytes keeps the encoded macOS security input below its 4096-byte command limit.
// Rejecting oversized values before invoking the provider also avoids leaving a waiting child.
const maxPasswordBytes = 2800

// Store gets, replaces, or deletes the password for a profile identifier.
// Get returns an empty string on errors. Delete reports ErrNotFound for missing entries.
// Implementations never include passwords or underlying provider output in errors.
type Store interface {
	Get(id string) (string, error)
	Set(id, password string) error
	Delete(id string) error
}

// provider is the injectable OS keyring API; service and account select one credential.
// Provider errors are sanitized before they cross the Store boundary.
type provider struct {
	get    func(string, string) (string, error)
	set    func(string, string, string) error
	delete func(string, string) error
}

// Keyring uses service fortix and account <bound-profile-key>:password in the system keyring.
// Its zero value is usable and never substitutes an insecure storage backend.
type Keyring struct{ backend *provider }

// api returns the injected provider or the production keyring functions without I/O.
func (k Keyring) api() provider {
	if k.backend != nil {
		return *k.backend
	}
	return provider{get: keyring.Get, set: keyring.Set, delete: keyring.Delete}
}

// Get retrieves id's password; missing and locked stores return typed, sanitized errors.
func (k Keyring) Get(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrInvalidID
	}
	password, err := k.api().get("fortix", id+":password")
	if err != nil {
		return "", classify(err)
	}
	return password, nil
}

// Set replaces id's password securely, returning ErrUnavailable when storage fails.
// Invalid identifiers return ErrInvalidID; oversized passwords return ErrTooLong before I/O.
func (k Keyring) Set(id, password string) error {
	if !idPattern.MatchString(id) {
		return ErrInvalidID
	}
	if len(password) > maxPasswordBytes {
		return ErrTooLong
	}
	return classify(k.api().set("fortix", id+":password", password))
}

// Delete removes id's password, reporting missing entries and inaccessible stores.
func (k Keyring) Delete(id string) error {
	if !idPattern.MatchString(id) {
		return ErrInvalidID
	}
	return classify(k.api().delete("fortix", id+":password"))
}

// classify maps provider failures without exposing command output or secret material.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return ErrUnavailable
}

// Memory is a concurrency-safe, explicit in-memory fake, not a keyring fallback.
// Its zero value is ready for use; credentials disappear with the process.
type Memory struct {
	mu        sync.RWMutex
	passwords map[string]string
}

// Get returns the fake password for id, or ErrNotFound when no entry exists.
func (m *Memory) Get(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrInvalidID
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	password, ok := m.passwords[id]
	if !ok {
		return "", ErrNotFound
	}
	return password, nil
}

// Set replaces the fake password for id, lazily allocating the private map.
func (m *Memory) Set(id, password string) error {
	if !idPattern.MatchString(id) {
		return ErrInvalidID
	}
	if len(password) > maxPasswordBytes {
		return ErrTooLong
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.passwords == nil {
		m.passwords = make(map[string]string)
	}
	m.passwords[id] = password
	return nil
}

// Delete removes the fake password for id and returns ErrNotFound if absent.
func (m *Memory) Delete(id string) error {
	if !idPattern.MatchString(id) {
		return ErrInvalidID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.passwords[id]; !ok {
		return ErrNotFound
	}
	delete(m.passwords, id)
	return nil
}

// Key binds a password to its profile ID, gateway host/port, and username.
// Encoding a tuple before hashing prevents ambiguous concatenation. Legacy ID-only
// accounts are deliberately not queried, so gateway changes require fresh input.
func Key(p *profile.Profile) string {
	data, _ := json.Marshal([]any{p.Gateway.Host, p.Gateway.Port, p.Username})
	return fmt.Sprintf("%s:%x", p.ID, sha256.Sum256(data))
}
