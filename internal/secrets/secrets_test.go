package secrets

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestMemory exercises missing, replacement, isolation, deletion, and identifier rejection.
func TestMemory(t *testing.T) {
	var m Memory
	if _, err := m.Get("work"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := m.Delete("work"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	for _, password := range []string{"test-password", "", "replacement"} {
		if err := m.Set("work", password); err != nil {
			t.Fatal(err)
		}
		if got, err := m.Get("work"); err != nil || got != password {
			t.Fatalf("get: %q %v", got, err)
		}
	}
	if _, err := m.Get("other"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := m.Delete("work"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../work", "Work", "work:second", "work\n"} {
		if err := m.Set(id, "test-password"); !errors.Is(err, ErrInvalidID) {
			t.Fatal(err)
		}
		if _, err := m.Get(id); !errors.Is(err, ErrInvalidID) {
			t.Fatal(err)
		}
		if err := m.Delete(id); !errors.Is(err, ErrInvalidID) {
			t.Fatal(err)
		}
	}
}

// TestKeyring verifies the exact keychain namespace and sanitization of all failure paths.
func TestKeyring(t *testing.T) {
	for _, tc := range []struct {
		name               string
		backendError, want error
	}{
		{"ok", nil, nil}, {"missing", fmt.Errorf("wrapped: %w", keyring.ErrNotFound), ErrNotFound},
		{"locked", errors.New("locked test-password"), ErrUnavailable},
		{"unsupported", keyring.ErrUnsupportedPlatform, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(service, account string) {
				t.Helper()
				if service != "fortix" || account != "work:password" {
					t.Fatalf("namespace: %q %q", service, account)
				}
			}
			k := Keyring{backend: &provider{
				get: func(service, account string) (string, error) {
					check(service, account)
					return "test-password", tc.backendError
				},
				set: func(service, account, password string) error {
					check(service, account)
					if password != "test-password" {
						t.Fatal("wrong password")
					}
					return tc.backendError
				},
				delete: func(service, account string) error { check(service, account); return tc.backendError },
			}}
			got, err := k.Get("work")
			if !errors.Is(err, tc.want) {
				t.Fatalf("get error: %v", err)
			}
			if tc.want != nil && got != "" {
				t.Fatal("secret returned with error")
			}
			if tc.want == nil && got != "test-password" {
				t.Fatal("wrong secret")
			}
			if err := k.Set("work", "test-password"); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if err := k.Delete("work"); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if _, err := k.Get("../work"); !errors.Is(err, ErrInvalidID) {
				t.Fatal(err)
			}
			if err := k.Set("../work", "test-password"); !errors.Is(err, ErrInvalidID) {
				t.Fatal(err)
			}
			if err := k.Delete("../work"); !errors.Is(err, ErrInvalidID) {
				t.Fatal(err)
			}
		})
	}
}

// TestMemoryConcurrent uses independent profiles to exercise synchronized map access under race detection.
func TestMemoryConcurrent(t *testing.T) {
	var m Memory
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			id := fmt.Sprintf("vpn-%d", i)
			if err := m.Set(id, "test-password"); err != nil {
				t.Error(err)
			}
			if _, err := m.Get(id); err != nil {
				t.Error(err)
			}
			if err := m.Delete(id); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

// TestPasswordSize distinguishes invalid input from unavailable storage without provider calls.
func TestPasswordSize(t *testing.T) {
	calls := 0
	k := Keyring{backend: &provider{set: func(_, _, _ string) error { calls++; return nil }}}
	var memory Memory
	for _, store := range []Store{k, &memory} {
		if err := store.Set("work", strings.Repeat("x", maxPasswordBytes)); err != nil {
			t.Fatal(err)
		}
		if err := store.Set("work", strings.Repeat("x", maxPasswordBytes+1)); !errors.Is(err, ErrTooLong) || errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("provider calls: %d", calls)
	}
}
