package secrets

import (
	"errors"
	"strings"
	"testing"
)

// TestOversizedPassword rejects values before entering a provider with a bounded command channel.
func TestOversizedPassword(t *testing.T) {
	called := false
	k := Keyring{backend: &provider{set: func(string, string, string) error { called = true; return nil }}}
	if err := k.Set("work", strings.Repeat("x", maxPasswordBytes+1)); !errors.Is(err, ErrTooLong) || called {
		t.Fatalf("oversized write: %v called=%v", err, called)
	}
	if err := k.Set("work", strings.Repeat("x", maxPasswordBytes)); err != nil || !called {
		t.Fatalf("boundary write: %v called=%v", err, called)
	}
}
