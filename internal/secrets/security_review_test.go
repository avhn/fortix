package secrets

import (
	"errors"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// TestEndpointBoundPasswords isolates saved passwords across each account identity
// component and deliberately leaves legacy profile-only entries undiscovered.
func TestEndpointBoundPasswords(t *testing.T) {
	p := profile.Profile{ID: "work", Gateway: profile.Gateway{Host: "vpn.example.com", Port: 443}, Username: "jane.doe"}
	store := &Memory{}
	if err := store.Set(p.ID, "legacy"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(Key(&p)); !errors.Is(err, ErrNotFound) {
		t.Fatal("legacy entry was reused")
	}
	if err := store.Set(Key(&p), "fixture-password"); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "host", "port", "username"} {
		other := p
		switch field {
		case "id":
			other.ID = "other"
		case "host":
			other.Gateway.Host = "other.example.com"
		case "port":
			other.Gateway.Port++
		case "username":
			other.Username = "other-user"
		}
		if _, err := store.Get(Key(&other)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("password crossed changed %s", field)
		}
	}
	if password, err := store.Get(Key(&p)); err != nil || password != "fixture-password" {
		t.Fatal("unchanged endpoint lost its password")
	}
	var account string
	k := Keyring{backend: &provider{get: func(service, key string) (string, error) { account = key; return "fixture-password", nil }}}
	if _, err := k.Get(Key(&p)); err != nil || account != Key(&p)+":password" {
		t.Fatal("keyring did not use the bound account")
	}
}
