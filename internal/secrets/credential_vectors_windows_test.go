package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// credentialVector records the exact UTF-8 JSON tuple and Windows credential target.
// Field ordering is stable so regenerated fixtures remain byte-identical.
type credentialVector struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	TupleJSON string `json:"tuple_json"`
	Target    string `json:"target"`
}

// credentialVectors supplies synthetic identities with Go's Unicode and HTML-sensitive escaping.
// These golden vectors are shared with Windows clients that must hash the same UTF-8 bytes.
func credentialVectors() []credentialVector {
	return []credentialVector{
		{Name: "ascii", ID: "office", Host: "vpn.example.com", Port: 443, Username: "alice",
			Target: "fortix:office:1e37db253af678a3c9010637555e6a96fb5a3a71ed566bc4abf79ce423186bc7:password"},
		{Name: "unicode", ID: "office", Host: "vpn.example.com", Port: 443, Username: "İpek.東京",
			Target: "fortix:office:c4f955a2f5814ef6ac45ff82cf58f5a45c88d8cf02b6e0f6569e3e1a3b2c9e44:password"},
		{Name: "json-escaped", ID: "office", Host: "vpn.example.com", Port: 443, Username: "quote\"slash\\<&>",
			Target: "fortix:office:a8f5ff4a15013eed701ab70b14af510385e2790e6516fbb95ab193cad3a99b8a:password"},
	}
}

// TestWindowsCredentialVectors checks shared Key hashing and deterministic JSON fixture generation.
// Golden: ["vpn.example.com",443,"alice"] -> fortix:office:1e37db253af678a3c9010637555e6a96fb5a3a71ed566bc4abf79ce423186bc7:password.
// Golden: ["vpn.example.com",443,"İpek.東京"] -> fortix:office:c4f955a2f5814ef6ac45ff82cf58f5a45c88d8cf02b6e0f6569e3e1a3b2c9e44:password.
// Golden escaped username quote"slash\<&> -> fortix:office:a8f5ff4a15013eed701ab70b14af510385e2790e6516fbb95ab193cad3a99b8a:password.
func TestWindowsCredentialVectors(t *testing.T) {
	vectors := credentialVectors()
	for i := range vectors {
		v := &vectors[i]
		tuple, err := json.Marshal([]any{v.Host, v.Port, v.Username})
		if err != nil {
			t.Fatal(err)
		}
		v.TupleJSON = string(tuple)
		p := &profile.Profile{ID: v.ID, Gateway: profile.Gateway{Host: v.Host, Port: v.Port}, Username: v.Username}
		if target := "fortix:" + Key(p) + ":password"; target != v.Target {
			t.Fatalf("%s: target %q, want %q", v.Name, target, v.Target)
		}
		if target := fmt.Sprintf("fortix:%s:%x:password", v.ID, sha256.Sum256(tuple)); target != v.Target {
			t.Fatalf("%s: tuple hash differs from golden target", v.Name)
		}
	}
	generated, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "credential-targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(generated, '\n'), fixture) {
		t.Fatal("credential targets fixture differs from deterministic generation")
	}
}
