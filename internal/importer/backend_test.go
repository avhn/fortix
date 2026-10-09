package importer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// TestImportLeavesBackendOmitted verifies import does not pin a backend before the
// user edits MFA; saved drafts resolve through the same strict profile decoder.
func TestImportLeavesBackendOmitted(t *testing.T) {
	drafts, _, err := Decode(bytes.NewReader(fixture(t)))
	if err != nil || len(drafts) == 0 {
		t.Fatalf("decode: %v", err)
	}
	for _, p := range drafts {
		if p.Backend != "" {
			t.Fatalf("import pinned backend %q", p.Backend)
		}
		for _, mode := range []string{"none", "push", "prompt", "totp", "static"} {
			p.MFA = profile.MFA{Mode: mode}
			data, err := json.Marshal(p)
			if err != nil || strings.Contains(string(data), `"backend"`) {
				t.Fatalf("draft backend not omitted: %s, %v", data, err)
			}
			resolved, err := profile.Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			want := "openfortivpn"
			if mode == "none" {
				want = "native"
			}
			if resolved.Backend != want {
				t.Fatalf("%s backend = %s, want %s", mode, resolved.Backend, want)
			}
		}
	}
}
