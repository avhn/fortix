package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/protocol"
)

// TestSavedPasswordFailureHint limits recovery advice to typed authentication
// rejection, while every terminal failure still releases the attempt credential.
func TestSavedPasswordFailureHint(t *testing.T) {
	for _, code := range []protocol.Code{backend.AuthenticationFailedCode, "", protocol.Conflict, protocol.InterfaceMismatch, protocol.Internal} {
		t.Run(string(code), func(t *testing.T) {
			var output bytes.Buffer
			r := runner{errout: &output, credentials: map[string]credential{"work": {attempt: 1, keyring: true}}}
			if err := r.finishCredential(protocol.Event{Profile: "work", Attempt: 1, State: "failed", Code: code}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(output.String(), "fortix password clear"); got != (code == backend.AuthenticationFailedCode) {
				t.Fatalf("code %q produced advice %q", code, output.String())
			}
			if len(r.credentials) != 0 {
				t.Fatal("terminal failure retained a credential")
			}
		})
	}
}
