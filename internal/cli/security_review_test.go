package cli

import (
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
)

// TestRemoveAliasAndFailureStatus verifies both deletion spellings target the
// same helper operation and plain status includes the actionable failure detail.
func TestRemoveAliasAndFailureStatus(t *testing.T) {
	for _, subcommand := range []string{"rm", "remove"} {
		deleted := false
		socket := fakeSocket(t, func(r protocol.Request) (any, []protocol.Event, *protocol.Error) {
			deleted = r.Op == "profile.delete" && r.Profile == "work"
			return nil, nil, nil
		})
		code, _, diag := runCommand(t, []string{"profile", subcommand, "work"}, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
		if code != 0 || !deleted {
			t.Fatalf("%s: %d %s", subcommand, code, diag)
		}
	}
	detail := "openfortivpn not found or not trusted; see helper log"
	socket := fakeSocket(t, func(protocol.Request) (any, []protocol.Event, *protocol.Error) {
		return []statusEntry{{Profile: "work", State: "failed", Detail: detail}}, nil, nil
	})
	code, out, diag := runCommand(t, []string{"status"}, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
	if code != 0 || !strings.Contains(out, detail) {
		t.Fatalf("failure detail missing: %d %s %s", code, out, diag)
	}
}
