package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/client"
)

// TestWindowsOfflineSyntax retains argument validation without Unix sockets or helper impersonation.
func TestWindowsOfflineSyntax(t *testing.T) {
	for _, command := range [][]string{{"version"}, {"profile", "validate"}, {"profile", "list"}, {"profile", "show"}, {"profile", "add"}, {"profile", "rm"}, {"import", "forticlient"}, {"password", "set"}, {"password", "clear"}, {"up"}, {"down"}, {"status"}, {"logs"}, {"trust"}, {"profile"}, {"password"}, {"import"}, {"profile", "export"}, {"profile", "import"}} {
		var out, diag bytes.Buffer
		args := append(command, "--help")
		if code := RunContext(t.Context(), args, &out, &diag, Options{}); code != 0 || !strings.Contains(out.String(), "usage:") || diag.Len() != 0 {
			t.Fatalf("%v: %d %s %s", args, code, &out, &diag)
		}
	}
	options := Options{Client: client.Options{Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("invalid arguments reached transport")
		return nil, nil
	}}}
	for _, args := range [][]string{{"up"}, {"up", "work", "--all"}, {"up", "work", "work"}, {"up", "../work"}, {"down"}, {"status", "extra"}, {"logs", "work", "--lines", "501"}, {"profile", "show"}, {"trust", "work", "--unknown"}, {"profile", "export"}, {"profile", "export", "../work"}, {"profile", "export", "work", "work"}, {"profile", "import"}, {"profile", "import", "shared.json", "--id", "../work"}, {"profile", "import", "shared.json", "--merge", "work", "--id", "other"}} {
		if code := RunContext(t.Context(), args, io.Discard, io.Discard, options); code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
	}
	for _, args := range [][]string{{"profile", "export", "work", "-o", "shared.json", "--force"}, {"profile", "export", "--force", "-o", "shared.json", "work"}, {"profile", "import", "-", "--username", "local-user", "--yes"}, {"profile", "import", "--username", "local-user", "--yes", "-"}} {
		if _, err := parseCommand(args, io.Discard, io.Discard); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}
