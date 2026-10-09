//go:build darwin || linux

package helpercmd

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

// TestRejectedCommands verifies unsafe development roots and unsupported commands
// fail before touching privileged paths. Pinentry configuration is likewise bounded.
func TestRejectedCommands(t *testing.T) {
	cases := [][]string{nil, {"fortix-helper", "unknown"}, {"fortix-helper", "install"}, {"fortix-helper", "uninstall"}, {"fortix-helper", "serve", "--dev-root", "/"},
		{"fortix-helper", "serve", "--dev-root", "relative"}, {"fortix-helper", "serve", "--dev-root", "/tmp/../tmp"}}
	if os.Geteuid() != 0 {
		cases = append(cases, []string{"fortix-helper", "serve"})
	}
	for _, argv := range cases {
		var output bytes.Buffer
		if Run(context.Background(), argv, strings.NewReader(""), &output, &output) == nil {
			t.Fatalf("accepted command %v", argv)
		}
	}
	t.Setenv("FORTIX_PINENTRY_SOCKET", "")
	t.Setenv("FORTIX_ATTEMPT_TOKEN", "")
	if Run(context.Background(), []string{"/tmp/fortix-pinentry"}, strings.NewReader("GETPIN\n"), &bytes.Buffer{}, &bytes.Buffer{}) == nil {
		t.Fatal("pinentry accepted missing configuration")
	}
}
