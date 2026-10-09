package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/native"
	"github.com/avhn/fortix/internal/network"
)

// TestNativeDiagnosticRedaction verifies native terminal messages use the same
// known-secret, cookie-label and control filtering as external process output.
func TestNativeDiagnosticRedaction(t *testing.T) {
	dir := t.TempDir()
	log, err := openLog(dir, "work")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	log.protect([]byte("fixture-private-password"))
	a := supervisor{id: "work", server: &Server{}}
	a.nativeDiagnostic(log, 1, "terminal error: fixture-private-password\nSVPNCOOKIE=fixture-cookie")
	data, err := os.ReadFile(filepath.Join(dir, "work.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "fixture-private-password") || strings.Contains(string(data), "fixture-cookie") || strings.Count(string(data), "\n") != 1 {
		t.Fatalf("unsafe diagnostic: %q", data)
	}
	if !strings.Contains(string(data), "terminal error:") || !strings.Contains(string(data), "[redacted]") {
		t.Fatalf("diagnostic missing: %q", data)
	}
}

// TestNativeOutcomeDetails checks typed, body-free causes and preserves the empty
// failure category needed for the reducer's connected-transport retry inference.
func TestNativeOutcomeDetails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		failure backend.Failure
		detail  string
	}{
		{"authentication", native.ErrAuthentication, backend.AuthFailure, "authentication rejected"},
		{"MFA", &native.UnsupportedMFA{}, backend.AuthFailure, "native backend does not support second factors; select openfortivpn"},
		{"HTTP", &native.HTTPError{Status: 403}, backend.ProcessFailure, "gateway HTTP status 403"},
		{"conflict", &network.ConflictError{Detail: "fixture collision"}, backend.ConflictFailure, "network conflict; see profile log"},
		{"transport", errors.New("EOF"), "", "native backend failed; see profile log"},
		{"cancelled", context.Canceled, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := nativeOutcome(backend.Outcome{ExitCode: 1}, tc.err)
			if got.Failure != tc.failure || got.Detail != tc.detail {
				t.Fatalf("outcome %+v, want %q %q", got, tc.failure, tc.detail)
			}
		})
	}
}
