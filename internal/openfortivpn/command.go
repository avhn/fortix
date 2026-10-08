package openfortivpn

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/avhn/fortix/internal/profile"
)

// WorkingDirectory is the fixed child working directory, independent of user files.
// The supervisor must use it when executing the argv returned by BuildCommand.
const WorkingDirectory = "/"

// Options supplies helper-controlled executable and relay locations and attempt token.
// Paths must be clean and absolute. AttemptToken is 32 random bytes encoded as 64
// lowercase hex characters; the caller generates it and verifies executable trust.
type Options struct {
	Executable     string
	Pinentry       string
	PinentrySocket string
	AttemptToken   string
}

// BuildCommand returns complete argv (including executable) and the entire environment.
// It validates a copy of p without altering it, rejects invalid options or profiles,
// and returns nil slices on error. Secrets and caller-provided raw options are never
// accepted. The caller must replace, not append to, the inherited environment.
func BuildCommand(p *profile.Profile, opts Options) (argv, env []string, err error) {
	if p == nil {
		return nil, nil, errors.New("openfortivpn: profile must not be nil")
	}
	validated := *p
	if err := validated.Validate(); err != nil {
		return nil, nil, fmt.Errorf("openfortivpn profile: %w", err)
	}
	for _, path := range []string{opts.Executable, opts.Pinentry, opts.PinentrySocket} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsFunc(path, unicode.IsControl) {
			return nil, nil, errors.New("openfortivpn: executable and relay paths must be clean absolute paths")
		}
	}
	if len(opts.AttemptToken) != 64 || strings.ToLower(opts.AttemptToken) != opts.AttemptToken {
		return nil, nil, errors.New("openfortivpn: attempt token must be 64 lowercase hex characters")
	}
	if _, err := hex.DecodeString(opts.AttemptToken); err != nil {
		return nil, nil, errors.New("openfortivpn: attempt token must be 64 lowercase hex characters")
	}
	argv = []string{opts.Executable, net.JoinHostPort(validated.Gateway.Host, strconv.Itoa(validated.Gateway.Port))}
	if validated.TrustedCert != "" {
		argv = append(argv, "--trusted-cert="+validated.TrustedCert)
	}
	routes := "1"
	if validated.Routes.Mode == "custom" {
		routes = "0"
	}
	// Disable both DNS writers so the helper remains the single DNS owner.
	argv = append(argv, "--pinentry="+opts.Pinentry, "-c", "/dev/fd/3", "--set-dns=0", "--pppd-use-peerdns=0", "--set-routes="+routes)
	if validated.MFA.Mode != "push" {
		argv = append(argv, "--no-ftm-push")
	}
	env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "FORTIX_PINENTRY_SOCKET=" + opts.PinentrySocket, "FORTIX_ATTEMPT_TOKEN=" + opts.AttemptToken}
	return argv, env, nil
}

// Config encodes validated account fields for an inherited anonymous pipe at fd 3.
// Control characters are refused by profile validation, so values cannot add keys.
// The caller closes the pipe after spawn and never writes these bytes to disk.
func Config(p *profile.Profile) ([]byte, error) {
	if p == nil {
		return nil, errors.New("openfortivpn: profile must not be nil")
	}
	validated := *p
	if err := validated.Validate(); err != nil {
		return nil, err
	}
	config := "username = " + validated.Username + "\n"
	if validated.Realm != "" {
		config += "realm = " + validated.Realm + "\n"
	}
	return []byte(config), nil
}
