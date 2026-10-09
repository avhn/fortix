//go:build darwin || linux

package openfortivpn

import (
	"reflect"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// commandProfile returns a defaulted, secret-free public fixture for independent tests.
// It does no I/O and supplies valid schema, gateway, and account fields.
func commandProfile() *profile.Profile {
	p := &profile.Profile{SchemaVersion: 1, ID: "work", Name: "Work", Backend: "openfortivpn", Gateway: profile.Gateway{Host: "vpn.example.com", Port: 10443}, Username: "jane.doe"}
	p.ApplyDefaults()
	return p
}

// commandOptions returns helper-controlled public fixture paths and a synthetic token.
// It is deterministic and never generates or reads actual credentials.
func commandOptions() Options {
	return Options{Executable: "/usr/bin/openfortivpn", Pinentry: "/usr/local/libexec/fortix/fortix-pinentry", PinentrySocket: "/run/fortix/private/pinentry.sock", AttemptToken: strings.Repeat("ab", 32)}
}

// TestBuildCommand checks all route and MFA combinations against complete argv and env.
// Forbidden credential, verbosity, and executable-option flags must never be emitted.
func TestBuildCommand(t *testing.T) {
	for _, routes := range []string{"gateway", "full", "custom"} {
		for _, mfa := range []string{"none", "push", "prompt", "totp", "static"} {
			t.Run(routes+"/"+mfa, func(t *testing.T) {
				p := commandProfile()
				p.Routes.Mode, p.MFA.Mode = routes, mfa
				p.ApplyDefaults()
				if routes == "custom" {
					p.Routes.Include = []string{"10.20.0.0/16"}
				}
				o := commandOptions()
				argv, env, err := BuildCommand(p, o)
				if err != nil {
					t.Fatal(err)
				}
				setting := "1"
				if routes == "custom" {
					setting = "0"
				}
				want := []string{o.Executable, "vpn.example.com:10443", "--pinentry=" + o.Pinentry, "-c", "/dev/fd/3", "--set-dns=0", "--pppd-use-peerdns=0", "--set-routes=" + setting}
				if mfa != "push" {
					want = append(want, "--no-ftm-push")
				}
				wantEnv := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "FORTIX_PINENTRY_SOCKET=" + o.PinentrySocket, "FORTIX_ATTEMPT_TOKEN=" + o.AttemptToken}
				if !reflect.DeepEqual(argv, want) || !reflect.DeepEqual(env, wantEnv) || WorkingDirectory != "/" {
					t.Fatalf("incorrect invocation: %q, %q", argv, env)
				}
				for _, arg := range argv {
					for _, forbidden := range []string{"-p", "--otp", "--pppd-plugin", "--pppd-call", "--pppd-ipparam", "--pppd-log", "-v"} {
						if arg == forbidden || strings.HasPrefix(arg, forbidden+"=") {
							t.Fatalf("forbidden flag %q", arg)
						}
					}
				}
			})
		}
	}
}

// TestCommandOptionalFields checks realm, pin normalization, IPv6 brackets, and
// shell-like username text as a single argument. Validation must not mutate p.
func TestCommandOptionalFields(t *testing.T) {
	p := commandProfile()
	p.Realm, p.TrustedCert = "work", strings.Repeat("AB:", 31)+"AB"
	p.Gateway.Host = "2001:db8::1"
	p.Username = "jane.doe; $(false)"
	before := *p
	argv, _, err := BuildCommand(p, commandOptions())
	if err != nil {
		t.Fatal(err)
	}
	if argv[1] != "[2001:db8::1]:10443" || argv[2] != "--trusted-cert="+strings.Repeat("ab", 32) {
		t.Fatalf("optional fields changed: %q", argv)
	}
	if !reflect.DeepEqual(*p, before) {
		t.Fatal("profile mutated")
	}
}

// TestCommandFailures rejects nil or unvalidated profiles and unsafe option inputs.
// Every failure must return no partial invocation or environment.
func TestCommandFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*profile.Profile, *Options)
	}{
		{"bad host", func(p *profile.Profile, _ *Options) { p.Gateway.Host = "--otp=x" }},
		{"bad realm", func(p *profile.Profile, _ *Options) { p.Realm = "x --otp=x" }},
		{"bad pin", func(p *profile.Profile, _ *Options) { p.TrustedCert = "--pppd-plugin=x" }},
		{"bad mode", func(p *profile.Profile, _ *Options) { p.MFA.Mode = "other" }},
		{"relative binary", func(_ *profile.Profile, o *Options) { o.Executable = "openfortivpn" }},
		{"relative pinentry", func(_ *profile.Profile, o *Options) { o.Pinentry = "pinentry" }},
		{"relative socket", func(_ *profile.Profile, o *Options) { o.PinentrySocket = "relay.sock" }},
		{"path controls", func(_ *profile.Profile, o *Options) { o.Pinentry = "/tmp/pinentry\n" }},
		{"traversal", func(_ *profile.Profile, o *Options) { o.Executable = "/usr/bin/../openfortivpn" }},
		{"empty token", func(_ *profile.Profile, o *Options) { o.AttemptToken = "" }},
		{"uppercase token", func(_ *profile.Profile, o *Options) { o.AttemptToken = strings.Repeat("AB", 32) }},
		{"nonhex token", func(_ *profile.Profile, o *Options) { o.AttemptToken = strings.Repeat("gg", 32) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, o := commandProfile(), commandOptions()
			tc.change(p, &o)
			if argv, env, err := BuildCommand(p, o); err == nil || argv != nil || env != nil {
				t.Fatalf("unsafe invocation accepted: %q, %q, %v", argv, env, err)
			}
		})
	}
	if argv, env, err := BuildCommand(nil, commandOptions()); err == nil || argv != nil || env != nil {
		t.Fatal("nil profile accepted")
	}
}
