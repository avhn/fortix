// Package cli tests shared configuration through the existing helper socket fixtures.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
)

// sharedProfile returns a valid, reserved-example profile with a personal placeholder.
func sharedProfile(id string) profile.Profile {
	p := profile.Profile{SchemaVersion: 1, ID: id, Name: "Example", Username: "example-user", Gateway: profile.Gateway{Host: "vpn.example.com"}}
	p.ApplyDefaults()
	return p
}

// sharedFile writes a test document in a fresh temporary directory with no real credentials.
func sharedFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shared.json")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// sharedJSON wraps raw draft objects in the versioned exchange envelope.
func sharedJSON(drafts string) string {
	return `{"format":"fortix-profile","version":1,"profiles":[` + drafts + `]}`
}

// sharedOptions uses an empty regular file to force noninteractive behavior on any test host.
func sharedOptions(t *testing.T, socket string) Options {
	t.Helper()
	input, err := os.Open(sharedFile(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	options := testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false)
	options.Input = input
	return options
}

// TestProfileExport verifies ordered secret-free stdout and exclusive file creation with force opt-in.
func TestProfileExport(t *testing.T) {
	for _, mode := range []string{"stdout", "file", "existing", "force"} {
		t.Run(mode, func(t *testing.T) {
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				if req.Op != "profile.get" {
					t.Errorf("unexpected operation %s", req.Op)
				}
				return sharedProfile(req.Profile), nil, nil
			})
			args := []string{"profile", "export", "work", "second"}
			path := filepath.Join(t.TempDir(), "export.json")
			if mode != "stdout" {
				args = append(args, "-o", path)
			}
			if mode == "existing" || mode == "force" {
				if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "force" {
				args = append(args, "--force")
			}
			code, out, diagnostics := runCommand(t, args, sharedOptions(t, socket))
			if mode != "stdout" {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				out = string(data)
			}
			if mode == "existing" {
				if code != 1 || out != "original" || !strings.Contains(diagnostics, "--force") {
					t.Fatalf("overwrite protection: %d %q %q", code, out, diagnostics)
				}
				return
			}
			if code != 0 || strings.Contains(out, "username") || strings.Contains(out, "example-user") {
				t.Fatalf("export: %d %s %s", code, out, diagnostics)
			}
			drafts, err := profile.Parse([]byte(out))
			if err != nil || len(drafts) != 2 || *drafts[0].ID != "work" || *drafts[1].ID != "second" {
				t.Fatalf("ordered export: %v %v", drafts, err)
			}
			if mode == "file" {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm()&0o022 != 0 {
					t.Fatalf("unsafe export mode: %v %v", info, err)
				}
			}
		})
	}
}

// TestProfileImport verifies local completion, preflight refusal, list replacement, and pin consent.
func TestProfileImport(t *testing.T) {
	minimal := `{"id":"work","name":"Example","gateway":{"host":"vpn.example.com"}}`
	pin := strings.Repeat("a", 64)
	tests := []struct {
		name, drafts, diagnostic string
		flags                    []string
		existing                 bool
		want                     int
		writes                   int
	}{
		{name: "new", drafts: minimal, flags: []string{"--username", "local-user"}, writes: 1},
		{name: "overrides", drafts: minimal, flags: []string{"--username", "local-user", "--id", "other", "--name", "Local name"}, writes: 1},
		{name: "missing username", drafts: minimal, want: 1, diagnostic: "missing required fields: username"},
		{name: "all missing", drafts: `{}`, want: 1, diagnostic: "missing required fields: id, name, gateway.host, username"},
		{name: "missing lists", drafts: `{"routes":{"mode":"custom"},"dns":{"mode":"split"}}`, flags: []string{"--username", "local-user"}, want: 1, diagnostic: "id, name, gateway.host, routes.include, dns.domains"},
		{name: "existing id", drafts: minimal, flags: []string{"--username", "local-user"}, existing: true, want: 1, diagnostic: "already exists; use --merge"},
		{name: "merge", drafts: `{"id":"sender","routes":{"include":["192.0.2.128/25"]},"dns":{"domains":["new.example.com"]}}`, flags: []string{"--merge", "work", "--username", "ignored-user"}, existing: true, writes: 1},
		{name: "pin refused", drafts: `{"id":"work","name":"Example","gateway":{"host":"vpn.example.com"},"trusted_cert":"` + pin + `"}`, flags: []string{"--username", "local-user"}, want: 1, diagnostic: "use --yes"},
		{name: "pin accepted", drafts: `{"id":"work","name":"Example","gateway":{"host":"vpn.example.com"},"trusted_cert":"` + pin + `"}`, flags: []string{"--username", "local-user", "--yes"}, writes: 1},
		{name: "multiple", drafts: minimal + `,{"id":"second","name":"Second","gateway":{"host":"vpn.example.com"}}`, flags: []string{"--username", "local-user"}, writes: 2},
		{name: "multiple id override", drafts: minimal + `,{"id":"second"}`, flags: []string{"--id", "other"}, want: 1, diagnostic: "single-profile file"},
		{name: "multiple name override", drafts: minimal + `,{"id":"second"}`, flags: []string{"--name", "Other"}, want: 1, diagnostic: "single-profile file"},
		{name: "multiple merge", drafts: minimal + `,{"id":"second"}`, flags: []string{"--merge", "work"}, want: 1, diagnostic: "single-profile file"},
		{name: "late collision no writes", drafts: `{"id":"second","name":"Second","gateway":{"host":"vpn.example.com"}},` + minimal, flags: []string{"--username", "local-user"}, existing: true, want: 1, diagnostic: "already exists"},
		{name: "secret rejected", drafts: `{"password":"do-not-echo"}`, want: 1, diagnostic: "password: secret fields are forbidden"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var saved []profile.Profile
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "profile.list":
					if tc.existing {
						return []profileState{{Profile: "work"}}, nil, nil
					}
					return []profileState{}, nil, nil
				case "profile.get":
					base := sharedProfile("work")
					base.Username = "existing-user"
					base.Routes = profile.Routes{Mode: "custom", Include: []string{"192.0.2.0/25"}, PreserveLAN: new(true)}
					base.DNS = profile.DNS{Mode: "split", Domains: []string{"old.example.com"}}
					return base, nil, nil
				case "profile.put":
					var p profile.Profile
					if err := json.Unmarshal(req.ProfileJSON, &p); err != nil {
						t.Error(err)
					}
					saved = append(saved, p)
					return nil, nil, nil
				default:
					t.Errorf("unexpected operation %s", req.Op)
					return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected"}
				}
			})
			args := append([]string{"profile", "import", sharedFile(t, sharedJSON(tc.drafts))}, tc.flags...)
			options := sharedOptions(t, socket)
			code, out, diagnostics := runCommand(t, args, options)
			if code != tc.want || !strings.Contains(diagnostics, tc.diagnostic) || len(saved) != tc.writes {
				t.Fatalf("import: code %d want %d, writes %d want %d, %q %q", code, tc.want, len(saved), tc.writes, out, diagnostics)
			}
			if strings.Contains(out+diagnostics, "do-not-echo") || len(options.Prompt.(*fakePrompt).labels) != 0 {
				t.Fatal("secret leaked or password prompted")
			}
			for _, p := range saved {
				if err := p.Validate(); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out, "fortix up "+p.ID) || !strings.Contains(out, "keychain") {
					t.Fatal("missing connection hint")
				}
				if tc.name == "merge" {
					if p.ID != "work" || p.Username != "existing-user" || !reflect.DeepEqual(p.Routes.Include, []string{"192.0.2.128/25"}) || !reflect.DeepEqual(p.DNS.Domains, []string{"new.example.com"}) {
						t.Fatalf("merge replaced identity or appended lists: %+v", p)
					}
				} else if p.Username != "local-user" {
					t.Fatalf("incorrect local username: %q", p.Username)
				}
				if tc.name == "overrides" && (p.ID != "other" || p.Name != "Local name") {
					t.Fatalf("overrides ignored: %+v", p)
				}
			}
			if strings.HasPrefix(tc.name, "pin ") && !strings.Contains(diagnostics, pin) {
				t.Fatal("pin not displayed")
			}
		})
	}
}

// TestSharedStdin verifies a dash consumes the input stream and never reuses it for prompts.
func TestSharedStdin(t *testing.T) {
	data := sharedJSON(`{"id":"work","name":"Example","gateway":{"host":"vpn.example.com"}}`)
	socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
		if req.Op == "profile.list" {
			return []profileState{}, nil, nil
		}
		return nil, nil, nil
	})
	options := sharedOptions(t, socket)
	input, err := os.Open(sharedFile(t, data))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	options.Input = input
	code, _, diagnostics := runCommand(t, []string{"profile", "import", "-", "--username", "local-user"}, options)
	if code != 0 {
		t.Fatal(diagnostics)
	}
}

// TestSharedCompletion verifies visible field prompts, supplied defaults, and bounded input errors.
func TestSharedCompletion(t *testing.T) {
	drafts, err := profile.Parse([]byte(sharedJSON(`{"id":"work","name":"Example","routes":{"mode":"custom"},"dns":{"mode":"split"}}`)))
	if err != nil {
		t.Fatal(err)
	}
	r := runner{ctx: context.Background(), errout: io.Discard}
	p, err := r.completeShared(drafts[0], "", true, bufio.NewReader(strings.NewReader("vpn.example.com\nlocal-user\n192.0.2.0/24\nEXAMPLE.COM\n")))
	if err != nil || p.ID != "work" || p.Name != "Example" || p.Username != "local-user" || !reflect.DeepEqual(p.DNS.Domains, []string{"example.com"}) {
		t.Fatalf("completion: %+v %v", p, err)
	}
	_, err = r.completeShared(drafts[0], "", true, bufio.NewReader(strings.NewReader("")))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("input error lost: %v", err)
	}
}

// TestSharedFieldInput verifies completion cannot consume the following pin confirmation.
func TestSharedFieldInput(t *testing.T) {
	r := runner{ctx: context.Background()}
	input := strings.NewReader("local-user\ny\n")
	value, err := r.readSharedField(input)
	remaining, readErr := io.ReadAll(input)
	if err != nil || readErr != nil || value != "local-user" || string(remaining) != "y\n" {
		t.Fatalf("consent consumed by completion: %q %q %v %v", value, remaining, err, readErr)
	}
	if _, err := r.readSharedField(strings.NewReader(strings.Repeat("a", 64*1024+1))); err == nil {
		t.Fatal("oversized field accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.ctx = ctx
	if _, err := r.readSharedField(strings.NewReader("value\n")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

// TestSharedCommandSyntax verifies flags before or after operands, ID validation, and help.
func TestSharedCommandSyntax(t *testing.T) {
	for _, args := range [][]string{
		{"profile", "export"},
		{"profile", "export", "../work"},
		{"profile", "export", "work", "work"},
		{"profile", "import"},
		{"profile", "import", "shared.json", "--id", "../work"},
		{"profile", "import", "shared.json", "--merge", "work", "--id", "other"},
	} {
		if _, err := parseCommand(args, io.Discard, io.Discard); err == nil {
			t.Fatalf("invalid syntax accepted: %v", args)
		}
	}
	for _, args := range [][]string{
		{"profile", "export", "work", "-o", "shared.json", "--force"},
		{"profile", "export", "--force", "-o", "shared.json", "work"},
		{"profile", "import", "-", "--username", "local-user", "--yes"},
		{"profile", "import", "--username", "local-user", "--yes", "-"},
	} {
		if _, err := parseCommand(args, io.Discard, io.Discard); err != nil {
			t.Fatalf("valid syntax refused: %v: %v", args, err)
		}
	}
	code, out, diagnostics := runCommand(t, []string{"profile", "import", "--help"}, Options{})
	if code != 0 || !strings.Contains(out, "--merge ID") || diagnostics != "" {
		t.Fatalf("help: %d %q %q", code, out, diagnostics)
	}
}

// TestSharedPinConfirmation verifies interactive default refusal and explicit acceptance.
func TestSharedPinConfirmation(t *testing.T) {
	for _, yes := range []bool{false, true} {
		p := &fakePrompt{yes: yes}
		r := runner{ctx: context.Background(), errout: io.Discard, options: Options{Prompt: p}}
		err := r.confirmSharedPin(profile.Draft{TrustedCert: new(strings.Repeat("a", 64))}, false, true)
		if (err == nil) != yes || p.confirms != 1 {
			t.Fatalf("confirmation: %v %d", err, p.confirms)
		}
	}
}
