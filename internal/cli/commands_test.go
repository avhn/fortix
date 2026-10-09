//go:build darwin || linux

// Package cli tests helper-backed commands and offline syntax through isolated protocol fixtures.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/client"
	"github.com/avhn/fortix/internal/importer"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
	"github.com/avhn/fortix/internal/userconfig"
)

// fakePrompt supplies hidden responses and confirmation decisions while recording prompt kinds.
type fakePrompt struct {
	responses []string
	labels    []string
	confirms  int
	yes       bool
	err       error
}

// Password consumes one scripted response or returns the configured prompt error.
func (p *fakePrompt) Password(_ context.Context, label string, stdin bool) (string, error) {
	p.labels = append(p.labels, label)
	if stdin {
		return "", errors.New("unexpected plaintext input")
	}
	if p.err != nil {
		return "", p.err
	}
	if len(p.responses) == 0 {
		return "", errors.New("unexpected prompt")
	}
	response := p.responses[0]
	p.responses = p.responses[1:]
	return response, nil
}

// Confirm records an explicit trust decision without consuming credential responses.
func (p *fakePrompt) Confirm(context.Context, string) (bool, error) {
	p.confirms++
	return p.yes, p.err
}

// fakeHandler implements one helper operation and optional events before its result.
type fakeHandler func(protocol.Request) (any, []protocol.Event, *protocol.Error)

// fakeSocket serves bounded protocol records through a real temporary Unix socket.
// Cleanup joins the server and removes only the newly created socket directory.
func fakeSocket(t *testing.T, handler fakeHandler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fx-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}
	var mu sync.Mutex
	var active net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		active = conn
		mu.Unlock()
		defer func() { _ = conn.Close() }()
		reader := protocol.NewReader(conn)
		hadUp := false
		for {
			var req protocol.Request
			if err := reader.Read(&req); err != nil {
				return
			}
			if err := req.Validate(); err != nil {
				t.Error(err)
				return
			}
			var data any
			var events []protocol.Event
			var failure *protocol.Error
			switch {
			case req.Op == "hello":
				data = map[string]any{"helper_version": "test", "protocol": 1}
			case req.Op == "profile.get" && hadUp:
				data = credentialProfile(req.Profile)
			default:
				data, events, failure = handler(req)
			}
			hadUp = hadUp || req.Op == "up"
			for _, event := range events {
				if err := protocol.Write(conn, event); err != nil {
					return
				}
			}
			if err := protocol.Write(conn, protocol.Result{Type: "result", ID: req.ID, OK: failure == nil, Error: failure, Data: data}); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		if active != nil {
			_ = active.Close()
		}
		mu.Unlock()
		<-done
		_ = os.RemoveAll(dir)
	})
	return socket
}

// testOptions isolates keyring and preferences while using the production socket client.
func testOptions(socket string, store secrets.Store, p Prompter, remember bool) Options {
	cfg := userconfig.Defaults()
	cfg.RememberPasswords = remember
	return Options{Client: client.Options{Socket: socket}, Secrets: store, Prompt: p, Config: &cfg}
}

// runCommand executes under a bounded context and returns captured non-secret output and diagnostics.
func runCommand(t *testing.T, args []string, options Options) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var out, errout bytes.Buffer
	code := RunContext(ctx, args, &out, &errout, options)
	return code, out.String(), errout.String()
}

// TestUpCredentials verifies keyring hits, fallback prompts, opt-in saves, codes, and authentication failure.
func TestUpCredentials(t *testing.T) {
	tests := []struct {
		name                                        string
		hit, remember, save, code, fail, promptFail bool
	}{
		{name: "keyring hit", hit: true},
		{name: "keyring miss"},
		{name: "remember preference", remember: true},
		{name: "explicit save", save: true},
		{name: "code always prompts", hit: true, code: true},
		{name: "auth failure", hit: true, fail: true},
		{name: "bad prompted password not saved", remember: true, fail: true},
		{name: "bad explicit save not saved", save: true, fail: true},
		{name: "prompt cancellation", promptFail: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &secrets.Memory{}
			if tc.hit {
				if err := store.Set(secrets.Key(credentialProfile("work")), "test-password"); err != nil {
					t.Fatal(err)
				}
			}
			p := &fakePrompt{responses: []string{"test-password", "123456"}}
			if tc.hit && tc.code {
				p.responses = []string{"123456"}
			}
			if tc.promptFail {
				p.err = errors.New("prompt cancelled")
			}
			answers, cancelled := 0, false
			state := "starting"
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "subscribe":
					return nil, nil, nil
				case "up":
					return map[string]any{"attempt": 1}, []protocol.Event{{Type: "state", Profile: "work", Attempt: 1, State: "starting"}, {Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "password", Kind: "password"}}, nil
				case "status":
					return []statusEntry{{Profile: "work", Attempt: 1, State: state}}, nil, nil
				case "down":
					return nil, nil, nil
				case "cancel":
					cancelled = true
					return nil, nil, nil
				case "answer":
					answers++
					expected := "test-password"
					if req.ChallengeID == "code" {
						expected = "123456"
					}
					if req.Secret != expected {
						t.Error("incorrect credential delivered")
					}
					if tc.code && answers == 1 {
						return nil, []protocol.Event{{Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "code", Kind: "code"}}, nil
					}
					state = "connected"
					if tc.fail {
						state = "failed"
					}
					return nil, []protocol.Event{{Type: "state", Profile: "work", Attempt: 1, State: state, Detail: "authentication result", Code: "AUTHENTICATION_FAILED"}}, nil
				}
				t.Errorf("unexpected operation %s", req.Op)
				return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected"}
			})
			args := []string{"up", "work"}
			if tc.save {
				args = append(args, "--save")
			}
			code, out, diagnostics := runCommand(t, args, testOptions(socket, store, p, tc.remember))
			want := 0
			if tc.fail || tc.promptFail {
				want = 1
			}
			if code != want {
				t.Fatalf("code %d, want %d: %s", code, want, diagnostics)
			}
			if strings.Contains(out+diagnostics, "test-password") || strings.Contains(out+diagnostics, "123456") {
				t.Fatal("credential leaked")
			}
			if tc.promptFail {
				if !cancelled {
					t.Fatal("challenge was not cancelled")
				}
				return
			}
			prompts := 1
			if tc.hit {
				prompts = 0
			}
			if tc.code {
				prompts++
			}
			if len(p.labels) != prompts {
				t.Fatalf("prompt count %d, want %d", len(p.labels), prompts)
			}
			_, getErr := store.Get(secrets.Key(credentialProfile("work")))
			if (tc.hit || ((tc.remember || tc.save) && !tc.fail)) != (getErr == nil) {
				t.Fatal("save policy not respected")
			}
			if tc.fail && tc.hit && !strings.Contains(diagnostics, "fortix password clear work") {
				t.Fatal("missing saved-password recovery hint")
			}
			if tc.fail && !strings.Contains(diagnostics, "failed") {
				t.Fatal(diagnostics)
			}
		})
	}
}

// TestTrustFlow verifies rejected metadata, explicit refusal, --yes, and the next attempt's connection.
func TestTrustFlow(t *testing.T) {
	for _, tc := range []struct {
		name                string
		trust, yes, consent bool
		code                int
	}{
		{"up rejection", false, false, false, 1}, {"confirmed", true, false, true, 0}, {"declined", true, false, false, 1}, {"noninteractive confirmation", true, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest := strings.Repeat("a", 64)
			p := &fakePrompt{yes: tc.consent}
			attempt := uint64(1)
			state := "disconnected"
			trusted := false
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "subscribe":
					return nil, nil, nil
				case "status":
					return []statusEntry{{Profile: "work", Attempt: attempt, State: state}}, nil, nil
				case "up":
					state = "waiting_trust"
					return map[string]any{"attempt": attempt}, []protocol.Event{{Type: "state", Profile: "work", Attempt: attempt, State: "waiting_trust"}, {Type: "cert", Profile: "work", Attempt: attempt, Digest: digest, Subject: "CN=vpn.example.com", Issuer: "CN=Example CA"}}, nil
				case "trust":
					trusted = req.Digest == digest
					attempt++
					return nil, []protocol.Event{{Type: "state", Profile: "work", Attempt: attempt, State: "connected"}}, nil
				}
				return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected"}
			})
			args := []string{"up", "work"}
			if tc.trust {
				args[0] = "trust"
			}
			if tc.yes {
				args = append(args, "--yes")
			}
			code, out, diag := runCommand(t, args, testOptions(socket, &secrets.Memory{}, p, false))
			if code != tc.code {
				t.Fatalf("code %d: %s", code, diag)
			}
			if !strings.Contains(out, digest) || !strings.Contains(out, "CN=vpn.example.com") || !strings.Contains(out, "CN=Example CA") {
				t.Fatal(out)
			}
			if trusted != (tc.trust && (tc.yes || tc.consent)) {
				t.Fatal("incorrect trust decision")
			}
			if tc.trust && !tc.yes && p.confirms != 1 {
				t.Fatal("missing confirmation")
			}
		})
	}
}

// TestHelperCommands covers status JSON/table, profile operations, logs, and down --all wire requests.
func TestHelperCommands(t *testing.T) {
	fixture, err := os.ReadFile("../profile/testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		op   string
		data any
		want string
	}{
		{"status JSON", []string{"status", "--json"}, "status", []statusEntry{{Profile: "work", State: "connected", Interface: "ppp0", LocalIP: "10.20.0.2"}}, `"local_ip": "10.20.0.2"`},
		{"status table", []string{"status"}, "status", []statusEntry{{Profile: "work", State: "connected", Interface: "ppp0", LocalIP: "10.20.0.2"}}, "LOCAL IP"},
		{"list", []string{"profile", "list"}, "profile.list", []profileState{{Profile: "work", State: "disconnected"}}, "work"},
		{"show", []string{"profile", "show", "work"}, "profile.get", json.RawMessage(fixture), `"id": "work"`},
		{"add", []string{"profile", "add", "../profile/testdata/valid.json"}, "profile.put", nil, ""},
		{"rm", []string{"profile", "rm", "work"}, "profile.delete", nil, ""},
		{"down all", []string{"down", "--all"}, "down", nil, ""},
		{"down id", []string{"down", "work"}, "down", nil, ""},
		{"logs", []string{"logs", "work", "--lines", "2"}, "logs", []string{"connected", "stopped"}, "stopped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				if strings.HasPrefix(tc.name, "down ") {
					switch req.Op {
					case "subscribe":
						return nil, nil, nil
					case "status":
						return []statusEntry{{Profile: "work", State: "disconnected"}}, nil, nil
					}
				}
				calls++
				if req.Op != tc.op {
					t.Errorf("operation %s, want %s", req.Op, tc.op)
				}
				if tc.name == "down all" && (!req.All || req.Profile != "") {
					t.Error("incorrect all selector")
				}
				if tc.name == "add" && !bytes.Contains(req.ProfileJSON, []byte(`"id":"work"`)) {
					t.Error("missing profile JSON")
				}
				if tc.name == "logs" && req.Lines != 2 {
					t.Error("incorrect log limit")
				}
				return tc.data, nil, nil
			})
			code, out, diag := runCommand(t, tc.args, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
			if code != 0 || calls != 1 || !strings.Contains(out, tc.want) {
				t.Fatalf("code %d calls %d out %s diagnostics %s", code, calls, out, diag)
			}
			if tc.name == "status JSON" {
				var entries []statusEntry
				if err := json.Unmarshal([]byte(out), &entries); err != nil || len(entries) != 1 {
					t.Fatal("invalid status JSON")
				}
			}
		})
	}
}

// fixtureConverter returns the existing secret-bearing import fixture for preview sanitization tests.
type fixtureConverter struct{}

// Convert reads the fixture without invoking plutil or touching a real FortiClient installation.
func (fixtureConverter) Convert(context.Context, string) ([]byte, error) {
	return os.ReadFile("../importer/testdata/vpn.json")
}

// TestImport verifies preview and profile.put application never copy saved FortiClient secrets.
func TestImport(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("import command is macOS-only")
	}
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "preview", true: "apply"}[apply], func(t *testing.T) {
			calls := 0
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				calls++
				if req.Op != "profile.put" || bytes.Contains(req.ProfileJSON, []byte("ignored-test-value")) {
					t.Error("unsafe import request")
				}
				return nil, nil, nil
			})
			options := testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false)
			options.Converter = fixtureConverter{}
			args := []string{"import", "forticlient", "--plist", "/tmp/example.plist"}
			if apply {
				args = append(args, "--apply")
			}
			code, out, diag := runCommand(t, args, options)
			if code != 0 || strings.Contains(out+diag, "ignored-test-value") {
				t.Fatalf("code %d diagnostics %s", code, diag)
			}
			var drafts []json.RawMessage
			if err := json.Unmarshal([]byte(out), &drafts); err != nil || len(drafts) != 2 {
				t.Fatal("incorrect drafts")
			}
			expected := 0
			if apply {
				expected = 2
			}
			if calls != expected {
				t.Fatalf("apply calls %d", calls)
			}
		})
	}
}

// TestPasswordManagement verifies hidden set, idempotent clear, and no secret in command output.
func TestPasswordManagement(t *testing.T) {
	store := &secrets.Memory{}
	for _, args := range [][]string{{"password", "set", "work"}, {"password", "clear", "work"}, {"password", "clear", "work"}} {
		socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
			return credentialProfile(req.Profile), nil, nil
		})
		options := testOptions(socket, store, &fakePrompt{responses: []string{"test-password"}}, false)
		code, out, diag := runCommand(t, args, options)
		if code != 0 || strings.Contains(out+diag, "test-password") {
			t.Fatalf("code %d: %s", code, diag)
		}
	}
}

// TestHelpAndUsage ensures every subcommand has offline help and malformed syntax never dials.
func TestHelpAndUsage(t *testing.T) {
	commands := [][]string{{"version"}, {"profile", "validate"}, {"profile", "list"}, {"profile", "show"}, {"profile", "add"}, {"profile", "rm"}, {"import", "forticlient"}, {"password", "set"}, {"password", "clear"}, {"up"}, {"down"}, {"status"}, {"logs"}, {"trust"}, {"profile"}, {"password"}, {"import"}}
	for _, cmd := range commands {
		args := append(append([]string{}, cmd...), "-h")
		code, out, diag := runCommand(t, args, Options{})
		if code != 0 || !strings.Contains(out, "usage:") || diag != "" {
			t.Fatalf("%v: %d %s", args, code, diag)
		}
	}
	for _, args := range [][]string{{"up"}, {"up", "work", "--all"}, {"up", "work", "work"}, {"up", "../work"}, {"down"}, {"status", "extra"}, {"logs", "work", "--lines", "501"}, {"profile", "show"}, {"trust", "work", "--unknown"}} {
		code, _, _ := runCommand(t, args, Options{})
		if code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
	}
}

// TestCLIConnectionErrors verifies actionable diagnostics and helper rejections retain failure status.
func TestCLIConnectionErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{os.ErrNotExist, "helper is not running"}, {os.ErrPermission, "group fortix"}} {
		options := Options{Client: client.Options{Socket: "/tmp/example.sock", Dial: func(context.Context, string, string) (net.Conn, error) { return nil, tc.err }}}
		code, _, diag := runCommand(t, []string{"status"}, options)
		if code != 1 || !strings.Contains(diag, tc.want) {
			t.Fatalf("%d %s", code, diag)
		}
	}
	socket := fakeSocket(t, func(protocol.Request) (any, []protocol.Event, *protocol.Error) {
		return nil, nil, &protocol.Error{Code: protocol.NotFound, Message: "profile not found"}
	})
	code, _, diag := runCommand(t, []string{"profile", "show", "work"}, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
	if code != 1 || !strings.Contains(diag, "NOT_FOUND") {
		t.Fatalf("%d %s", code, diag)
	}
}

// FuzzCommand exercises flag ordering, help, unknown flags, and operand validation without I/O.
func FuzzCommand(f *testing.F) {
	f.Add("up work --save")
	f.Add("import forticlient --plist /tmp/example.plist --apply")
	f.Add("logs --lines=500 work")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > protocol.MaxLine {
			return
		}
		_, _ = parseCommand(strings.Fields(input), io.Discard, io.Discard)
	})
}

// TestImporterUnsupported preserves the client library's Linux boundary with no subprocess fallback.
func TestImporterUnsupported(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("unsupported-platform assertion runs on Linux")
	}
	code, _, diag := runCommand(t, []string{"import", "forticlient"}, Options{})
	if code != 1 || !strings.Contains(diag, importer.ErrUnsupported.Error()) {
		t.Fatalf("%d %s", code, diag)
	}
}

// lockedStore simulates a secure provider that cannot read, save, or delete credentials.
type lockedStore struct{}

// Get reports unavailable secure storage without returning a password.
func (lockedStore) Get(string) (string, error) { return "", secrets.ErrUnavailable }

// Set refuses persistence rather than introducing a plaintext fallback.
func (lockedStore) Set(string, string) error { return secrets.ErrUnavailable }

// Delete reports inaccessible storage without changing an entry.
func (lockedStore) Delete(string) error { return secrets.ErrUnavailable }

// TestLockedKeyring verifies unavailable storage falls back to a prompt and warns without aborting VPN setup.
func TestLockedKeyring(t *testing.T) {
	socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
		switch req.Op {
		case "subscribe":
			return nil, nil, nil
		case "status":
			return []statusEntry{}, nil, nil
		case "up":
			return map[string]any{"attempt": 1}, []protocol.Event{{Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "c", Kind: "password"}}, nil
		case "answer":
			return nil, []protocol.Event{{Type: "state", Profile: "work", Attempt: 1, State: "connected"}}, nil
		}
		return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected"}
	})
	code, out, diag := runCommand(t, []string{"up", "work"}, testOptions(socket, lockedStore{}, &fakePrompt{responses: []string{"test-password"}}, true))
	if code != 0 || !strings.Contains(out, "connected") || !strings.Contains(diag, "password not saved") || strings.Contains(out+diag, "test-password") {
		t.Fatalf("%d %s %s", code, out, diag)
	}
}

// TestUpAllAndGenerations verifies every selected tunnel reaches an outcome and stale challenges are ignored.
func TestUpAllAndGenerations(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit ids", true: "all"}[all], func(t *testing.T) {
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "subscribe":
					return nil, nil, nil
				case "profile.list":
					return []profileState{{Profile: "work"}, {Profile: "other"}}, nil, nil
				case "status":
					return []statusEntry{}, nil, nil
				case "up":
					outcome := "connected"
					if req.Profile == "other" {
						outcome = "failed"
					}
					return map[string]any{"attempt": 2}, []protocol.Event{
						{Type: "challenge", Profile: req.Profile, Attempt: 1, ChallengeID: "stale", Kind: "password"},
						{Type: "state", Profile: req.Profile, Attempt: 1, State: "failed"},
						{Type: "state", Profile: req.Profile, Attempt: 2, State: "starting"},
						{Type: "state", Profile: req.Profile, Attempt: 2, State: outcome},
					}, nil
				}
				t.Errorf("unexpected %s", req.Op)
				return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected"}
			})
			args := []string{"up", "work", "other"}
			if all {
				args = []string{"up", "--all"}
			}
			p := &fakePrompt{}
			code, out, diag := runCommand(t, args, testOptions(socket, &secrets.Memory{}, p, false))
			if code != 1 || !strings.Contains(out, "work: connected") || !strings.Contains(out, "other: failed") || !strings.Contains(diag, "other: failed") || len(p.labels) != 0 {
				t.Fatalf("%d %s %s", code, out, diag)
			}
		})
	}
}

// TestAlreadyConnectedAndRejected ensures up resolves existing states without waiting for an event replay.
func TestAlreadyConnectedAndRejected(t *testing.T) {
	for _, state := range []string{"connected", "waiting_trust"} {
		t.Run(state, func(t *testing.T) {
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "subscribe":
					return nil, nil, nil
				case "status":
					return []statusEntry{{Profile: "work", Attempt: 1, State: state}}, nil, nil
				case "up":
					return map[string]any{"attempt": 1}, nil, nil
				}
				return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected"}
			})
			code, out, diag := runCommand(t, []string{"up", "work"}, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
			if state == "connected" && (code != 0 || !strings.Contains(out, "connected")) {
				t.Fatalf("%d %s", code, diag)
			}
			if state == "waiting_trust" && (code != 1 || !strings.Contains(diag, "fortix trust work")) {
				t.Fatalf("%d %s", code, diag)
			}
		})
	}
}

// TestTrustRecapture checks that only a certificate-rejected attempt is restarted before fresh confirmation.
func TestTrustRecapture(t *testing.T) {
	for _, initial := range []string{"waiting_trust", "connected"} {
		t.Run(initial, func(t *testing.T) {
			state := initial
			down := false
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "subscribe":
					return nil, nil, nil
				case "status":
					return []statusEntry{{Profile: "work", Attempt: 2, State: state}}, nil, nil
				case "down":
					down = true
					state = "disconnected"
					return nil, nil, nil
				case "up":
					state = "waiting_trust"
					return map[string]any{"attempt": 2}, []protocol.Event{{Type: "cert", Profile: "work", Attempt: 2, Digest: strings.Repeat("b", 64), Subject: "CN=vpn.example.com", Issuer: "CN=Example CA"}}, nil
				case "trust":
					return nil, []protocol.Event{{Type: "state", Profile: "work", Attempt: 3, State: "connected"}}, nil
				}
				return nil, nil, &protocol.Error{Code: protocol.Invalid, Message: "unexpected"}
			})
			code, _, diag := runCommand(t, []string{"trust", "work", "--yes"}, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
			if initial == "waiting_trust" && (code != 0 || !down) {
				t.Fatalf("%d %s", code, diag)
			}
			if initial == "connected" && (code != 1 || down || !strings.Contains(diag, "trust requires")) {
				t.Fatalf("%d %s", code, diag)
			}
		})
	}
}

// TestCLIWaitCancellation ensures a stalled helper attempt respects the caller's deadline.
func TestCLIWaitCancellation(t *testing.T) {
	socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
		if req.Op == "status" {
			return []statusEntry{}, nil, nil
		}
		if req.Op == "up" {
			return map[string]any{"attempt": 1}, nil, nil
		}
		return nil, nil, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	var diag bytes.Buffer
	code := RunContext(ctx, []string{"up", "work"}, io.Discard, &diag, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
	if code != 1 || !strings.Contains(diag.String(), "context deadline exceeded") {
		t.Fatalf("%d %s", code, &diag)
	}
}

// TestHelperOutputFailures confirms each output-producing command reports stream errors rather than success.
func TestHelperOutputFailures(t *testing.T) {
	for _, args := range [][]string{{"status"}, {"status", "--json"}, {"profile", "list"}, {"profile", "show", "work"}, {"logs", "work"}, {"up", "work"}} {
		socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
			switch req.Op {
			case "subscribe":
				return nil, nil, nil
			case "up":
				return map[string]any{"attempt": 1}, nil, nil
			case "status":
				return []statusEntry{{Profile: "work", State: "connected", Attempt: 1}}, nil, nil
			case "profile.list":
				return []profileState{{Profile: "work", State: "connected"}}, nil, nil
			case "profile.get":
				return map[string]any{"id": "work"}, nil, nil
			case "logs":
				return []string{"redacted line"}, nil, nil
			}
			return nil, nil, nil
		})
		var diag bytes.Buffer
		if code := RunContext(t.Context(), args, brokenWriter{}, &diag, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false)); code != 1 || !strings.Contains(diag.String(), "closed pipe") {
			t.Fatalf("%v %d %s", args, code, &diag)
		}
	}
}

// credentialProfile returns a stable helper-owned account for credential fixtures.
// Endpoint and username match the shared valid profile without carrying a password.
func credentialProfile(id string) *profile.Profile {
	p := &profile.Profile{SchemaVersion: 1, ID: id, Name: "Work", Backend: "openfortivpn", Gateway: profile.Gateway{Host: "vpn.example.com", Port: 10443}, Username: "jane.doe"}
	p.ApplyDefaults()
	return p
}
