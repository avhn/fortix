// Package cli exercises credential lifetime, prompt backpressure, and actionable diagnostics.
package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/prompt"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
)

// waitingPrompt holds terminal input until the helper has sent a diagnostic flood.
// Cancellation returns the context error without exposing a credential.
type waitingPrompt struct {
	started chan struct{}
	ready   chan struct{}
}

// Password announces the prompt and waits for diagnostics or cancellation before returning a fixture.
func (p waitingPrompt) Password(ctx context.Context, _ string, _ bool) (string, error) {
	close(p.started)
	select {
	case <-p.ready:
		return "fixture-password", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Confirm declines consent because this fixture only supports password challenges.
func (waitingPrompt) Confirm(context.Context, string) (bool, error) { return false, nil }

// TestLogsDuringPrompt verifies unused logs cannot exhaust the client's queue while input blocks.
// The helper sends more than the queue capacity only after the terminal prompt begins.
func TestLogsDuringPrompt(t *testing.T) {
	local, remote := net.Pipe()
	p := waitingPrompt{started: make(chan struct{}), ready: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = remote.Close() }()
		reader := protocol.NewReader(remote)
		started := false
		for {
			var req protocol.Request
			if err := reader.Read(&req); err != nil {
				return
			}
			var data any
			switch req.Op {
			case "hello":
				data = map[string]any{"protocol": 1}
			case "up":
				started = true
				data = map[string]any{"attempt": 1}
				if err := protocol.Write(remote, protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "password", Kind: "password"}); err != nil {
					return
				}
			case "status":
				data = []statusEntry{}
			case "profile.get":
				data = credentialProfile(req.Profile)
			case "answer":
				if err := protocol.Write(remote, protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "connected"}); err != nil {
					return
				}
			}
			if err := protocol.Write(remote, protocol.Result{Type: "result", ID: req.ID, OK: true, Data: data}); err != nil {
				return
			}
			if req.Op == "profile.get" && started {
				select {
				case <-p.started:
				case <-time.After(2 * time.Second):
					return
				}
				for range 1024 {
					if err := protocol.Write(remote, protocol.Event{Type: "log", Profile: "work", Attempt: 1, Line: "diagnostic"}); err != nil {
						return
					}
				}
				close(p.ready)
			}
		}
	}()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close(); <-done })
	options := testOptions("/tmp/example.sock", &secrets.Memory{}, p, false)
	options.Client.Dial = func(context.Context, string, string) (net.Conn, error) { return local, nil }
	code, out, diag := runCommand(t, []string{"up", "work"}, options)
	if code != 0 || !strings.Contains(out, "connected") || diag != "" {
		t.Fatalf("code %d output %s diagnostics %s", code, out, diag)
	}
}

// cancellingPrompt simulates Ctrl-C during hidden terminal input rather than before dialing.
type cancellingPrompt struct{ cancel context.CancelFunc }

// Password cancels the invocation and reports its context error without a credential.
func (p cancellingPrompt) Password(ctx context.Context, _ string, _ bool) (string, error) {
	p.cancel()
	return "", ctx.Err()
}

// Confirm declines unused certificate confirmation for this password-only fixture.
func (cancellingPrompt) Confirm(context.Context, string) (bool, error) { return false, nil }

// TestCancelledPromptCleanup checks that both cleanup requests reach the helper after Ctrl-C.
// A rejected down request warns explicitly that the attempt may remain active.
func TestCancelledPromptCleanup(t *testing.T) {
	for _, failDown := range []bool{false, true} {
		t.Run(map[bool]string{false: "stopped", true: "stop failed"}[failDown], func(t *testing.T) {
			cancelled, stopped := false, false
			socket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
				switch req.Op {
				case "up":
					return map[string]any{"attempt": 1}, []protocol.Event{{Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "password", Kind: "password"}}, nil
				case "status":
					return []statusEntry{}, nil, nil
				case "cancel":
					cancelled = true
				case "down":
					stopped = req.Profile == "work"
					if failDown {
						return nil, nil, &protocol.Error{Code: protocol.Internal, Message: "stop failed"}
					}
				}
				return nil, nil, nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			var diag bytes.Buffer
			code := RunContext(ctx, []string{"up", "work"}, io.Discard, &diag, testOptions(socket, &secrets.Memory{}, cancellingPrompt{cancel}, false))
			if code != 1 || !cancelled || !stopped || !strings.Contains(diag.String(), "context canceled") {
				t.Fatalf("code %d cancel %v down %v diagnostics %s", code, cancelled, stopped, &diag)
			}
			if failDown != strings.Contains(diag.String(), "attempt left running; use fortix down work") {
				t.Fatal(diag.String())
			}
		})
	}
}

// TestCredentialGeneration verifies accepted answers alone never persist a password.
// Terminal outcomes save only their own successful generation and release failed values.
func TestCredentialGeneration(t *testing.T) {
	for _, state := range []string{"connected", "failed", "disconnected"} {
		t.Run(state, func(t *testing.T) {
			store := &secrets.Memory{}
			r := runner{options: Options{Secrets: store}, errout: io.Discard, credentials: map[string]credential{"work": {attempt: 2, secret: "fixture-password", key: secrets.Key(credentialProfile("work"))}}}
			if err := r.finishCredential(protocol.Event{Profile: "work", Attempt: 1, State: "connected"}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Get(secrets.Key(credentialProfile("work"))); !errors.Is(err, secrets.ErrNotFound) {
				t.Fatal("stale attempt saved a password")
			}
			if err := r.finishCredential(protocol.Event{Profile: "work", Attempt: 2, State: state}); err != nil {
				t.Fatal(err)
			}
			_, err := store.Get(secrets.Key(credentialProfile("work")))
			if (err == nil) != (state == "connected") || len(r.credentials) != 0 {
				t.Fatal("incorrect credential lifetime")
			}
		})
	}
}

// TestReviewDiagnostics verifies single usage blocks, invalid-ID details, empty selections, and terminal requirements.
func TestReviewDiagnostics(t *testing.T) {
	code, _, diag := runCommand(t, []string{"trust", "work", "--unknown"}, Options{})
	if code != 2 || strings.Count(diag, "usage:") != 1 {
		t.Fatal(diag)
	}
	for _, args := range [][]string{{"profile", "show", "../work"}, {"profile", "rm", "../work"}, {"down", "../work"}, {"logs", "../work"}} {
		code, _, diag := runCommand(t, args, Options{})
		if code != 2 || !strings.Contains(diag, `invalid profile id "../work"`) {
			t.Fatal(diag)
		}
	}
	for _, args := range [][]string{{"up", "--all"}, {"down", "--all"}, {"profile", "list"}} {
		socket := fakeSocket(t, func(protocol.Request) (any, []protocol.Event, *protocol.Error) { return []profileState{}, nil, nil })
		code, _, diag := runCommand(t, args, testOptions(socket, &secrets.Memory{}, &fakePrompt{}, false))
		if code != 0 || diag != "no profiles\n" {
			t.Fatalf("%v: %d %s", args, code, diag)
		}
	}
	passwordSocket := fakeSocket(t, func(req protocol.Request) (any, []protocol.Event, *protocol.Error) {
		return credentialProfile(req.Profile), nil, nil
	})
	code, _, diag = runCommand(t, []string{"password", "set", "work"}, testOptions(passwordSocket, &secrets.Memory{}, &fakePrompt{err: prompt.ErrUnavailable}, false))
	if code != 1 || !strings.Contains(diag, "password set needs an interactive terminal") {
		t.Fatal(diag)
	}
}
