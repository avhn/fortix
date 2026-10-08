// Package tray tests connection and credential control with headless desktop fixtures.
package tray

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/client"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
	"github.com/avhn/fortix/internal/session"
	"github.com/avhn/fortix/internal/tray/model"
	"github.com/avhn/fortix/internal/userconfig"
)

// fakeConnection replies to snapshots and records all mutations without sockets.
type fakeConnection struct {
	events chan protocol.Event
	calls  chan protocol.Request
	fail   string
	phase  string
	once   sync.Once
}

// newConnection returns a bounded, initially disconnected helper fixture.
func newConnection() *fakeConnection {
	return &fakeConnection{events: make(chan protocol.Event, 32), calls: make(chan protocol.Request, 64)}
}

// Call implements the exact profile-list and status shapes and returns fake errors.
func (f *fakeConnection) Call(_ context.Context, r protocol.Request, out any) error {
	f.calls <- r
	if r.Op == f.fail {
		return errors.New("fixture failure")
	}
	var data any
	switch r.Op {
	case "profile.list":
		data = []entry{{Profile: "work", State: "disconnected"}}
	case "status":
		phase := f.phase
		if phase == "" {
			phase = "disconnected"
		}
		data = []status{{Profile: "work", State: phase}}
	case "profile.get":
		data = profile.Profile{ID: "work", Name: "Work"}
	case "logs":
		data = []string{"redacted diagnostic"}
	case "up":
		data = map[string]uint64{"attempt": 1}
	}
	if out != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Events provides the fake helper's event stream.
func (f *fakeConnection) Events() <-chan protocol.Event { return f.events }

// Close releases the event stream once, matching the real client's idempotence.
func (f *fakeConnection) Close() error { f.once.Do(func() { close(f.events) }); return nil }

// fakeView captures immutable snapshots and injects menu actions without a GUI.
type fakeView struct {
	actions chan string
	menus   chan model.Menu
}

// Render buffers snapshots without delaying the controller in a headless test.
func (v *fakeView) Render(m model.Menu) {
	select {
	case v.menus <- m:
	default:
	}
}

// Actions exposes the test's explicit click stream.
func (v *fakeView) Actions() <-chan string { return v.actions }

// fakeStore holds one credential and captures successful keyring saves.
type fakeStore struct {
	password string
	err      error
	saved    chan string
}

// Get returns a deterministic missing/locked keyring error or the fixture secret.
func (s *fakeStore) Get(string) (string, error) { return s.password, s.err }

// Set records a private credential without writing it to disk.
func (s *fakeStore) Set(_, password string) error { s.saved <- password; return nil }

// Delete is unused in tray flows and succeeds without side effects.
func (*fakeStore) Delete(string) error { return nil }

// fakeDialog provides injectable native prompt behavior and literal confirmations.
type fakeDialog struct {
	password func(context.Context) (string, error)
	confirm  func(context.Context, string) (bool, error)
}

// Password runs only the injected headless function, never a desktop process.
func (d fakeDialog) Password(ctx context.Context, _, _ string) (string, error) {
	return d.password(ctx)
}

// Confirm forwards certificate display text to the assertion function.
func (d fakeDialog) Confirm(ctx context.Context, _, message string) (bool, error) {
	return d.confirm(ctx, message)
}

// awaitCall finds a matching helper operation with a bounded test deadline.
func awaitCall(t *testing.T, f *fakeConnection, op string) protocol.Request {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case r := <-f.calls:
			if r.Op == op {
				return r
			}
		case <-timer.C:
			t.Fatalf("missing %s call", op)
			return protocol.Request{}
		}
	}
}

// awaitMenu waits for an immutable snapshot satisfying a predicate.
func awaitMenu(t *testing.T, v *fakeView, predicate func(model.Menu) bool) model.Menu {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case m := <-v.menus:
			if predicate(m) {
				return m
			}
		case <-timer.C:
			t.Fatal("missing menu snapshot")
			return model.Menu{}
		}
	}
}

// startController registers cancellation and verifies every worker exits promptly.
func startController(t *testing.T, options Options) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("controller did not stop")
		}
	})
}

// TestProfileActions covers toggles, bulk actions, unknown IDs and rejected attempts.
func TestProfileActions(t *testing.T) {
	cases := []struct {
		name, action, op string
		state            session.Phase
		fail             bool
		wanted           bool
	}{
		{"connect", "profile:work", "up", session.Disconnected, false, true},
		{"disconnect", "profile:work", "down", session.Connected, false, false},
		{"stop starting", "profile:work", "down", session.Starting, false, false},
		{"retry failure", "profile:work", "up", session.Failed, false, true},
		{"all connect", "connect_all", "up", session.Disconnected, false, true},
		{"all disconnect", "disconnect_all", "down", session.Connected, false, false},
		{"rejected", "profile:work", "up", session.Disconnected, true, false},
		{"unknown", "profile:missing", "", session.Disconnected, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newConnection()
			if tc.fail {
				conn.fail = tc.op
			}
			c := controller{attempts: make(map[string]uint64), profiles: []model.Profile{{ID: "work", State: tc.state}}}
			err := c.action(context.Background(), conn, tc.action)
			if (err != nil) != tc.fail {
				t.Fatalf("error = %v", err)
			}
			if tc.op != "" {
				r := awaitCall(t, conn, tc.op)
				if tc.action == "disconnect_all" && !r.All {
					t.Fatal("missing all selector")
				}
			}
			if c.profiles[0].Wanted != tc.wanted {
				t.Fatalf("wanted = %v", c.profiles[0].Wanted)
			}
		})
	}
}

// TestChallengeFlow verifies keychain-first lookup, prompt fallback, cancellation,
// remember-passwords policy, and that code responses are never persisted.
func TestChallengeFlow(t *testing.T) {
	cases := []struct {
		name, kind               string
		cached, remember, cancel bool
	}{
		{"cached", "password", true, true, false},
		{"prompt and remember", "password", false, true, false},
		{"do not remember", "password", false, false, false},
		{"code", "code", false, true, false},
		{"cancel", "password", false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newConnection()
			view := &fakeView{actions: make(chan string, 16), menus: make(chan model.Menu, 64)}
			store := &fakeStore{err: secrets.ErrNotFound, saved: make(chan string, 1)}
			if tc.cached {
				store.password, store.err = "cached-secret", nil
			}
			prompted := make(chan struct{}, 1)
			dialog := fakeDialog{password: func(context.Context) (string, error) {
				prompted <- struct{}{}
				if tc.cancel {
					return "", errors.New("cancelled")
				}
				return "prompt-secret", nil
			}}
			startController(t, Options{View: view, Store: store, Dialog: dialog, Preferences: userconfig.Config{RememberPasswords: tc.remember}, Dial: func(context.Context) (Connection, error) { return conn, nil }})
			awaitCall(t, conn, "profile.get")
			view.actions <- "profile:work"
			awaitCall(t, conn, "up")
			phase := "waiting_password"
			if tc.kind == "code" {
				phase = "waiting_code"
			}
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: phase}
			conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, Kind: tc.kind, ChallengeID: "challenge-1", Prompt: "Password or code"}
			op := "answer"
			if tc.cancel {
				op = "cancel"
			}
			answer := awaitCall(t, conn, op)
			if answer.ChallengeID != "challenge-1" {
				t.Fatal("wrong challenge")
			}
			if tc.cached {
				if answer.Secret != "cached-secret" {
					t.Fatal("keychain not used")
				}
				select {
				case <-prompted:
					t.Fatal("cached password prompted")
				default:
				}
			} else {
				<-prompted
			}
			awaitMenu(t, view, func(m model.Menu) bool { return m.Status == model.Connecting })
			select {
			case <-store.saved:
				t.Fatal("password saved before connection success")
			default:
			}
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "connected"}
			awaitMenu(t, view, func(m model.Menu) bool { return m.Status == model.Connected })
			if !tc.cached && tc.remember && !tc.cancel && tc.kind == "password" {
				select {
				case password := <-store.saved:
					if password != "prompt-secret" {
						t.Fatal("wrong saved password")
					}
				case <-time.After(time.Second):
					t.Fatal("password not saved")
				}
			} else {
				select {
				case <-store.saved:
					t.Fatal("unexpected credential save")
				default:
				}
			}
		})
	}
}

// TestCertificateConfirmation verifies literal identity display and trust-before-up.
func TestCertificateConfirmation(t *testing.T) {
	for _, yes := range []bool{false, true} {
		t.Run(map[bool]string{false: "decline", true: "accept"}[yes], func(t *testing.T) {
			conn := newConnection()
			view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
			shown := make(chan string, 1)
			dialog := fakeDialog{confirm: func(_ context.Context, message string) (bool, error) { shown <- message; return yes, nil }}
			startController(t, Options{View: view, Store: &fakeStore{}, Dialog: dialog, Dial: func(context.Context) (Connection, error) { return conn, nil }})
			awaitCall(t, conn, "profile.get")
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "waiting_trust"}
			digest := strings.Repeat("a", 64)
			conn.events <- protocol.Event{Type: "cert", Profile: "work", Attempt: 1, Digest: digest, Subject: "vpn.example.com\nIssuer: forged\t\x1b", Issuer: "<span>Example issuer</span> &"}
			select {
			case message := <-shown:
				if strings.Contains(message, "\nIssuer: forged") || !strings.Contains(message, `\nIssuer: forged\t\x1b`) {
					t.Fatal("certificate controls were not quoted")
				}
				for _, text := range []string{digest, "vpn.example.com", "Example issuer"} {
					if !strings.Contains(message, text) {
						t.Fatalf("missing certificate identity %q", text)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("no confirmation")
			}
			if yes {
				trust := awaitCall(t, conn, "trust")
				if trust.Digest != digest {
					t.Fatal("wrong digest")
				}
				awaitCall(t, conn, "up")
			} else {
				awaitMenu(t, view, func(m model.Menu) bool { return m.Status == model.Attention })
				select {
				case r := <-conn.calls:
					t.Fatalf("declined cert made request %s", r.Op)
				default:
				}
			}
		})
	}
}

// TestRestartCancelsPrompt verifies stale secrets cannot cross helper connections
// and the tray recovers a fresh snapshot after a bounded reconnect delay.
func TestRestartCancelsPrompt(t *testing.T) {
	first, second := newConnection(), newConnection()
	view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
	started, cancelled := make(chan struct{}), make(chan struct{})
	dialog := fakeDialog{password: func(ctx context.Context) (string, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return "stale-secret", nil
	}}
	dialed := 0
	startController(t, Options{View: view, Store: &fakeStore{err: secrets.ErrNotFound}, Dialog: dialog, Dial: func(context.Context) (Connection, error) {
		dialed++
		if dialed == 1 {
			return first, nil
		}
		return second, nil
	}})
	awaitCall(t, first, "profile.get")
	first.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "waiting_password"}
	first.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, Kind: "password", ChallengeID: "old"}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("prompt did not start")
	}
	_ = first.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("prompt not cancelled")
	}
	awaitCall(t, second, "profile.get")
	view.actions <- "quit"
	select {
	case r := <-second.calls:
		if r.Op == "answer" {
			t.Fatal("stale secret crossed restart")
		}
	default:
	}
}

// TestPreferencesAndLogs covers persistence failures and bounded helper log selection.
func TestPreferencesAndLogs(t *testing.T) {
	view := &fakeView{menus: make(chan model.Menu, 8)}
	saved, opened := false, ""
	c := controller{profiles: []model.Profile{{ID: "work"}}, options: Options{View: view, Report: func(string) {}, Preferences: userconfig.Defaults(), Save: func(context.Context, paths.Paths, userconfig.Config) error {
		saved = true
		return errors.New("fixture")
	}, OpenLog: func(_ context.Context, id string, lines []string) error {
		if len(lines) != 1 || lines[0] != "redacted diagnostic" {
			t.Fatal("snapshot did not come from helper")
		}
		opened = id
		return nil
	}}}
	if !c.localAction(context.Background(), "animate_icon") || !saved || !c.options.Preferences.AnimateIcon {
		t.Fatal("failed save changed live preference")
	}
	c.options.Save = func(context.Context, paths.Paths, userconfig.Config) error { return nil }
	c.localAction(context.Background(), "animate_icon")
	if c.options.Preferences.AnimateIcon {
		t.Fatal("preference not toggled live")
	}
	conn := newConnection()
	if c.action(context.Background(), conn, "logs:../etc/passwd") == nil {
		t.Fatal("unsafe ID accepted")
	}
	if opened != "" {
		t.Fatal("unsafe log ID accepted")
	}
	if err := c.action(context.Background(), conn, "logs:work"); err != nil {
		t.Fatal(err)
	}
	if r := awaitCall(t, conn, "logs"); r.Lines != 500 || r.Profile != "work" {
		t.Fatal("unbounded or wrong log request")
	}
	if opened != "work" {
		t.Fatal("known helper log not opened")
	}
	opened = ""
	conn.fail = "logs"
	if c.action(context.Background(), conn, "logs:work") == nil || opened != "" {
		t.Fatal("failed helper read opened a snapshot")
	}
}

// TestNotificationPolicy verifies only terminal state changes emit literal notices.
func TestNotificationPolicy(t *testing.T) {
	calls := 0
	c := controller{options: Options{Preferences: userconfig.Defaults(), Report: func(string) {}, Notify: func(_ context.Context, title, body string) error {
		calls++
		if title != "fortix" || !strings.HasPrefix(body, "Work: ") {
			t.Fatal("unsafe notice")
		}
		return nil
	}}}
	for _, phase := range []session.Phase{session.Starting, session.Connected, session.Disconnected, session.Failed} {
		c.notify(context.Background(), &model.Profile{Name: "Work", State: phase})
	}
	if calls != 3 {
		t.Fatalf("notifications = %d", calls)
	}
	c.options.Preferences.Notifications = false
	c.notify(context.Background(), &model.Profile{Name: "Work", State: session.Connected})
	if calls != 3 {
		t.Fatal("disabled notification delivered")
	}
}

// TestFailedAttemptDoesNotSave verifies rejected authentication cannot poison the
// keyring even though the helper accepted the credential delivery operation.
func TestFailedAttemptDoesNotSave(t *testing.T) {
	conn := newConnection()
	view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
	store := &fakeStore{err: secrets.ErrNotFound, saved: make(chan string, 1)}
	dialog := fakeDialog{password: func(context.Context) (string, error) { return "incorrect-secret", nil }}
	startController(t, Options{View: view, Store: store, Dialog: dialog, Preferences: userconfig.Defaults(), Dial: func(context.Context) (Connection, error) { return conn, nil }})
	awaitCall(t, conn, "profile.get")
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "waiting_password"}
	conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, Kind: "password", ChallengeID: "rejected"}
	awaitCall(t, conn, "answer")
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "failed"}
	awaitMenu(t, view, func(m model.Menu) bool { return m.Status == model.Attention })
	select {
	case <-store.saved:
		t.Fatal("failed attempt saved a password")
	default:
	}
}

// TestNewGenerationCancelsPrompt verifies a newer attempt releases the old human
// dialog and ignores late old-generation events before accepting a new code.
func TestNewGenerationCancelsPrompt(t *testing.T) {
	conn := newConnection()
	view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
	started, cancelled := make(chan struct{}), make(chan struct{})
	calls := 0
	dialog := fakeDialog{password: func(ctx context.Context) (string, error) {
		calls++
		if calls == 1 {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return "obsolete-secret", nil
		}
		return "fresh-code", nil
	}}
	startController(t, Options{View: view, Store: &fakeStore{err: secrets.ErrNotFound}, Dialog: dialog, Dial: func(context.Context) (Connection, error) { return conn, nil }})
	awaitCall(t, conn, "profile.get")
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "waiting_password"}
	conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, Kind: "password", ChallengeID: "old"}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("old prompt not started")
	}
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 2, State: "waiting_code"}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("old generation prompt not cancelled")
	}
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "failed"}
	conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 2, Kind: "code", ChallengeID: "new"}
	answer := awaitCall(t, conn, "answer")
	if answer.ChallengeID != "new" || answer.Secret != "fresh-code" {
		t.Fatalf("obsolete challenge answered: %s", answer.ChallengeID)
	}
}

// TestControllerDependencies refuses incomplete wiring before dialing or rendering.
func TestControllerDependencies(t *testing.T) {
	if Run(context.Background(), Options{}) == nil {
		t.Fatal("missing dependencies accepted")
	}
}

// TestKeyringLookupDoesNotRequestAttention verifies an automatic cached password
// answer never advertises a human dialog or starts one.
func TestKeyringLookupDoesNotRequestAttention(t *testing.T) {
	conn := newConnection()
	view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
	store := &fakeStore{password: "cached-secret"}
	dialog := fakeDialog{password: func(context.Context) (string, error) {
		t.Error("cached password started a dialog")
		return "", errors.New("unexpected")
	}}
	startController(t, Options{View: view, Store: store, Dialog: dialog, Dial: func(context.Context) (Connection, error) { return conn, nil }})
	awaitCall(t, conn, "profile.get")
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "waiting_password"}
	conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, Kind: "password", ChallengeID: "cached"}
	awaitCall(t, conn, "answer")
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "connected"}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case menu := <-view.menus:
			if menu.Status == model.Attention {
				t.Fatal("keyring lookup advertised a human prompt")
			}
			if menu.Status == model.Connected {
				return
			}
		case <-timer.C:
			t.Fatal("connection snapshot not received")
		}
	}
}

// TestSavedPasswordRecovery verifies failed cached credentials are bypassed on
// later attempts, while success or an explicit stop does not invalidate the keyring.
func TestSavedPasswordRecovery(t *testing.T) {
	for _, terminal := range []string{"failed", "connected", "disconnected"} {
		t.Run(terminal, func(t *testing.T) {
			conn := newConnection()
			view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
			store := &fakeStore{password: "old-password", saved: make(chan string, 1)}
			dialog := fakeDialog{password: func(context.Context) (string, error) { return "replacement-password", nil }}
			startController(t, Options{View: view, Store: store, Dialog: dialog, Preferences: userconfig.Defaults(), Dial: func(context.Context) (Connection, error) { return conn, nil }})
			awaitCall(t, conn, "profile.get")
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "waiting_password"}
			conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, Kind: "password", ChallengeID: "first"}
			if r := awaitCall(t, conn, "answer"); r.Secret != "old-password" {
				t.Fatal("initial keyring lookup missing")
			}
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: terminal}
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 2, State: "waiting_password"}
			conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 2, Kind: "password", ChallengeID: "second"}
			want := "old-password"
			if terminal == "failed" {
				want = "replacement-password"
			}
			if r := awaitCall(t, conn, "answer"); r.Secret != want || r.ChallengeID != "second" {
				t.Fatal("wrong password recovery")
			}
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 2, State: "connected"}
			if terminal == "failed" {
				select {
				case password := <-store.saved:
					if password != "replacement-password" {
						t.Fatal("wrong replacement saved")
					}
				case <-time.After(time.Second):
					t.Fatal("replacement not saved after success")
				}
			}
		})
	}
}

// TestUnreplayedChallengeAttention verifies snapshots expose waiting attempts
// without inventing a missing challenge ID or opening an unanswerable dialog.
func TestUnreplayedChallengeAttention(t *testing.T) {
	for _, phase := range []string{"waiting_password", "waiting_code", "waiting_trust"} {
		t.Run(phase, func(t *testing.T) {
			conn := newConnection()
			conn.phase = phase
			view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
			startController(t, Options{View: view, Store: &fakeStore{}, Dialog: fakeDialog{}, Dial: func(context.Context) (Connection, error) { return conn, nil }})
			awaitMenu(t, view, func(m model.Menu) bool { return m.Status == model.Attention })
		})
	}
}

// TestHelperFailureDiagnostics distinguishes socket permissions and helper
// authorization rejections from outages and suppresses duplicate retry reports.
func TestHelperFailureDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"permission", os.ErrPermission, "fortix group"},
		{"unauthorized", &client.OperationError{Code: protocol.Unauthorized}, "fortix group"},
		{"unavailable", errors.New("fixture"), "Helper unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := &fakeView{menus: make(chan model.Menu, 8)}
			reports := 0
			c := controller{options: Options{View: view, Report: func(string) { reports++ }}}
			c.helperFailure(tc.err)
			c.helperFailure(tc.err)
			if reports != 1 {
				t.Fatalf("reports = %d", reports)
			}
			menu := <-view.menus
			for _, item := range menu.Items {
				if item.ID == "open_logs" && item.Enabled {
					t.Fatal("offline log fetch enabled")
				}
			}
			if !strings.Contains(menu.Items[0].Title, tc.want) || !strings.Contains(menu.Tooltip, tc.want) {
				t.Fatal("missing actionable helper condition")
			}
		})
	}
}
