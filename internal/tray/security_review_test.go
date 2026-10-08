package tray

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
	"github.com/avhn/fortix/internal/session"
	"github.com/avhn/fortix/internal/tray/model"
)

// TestUnownedPromptsAreIgnored simulates a CLI-started attempt on the same desktop
// UID and proves a tray neither opens dialogs nor supplies credentials or trust.
func TestUnownedPromptsAreIgnored(t *testing.T) {
	conn := newConnection()
	view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
	dialog := fakeDialog{
		password: func(context.Context) (string, error) {
			t.Error("unowned password dialog")
			return "", errors.New("unexpected")
		},
		confirm: func(context.Context, string) (bool, error) {
			t.Error("unowned certificate dialog")
			return false, errors.New("unexpected")
		},
	}
	startController(t, Options{View: view, Store: &secrets.Memory{}, Dialog: dialog, Dial: func(context.Context) (Connection, error) { return conn, nil }})
	awaitCall(t, conn, "profile.get")
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "waiting_password", Wanted: true}
	conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, Kind: "password", ChallengeID: "cli-password"}
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "waiting_trust", Wanted: true}
	conn.events <- protocol.Event{Type: "cert", Profile: "work", Attempt: 1, Digest: strings.Repeat("a", 64)}
	conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "connected", Wanted: true}
	awaitMenu(t, view, func(m model.Menu) bool { return m.Status == model.Connected })
	for len(conn.calls) > 0 {
		if r := <-conn.calls; r.Op == "answer" || r.Op == "trust" || r.Op == "cancel" {
			t.Fatal("tray replied to a CLI-owned attempt")
		}
	}
}

// TestRefreshReplacesWantedIntent discards stale local desired state and reflects
// failed and active profiles started outside the tray from current helper snapshots.
func TestRefreshReplacesWantedIntent(t *testing.T) {
	for _, phase := range []string{"disconnected", "failed", "connected", "stopping"} {
		conn := newConnection()
		conn.phase = phase
		view := &fakeView{menus: make(chan model.Menu, 8)}
		c := controller{options: Options{View: view}, reachable: true, attempts: make(map[string]uint64), profiles: []model.Profile{{ID: "work", Wanted: phase == "disconnected"}}}
		if err := c.refresh(t.Context(), conn, nil); err != nil {
			t.Fatal(err)
		}
		want := phase == "failed" || phase == "connected"
		if c.profiles[0].Wanted != want {
			t.Fatalf("%s retained stale wanted intent", phase)
		}
	}
}

// TestForgetPasswordAndFailedCleanup verifies profile-local keyring deletion and
// ensures a failed profile with incomplete cleanup sends Down instead of Up.
func TestForgetPasswordAndFailedCleanup(t *testing.T) {
	store := &secrets.Memory{}
	key := "work:" + strings.Repeat("a", 64)
	if err := store.Set(key, "fixture-password"); err != nil {
		t.Fatal(err)
	}
	c := controller{options: Options{Store: store}, profiles: []model.Profile{{ID: "work", State: session.Failed, CleanupPending: true}}, keys: map[string]string{"work": key}, bypassKeyring: make(map[string]bool)}
	conn := newConnection()
	if err := c.action(t.Context(), conn, "forget:work"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(key); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatal("password remained saved")
	}
	if err := c.action(t.Context(), conn, "profile:work"); err != nil {
		t.Fatal(err)
	}
	if r := awaitCall(t, conn, "down"); r.Profile != "work" {
		t.Fatal("failed cleanup did not stop its profile")
	}
	menu := model.Build(c.profiles, true, model.Preferences{})
	found := false
	for _, item := range menu.Items {
		if item.ID == "forget:work" && item.Enabled {
			found = true
		}
		if item.ID == "disconnect_all" && !item.Enabled {
			t.Fatal("failed profile was not stoppable")
		}
	}
	if !found {
		t.Fatal("missing per-profile forget-password action")
	}
}

// TestCertificateDisplayIsBounded prevents enormous remote subject and issuer
// strings from overwhelming a native trust dialog while retaining the exact digest.
func TestCertificateDisplayIsBounded(t *testing.T) {
	text := strings.Repeat("界", 1000)
	if got := certificateText(text); len([]rune(got)) != 259 || !strings.HasSuffix(got, "...") {
		t.Fatal("certificate identity was not capped")
	}
	c := controller{options: Options{Dialog: fakeDialog{confirm: func(_ context.Context, message string) (bool, error) {
		if strings.Contains(message, text) || !strings.Contains(message, strings.Repeat("a", 64)) || len([]rune(message)) > 700 {
			t.Error("unbounded certificate confirmation")
		}
		return false, nil
	}}}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tasks := make(chan task, 1)
	replies := make(chan response, 1)
	done := make(chan struct{})
	go func() { defer close(done); c.prompts(ctx, tasks, replies) }()
	tasks <- task{ctx: ctx, event: protocol.Event{Type: "cert", Profile: "work", Digest: strings.Repeat("a", 64), Subject: text, Issuer: text}}
	select {
	case <-replies:
	case <-time.After(time.Second):
		t.Fatal("certificate dialog did not return")
	}
	cancel()
	<-done
}

// TestRetryPromptProvenance allows only a retry initiated by this tray connection,
// never a CLI attempt that replaces the tray's older backoff generation.
func TestRetryPromptProvenance(t *testing.T) {
	for _, initiated := range []bool{false, true} {
		t.Run(map[bool]string{false: "cli", true: "tray"}[initiated], func(t *testing.T) {
			conn := newConnection()
			view := &fakeView{actions: make(chan string, 8), menus: make(chan model.Menu, 64)}
			store := &fakeStore{password: "cached-password"}
			dialog := fakeDialog{password: func(context.Context) (string, error) {
				t.Error("unexpected human prompt")
				return "", errors.New("unexpected")
			}}
			startController(t, Options{View: view, Store: store, Dialog: dialog, Dial: func(context.Context) (Connection, error) { return conn, nil }})
			awaitCall(t, conn, "profile.get")
			view.actions <- "profile:work"
			awaitCall(t, conn, "up")
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "backoff", Wanted: true}
			conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 2, State: "waiting_password", Wanted: true, Initiated: initiated}
			conn.events <- protocol.Event{Type: "challenge", Profile: "work", Attempt: 2, Kind: "password", ChallengeID: "retry"}
			if initiated {
				if r := awaitCall(t, conn, "answer"); r.ChallengeID != "retry" || r.Secret != "cached-password" {
					t.Fatal("own retry lost its password")
				}
			} else {
				conn.events <- protocol.Event{Type: "state", Profile: "work", Attempt: 2, State: "connected", Wanted: true}
				awaitMenu(t, view, func(m model.Menu) bool { return m.Status == model.Connected })
				for len(conn.calls) > 0 {
					if r := <-conn.calls; r.Op == "answer" {
						t.Fatal("tray answered a CLI retry")
					}
				}
			}
		})
	}
}

// TestRefreshRetainsOnlyOwnRetry updates owned retry generations from a snapshot
// while refusing to claim an attempt started by another connection between polls.
func TestRefreshRetainsOnlyOwnRetry(t *testing.T) {
	for _, initiated := range []bool{false, true} {
		conn := newConnection()
		conn.phase, conn.snapshotAttempt, conn.initiated = "starting", 2, initiated
		view := &fakeView{menus: make(chan model.Menu, 8)}
		c := controller{options: Options{View: view}, reachable: true, attempts: map[string]uint64{"work": 1}, started: map[string]uint64{"work": 1}, profiles: []model.Profile{{ID: "work", State: session.Backoff, Wanted: true}}}
		if err := c.refresh(t.Context(), conn, nil); err != nil {
			t.Fatal(err)
		}
		want := uint64(1)
		if initiated {
			want = 2
		}
		if c.started["work"] != want {
			t.Fatal("snapshot changed attempt ownership incorrectly")
		}
	}
}
