//go:build darwin || linux

package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// TestAttemptUIDRouting keeps pending prompts and certificate fallback within the
// initiating kernel UID, even after disconnect and across retry generations.
func TestAttemptUIDRouting(t *testing.T) {
	origin := &connection{uid: 1001, open: true, events: make(chan protocol.Event, 4)}
	same := &connection{uid: 1001, open: true, subscribed: true, events: make(chan protocol.Event, 4)}
	other := &connection{uid: 1002, open: true, subscribed: true, events: make(chan protocol.Event, 4)}
	root := &connection{uid: 0, open: true, subscribed: true, events: make(chan protocol.Event, 4)}
	s := &Server{clients: map[*connection]bool{origin: true, same: true, other: true, root: true}, challenges: make(map[string]*challengeRoute)}
	e := protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "first", Kind: "password"}
	s.challenges[e.ChallengeID] = &challengeRoute{uid: origin.uid}
	s.emit(e, origin)
	if len(origin.events) != 1 || len(same.events)+len(root.events)+len(other.events) != 0 {
		t.Fatal("initial challenge was not exclusive to its origin")
	}
	s.detach(origin)
	if len(same.events) != 1 || len(root.events) != 1 || len(other.events) != 0 {
		t.Fatal("disconnect transferred a challenge across user identities")
	}
	e.Attempt, e.ChallengeID = 2, "retry"
	s.challenges[e.ChallengeID] = &challengeRoute{uid: origin.uid}
	s.emit(e, origin)
	s.emit(protocol.Event{Type: "cert", Profile: "work", Attempt: 2}, origin, origin.uid)
	if len(same.events) != 3 || len(root.events) != 3 || len(other.events) != 0 {
		t.Fatal("retry or certificate escaped its initiating user")
	}
}

// TestAttemptReplyAuthorization refuses another member's answer, cancellation and
// certificate trust inside the actor, and clears transferred credential buffers.
func TestAttemptReplyAuthorization(t *testing.T) {
	for _, op := range []string{"answer", "cancel", "trust"} {
		for _, uid := range []uint32{0, 1001, 1002} {
			s := &Server{ctx: context.Background(), opts: Options{}, clients: make(map[*connection]bool)}
			a := newSupervisor(s, &profile.Profile{ID: "work"})
			a.ownerUID = 1001
			secret := []byte("fixture-secret")
			reply := make(chan controlReply, 1)
			a.control(controlInput{op: op, origin: &connection{uid: uid}, secret: secret, reply: reply})
			got := <-reply
			if (got.code == protocol.Unauthorized) != (uid == 1002) {
				t.Fatalf("%s from UID %d: %s", op, uid, got.code)
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("rejected reply retained its credential buffer")
			}
		}
	}
}

// TestGatewayChangeClearsPin preserves helper-owned pins only for an unchanged
// endpoint; an imported pin cannot override that decision.
func TestGatewayChangeClearsPin(t *testing.T) {
	for _, change := range []string{"same", "host", "port"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			store, err := OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			p, err := profile.Decode(bytes.NewReader(profileJSON("work", "")))
			if err != nil {
				t.Fatal(err)
			}
			p.TrustedCert = strings.Repeat("a", 64)
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Put(raw); err != nil {
				t.Fatal(err)
			}
			if change == "host" {
				p.Gateway.Host = "other.example.com"
			}
			if change == "port" {
				p.Gateway.Port++
			}
			p.TrustedCert = strings.Repeat("b", 64)
			raw, err = json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{store: store, actors: make(map[string]*supervisor)}
			result := s.dispatch(&connection{uid: 1001}, protocol.Request{ID: "put", Op: "profile.put", ProfileJSON: raw})
			if !result.OK {
				t.Fatalf("put: %+v", result.Error)
			}
			stored, err := store.Get("work")
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if change == "same" {
				want = strings.Repeat("a", 64)
			}
			if stored.TrustedCert != want {
				t.Fatal("pin survived an endpoint change or import installed trust")
			}
		})
	}
}

// TestLogSubscriptionIsolation proves noisy diagnostics cannot fill ordinary
// subscribers' event queues, while explicit log subscribers still receive them.
func TestLogSubscriptionIsolation(t *testing.T) {
	ordinary := &connection{open: true, subscribed: true, events: make(chan protocol.Event, 64)}
	logs := &connection{open: true, subscribed: true, logs: true, events: make(chan protocol.Event, 128)}
	s := &Server{clients: map[*connection]bool{ordinary: true, logs: true}}
	for range 100 {
		s.emit(protocol.Event{Type: "log", Profile: "work", Line: "diagnostic"}, nil)
	}
	if !ordinary.open || len(ordinary.events) != 0 || len(logs.events) != 100 {
		t.Fatal("log events affected a state-only subscriber")
	}
	s.emit(protocol.Event{Type: "state", Profile: "work", State: "failed"}, nil)
	if len(ordinary.events) != 1 {
		t.Fatal("state subscriber lost progress")
	}
}

// TestSpawnFailureDiagnostics captures pre-spawn executable failures in both the
// helper logger and the profile's private log, with fixed safe public state detail.
func TestSpawnFailureDiagnostics(t *testing.T) {
	var output bytes.Buffer
	h := startHarness(t, nil, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(&output, nil))
		o.Paths.OpenFortiVPN = []string{filepath.Join(t.TempDir(), "missing-openfortivpn")}
	})
	c := h.client(t)
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "")})
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	e := c.event(t, "state", "work", "failed")
	if e.Detail != "openfortivpn not found or not trusted; see helper log" {
		t.Fatal(e.Detail)
	}
	result := c.success(t, protocol.Request{Op: "logs", Profile: "work"})
	if !strings.Contains(string(result.Data), e.Detail) || !strings.Contains(string(result.Data), "openfortivpn executable not found") {
		t.Fatal("profile log missed pre-spawn failure or its diagnostic")
	}
	h.cancel()
	if err := <-h.done; err != nil {
		t.Fatal(err)
	}
	h.done <- nil
	if !strings.Contains(output.String(), "openfortivpn start failed") {
		t.Fatal("helper logger missed spawn error")
	}
}

// TestProfileStorageRejectsPublicAccess verifies broad directory or file read
// permissions cannot bypass the group-only profile storage boundary.
func TestProfileStorageRejectsPublicAccess(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenStore(dir); err == nil {
		_ = store.Close()
		t.Fatal("world-readable profile directory accepted")
	}
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, err := store.Put(profileJSON("work", "")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "work.json")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("work"); err == nil {
		t.Fatal("world-readable profile read accepted")
	}
	if _, err := store.Put(profileJSON("work", "")); err == nil {
		t.Fatal("world-readable profile replaced without migration")
	}
}

// TestWantedFailureCanRestart keeps a failed profile wanted for tray aggregation
// without treating its cleaned-up failed generation as an idempotent live Up.
func TestWantedFailureCanRestart(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "auth")})
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	first := c.event(t, "challenge", "work", "")
	c.success(t, protocol.Request{Op: "answer", ChallengeID: first.ChallengeID, Secret: "wrong-password"})
	failed := c.event(t, "state", "work", "failed")
	if !failed.Wanted {
		t.Fatal("failure lost user intent before explicit stop")
	}
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	retry := c.event(t, "challenge", "work", "")
	if retry.Attempt != first.Attempt+1 {
		t.Fatal("cleaned-up wanted failure did not restart")
	}
	c.success(t, protocol.Request{Op: "cancel", ChallengeID: retry.ChallengeID})
	c.event(t, "state", "work", "failed")
	c.success(t, protocol.Request{Op: "down", Profile: "work"})
	stopped := c.event(t, "state", "work", "disconnected")
	if stopped.Wanted {
		t.Fatal("explicit stop retained desired connectivity")
	}
}

// TestWantedFailureWithIncompleteCleanupIsBusy refuses a new child while a wanted
// failed generation still has leaked network resources requiring explicit Down.
func TestWantedFailureWithIncompleteCleanupIsBusy(t *testing.T) {
	s := &Server{clients: make(map[*connection]bool)}
	a := newSupervisor(s, &profile.Profile{ID: "work"})
	a.state.Phase, a.state.Wanted, a.state.Exited, a.state.Cleaned = session.Failed, true, true, false
	a.publish()
	replies := make(chan controlReply, 1)
	a.control(controlInput{op: "up", origin: &connection{uid: 1001}, reply: replies})
	if r := <-replies; r.code != protocol.Busy {
		t.Fatal("wanted failed cleanup was mistaken for a live idempotent attempt")
	}
}

// TestKernelMismatchStateCode reports a stable interface failure to clients and
// never installs a route when kernel verification refuses the reported link.
func TestKernelMismatchStateCode(t *testing.T) {
	runner := &integrationRunner{}
	h := startHarness(t, nil, func(o *Options) {
		adapter, err := network.New(network.Options{Paths: o.Paths, OS: "linux", Runner: runner, Subnets: func() ([]network.InterfaceSubnet, error) { return nil, nil }, VerifyInterface: func(string, netip.Addr) error { return errors.New("injected kernel mismatch") }})
		if err != nil {
			t.Fatal(err)
		}
		o.Network = adapter
	})
	c := h.client(t)
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "")})
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	challenge := c.event(t, "challenge", "work", "")
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
	failed := c.event(t, "state", "work", "failed")
	if failed.Code != protocol.InterfaceMismatch || !strings.Contains(failed.Detail, "negotiated local IP") {
		t.Fatalf("missing kernel refusal code: %+v", failed)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.routes) != 0 {
		t.Fatal("kernel mismatch installed a route")
	}
}

// TestIdleStatusHidesLink keeps the last attempt's interface and address out of the
// published status once a profile is idle, while a live attempt still reports them.
func TestIdleStatusHidesLink(t *testing.T) {
	s := &Server{clients: make(map[*connection]bool)}
	a := newSupervisor(s, &profile.Profile{ID: "work"})
	a.state.Phase, a.state.Interface, a.state.LocalIP = session.Connected, "utun7", netip.MustParseAddr("10.99.0.2")
	a.publish()
	if a.public.Interface != "utun7" || a.public.LocalIP != "10.99.0.2" {
		t.Fatalf("live attempt lost its link: %+v", a.public)
	}
	a.state.Phase = session.Disconnected
	a.publish()
	if a.public.Interface != "" || a.public.LocalIP != "" {
		t.Fatalf("idle profile kept a stale link: %+v", a.public)
	}
}
