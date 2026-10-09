//go:build darwin || linux

// Package cli verifies socket commands against the helper with isolated storage and a fake VPN.
package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/helper"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/secrets"
	"github.com/avhn/fortix/internal/session"
)

// stopGateNetwork delays only an explicitly armed teardown without host networking.
// Embedding NoNetwork preserves no-op configuration and recovery for trust attempts.
type stopGateNetwork struct {
	helper.NoNetwork
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// Teardown acknowledges the cleanup phase, then waits for test release or its deadline.
func (n *stopGateNetwork) Teardown(ctx context.Context, _ helper.Journal) error {
	if !n.armed.Load() {
		return nil
	}
	select {
	case n.entered <- struct{}{}:
	default:
	}
	select {
	case <-n.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// unblock allows teardown to complete exactly once, including failed-test cleanup.
func (n *stopGateNetwork) unblock() { n.once.Do(func() { close(n.release) }) }

// TestRealHelperTrust drives certificate rejection, recapture, pinning, and password delivery.
// A profile replacement immediately after down proves exit and cleanup were acknowledged.
// All sockets and files are temporary; the fake VPN never changes routes or opens a gateway connection.
func TestRealHelperTrust(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("development helper paths require a non-root user")
	}
	root, err := os.MkdirTemp("", "fx-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	p, err := paths.Resolve(paths.Override{RootDir: root, SkipTrust: true, HelperPath: "/libexec/fortix-helper", HomeDir: "/home/test", ConfigHome: "/config", ControlSocket: filepath.Join(root, "run/control.sock"), PinentrySocket: filepath.Join(root, "run/private/pinentry.sock")})
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ output, pkg string }{{p.Pinentry, "../../cmd/fortix-helper"}, {p.OpenFortiVPN[0], "../testutil/fakeofv"}} {
		if err := os.MkdirAll(filepath.Dir(fixture.output), 0755); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", fixture.output, fixture.pkg)
		cmd.Env = append(os.Environ(), "GOMAXPROCS=2", "GOFLAGS=-p=2", "CGO_ENABLED=0")
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("fixture build: %v: %s", err, output)
		}
	}
	network := &stopGateNetwork{entered: make(chan struct{}, 1), release: make(chan struct{})}
	server, err := helper.New(helper.Options{Paths: p, Network: network, Authorize: func(peer helper.Peer) error {
		if peer.UID != uint32(os.Geteuid()) {
			return os.ErrPermission
		}
		return nil
	}, Deadlines: session.Deadlines{Connect: 2 * time.Second, Authenticate: 2 * time.Second, Human: 2 * time.Second, Negotiate: 2 * time.Second, Network: time.Second, Stop: 100 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("helper shutdown timed out")
		}
	})
	t.Cleanup(network.unblock)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(p.ControlSocket); err == nil {
			break
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("helper startup: %v", err)
		case <-deadline.C:
			t.Fatal("helper socket did not appear")
		case <-tick.C:
		}
	}
	fixture, err := os.ReadFile("../profile/testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(root, "profile.json")
	fixture = []byte(strings.Replace(string(fixture), `"realm": ""`, `"realm": "cert"`, 1))
	if !strings.Contains(string(fixture), `"realm": "cert"`) {
		t.Fatal("fixture did not select certificate scenario")
	}
	if err := os.WriteFile(profilePath, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	store := &secrets.Memory{}
	options := testOptions(p.ControlSocket, store, &fakePrompt{yes: true, responses: []string{"fixture-password"}}, true)
	for _, step := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"profile", "add", profilePath}, 0, ""},
		{[]string{"up", "work"}, 1, "fortix trust work"},
		{[]string{"trust", "work"}, 0, "work: connected"},
		{[]string{"up", "work"}, 0, "work: connected"},
		{[]string{"profile", "show", "work"}, 0, `"trusted_cert": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`},
		{[]string{"down", "--all"}, 0, ""},
		{[]string{"profile", "add", profilePath}, 0, ""},
	} {
		var code int
		var out, diag string
		if step.args[0] == "down" {
			network.armed.Store(true)
			// The short observation window lets an incorrectly early CLI return
			// reach the result channel while network cleanup remains blocked.
			const observationWindow = 25 * time.Millisecond
			// result transfers captured CLI output after the invocation finishes.
			type result struct {
				code      int
				out, diag string
			}
			completed := make(chan result, 1)
			go func() {
				code, out, diag := runCommand(t, step.args, options)
				completed <- result{code, out, diag}
			}()
			select {
			case <-network.entered:
			case early := <-completed:
				t.Fatalf("down returned before cleanup: %#v", early)
			case <-time.After(time.Second):
				t.Fatal("down did not reach cleanup")
			}
			select {
			case early := <-completed:
				t.Fatalf("down returned during cleanup: %#v", early)
			case <-time.After(observationWindow):
			}
			network.unblock()
			select {
			case finished := <-completed:
				code, out, diag = finished.code, finished.out, finished.diag
			case <-time.After(2 * time.Second):
				t.Fatal("down did not acknowledge cleanup")
			}
		} else {
			code, out, diag = runCommand(t, step.args, options)
		}
		if code != step.code || !strings.Contains(out+diag, step.want) {
			t.Fatalf("%v: code %d output %s diagnostics %s", step.args, code, out, diag)
		}
	}
	if password, err := store.Get(secrets.Key(credentialProfile("work"))); err != nil || password != "fixture-password" {
		t.Fatal("successful attempt did not save its prompted password")
	}
}
