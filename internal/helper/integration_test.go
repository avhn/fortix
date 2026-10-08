package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/pinentry"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// Fixture paths are initialized before tests, except in parser fuzz worker processes
// which must not launch nested compilers. The parent owns temporary binary cleanup.
var (
	fixtureHelper, fixtureVPN, fixtureDir string
	fixtureErr                            error
)

// TestMain builds both fixture executables serially before running tests and removes
// them afterwards. Fuzz subprocesses only exercise parsers and skip fixture builds.
func TestMain(m *testing.M) {
	worker := false
	for _, arg := range os.Args[1:] {
		worker = worker || strings.HasPrefix(arg, "-test.fuzzworker")
	}
	if !worker {
		buildFixtures()
	}
	code := 1
	if fixtureErr == nil {
		code = m.Run()
	} else {
		_, _ = fmt.Fprintln(os.Stderr, fixtureErr)
	}
	if fixtureDir != "" {
		_ = os.RemoveAll(fixtureDir)
	}
	os.Exit(code)
}

// buildFixtures compiles the fake child and pinentry entry point with bounded
// compiler concurrency and deadlines, retaining any failure for TestMain to report.
func buildFixtures() {
	fixtureDir, fixtureErr = os.MkdirTemp("", "fortix-fixtures-")
	if fixtureErr != nil {
		return
	}
	fixtureHelper = filepath.Join(fixtureDir, "fortix-helper")
	fixtureVPN = filepath.Join(fixtureDir, "openfortivpn")
	for _, build := range []struct{ path, pkg string }{{fixtureHelper, "../../cmd/fortix-helper"}, {fixtureVPN, "../testutil/fakeofv"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", build.path, build.pkg)
		cmd.Env = append(os.Environ(), "GOMAXPROCS=2", "GOFLAGS=-p=2", "CGO_ENABLED=0")
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			fixtureErr = fmt.Errorf("fixture build: %w: %s", err, output)
			return
		}
	}
}

// ensureFixtures checks that TestMain made fixture binaries available. Fuzz workers
// cannot invoke integration helpers because they intentionally do not build programs.
func ensureFixtures(t *testing.T) {
	t.Helper()
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	if fixtureDir == "" {
		t.Fatal("fixture binaries unavailable in parser worker")
	}
}

// harness owns one isolated helper and its sockets; cleanup waits for child teardown.
type harness struct {
	server *Server
	paths  paths.Paths
	root   string
	cancel context.CancelFunc
	done   chan error
}

// startHarness creates development-only paths, installs fixture binaries, and starts
// an unprivileged helper. Timers are shortened without weakening production defaults.
func startHarness(t *testing.T, authorize Authorizer, configure ...func(*Options)) *harness {
	t.Helper()
	ensureFixtures(t)
	if os.Geteuid() == 0 {
		t.Skip("development helper tests require a non-root user")
	}
	root, err := os.MkdirTemp("/tmp", "fx-")
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
	for _, pair := range [][2]string{{fixtureHelper, p.Pinentry}, {fixtureVPN, p.OpenFortiVPN[0]}} {
		if err := os.MkdirAll(filepath.Dir(pair[1]), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	if authorize == nil {
		authorize = func(p Peer) error {
			if p.UID != uint32(os.Geteuid()) {
				return errors.New("wrong peer uid")
			}
			return nil
		}
	}
	opts := Options{Paths: p, Authorize: authorize, Network: NoNetwork{}, Deadlines: session.Deadlines{Connect: 2 * time.Second, Authenticate: 2 * time.Second, Human: 2 * time.Second, Negotiate: 2 * time.Second, Network: time.Second, Stop: 100 * time.Millisecond}}
	for _, apply := range configure {
		apply(&opts)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{server: s, paths: p, root: root, cancel: cancel, done: make(chan error, 1)}
	go func() { h.done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-h.done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("helper shutdown timed out")
		}
	})
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(p.ControlSocket); err == nil {
			return h
		}
		select {
		case err := <-h.done:
			h.done <- err
			t.Fatalf("startup: %v", err)
		case <-deadline.C:
			t.Fatal("socket did not appear")
		case <-tick.C:
		}
	}
}

// wireMessage decodes the result/event union only in integration tests.
type wireMessage struct {
	protocol.Event
	ID    string          `json:"id"`
	OK    bool            `json:"ok"`
	Error *protocol.Error `json:"error"`
	Data  json.RawMessage `json:"data"`
}

// testClient retains interleaved events while waiting for operation results.
type testClient struct {
	socket  net.Conn
	decoder *json.Decoder
	events  []wireMessage
	serial  int
}

// client opens one control connection and registers deterministic cleanup.
func (h *harness) client(t *testing.T) *testClient {
	t.Helper()
	conn, err := net.DialTimeout("unix", h.paths.ControlSocket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &testClient{socket: conn, decoder: json.NewDecoder(conn)}
}

// read consumes one frame with a finite deadline, failing the test on malformed data.
func (c *testClient) read(t *testing.T) wireMessage {
	t.Helper()
	if err := c.socket.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var message wireMessage
	if err := c.decoder.Decode(&message); err != nil {
		t.Fatal(err)
	}
	return message
}

// request writes one request and waits for exactly its result, preserving events.
func (c *testClient) request(t *testing.T, r protocol.Request) wireMessage {
	t.Helper()
	c.serial++
	r.ID = strconv.Itoa(c.serial)
	if err := protocol.Write(c.socket, r); err != nil {
		t.Fatal(err)
	}
	for {
		message := c.read(t)
		if message.Type == "result" {
			if message.ID != r.ID {
				t.Fatalf("wrong result id: %q", message.ID)
			}
			return message
		}
		c.events = append(c.events, message)
	}
}

// success requires an operation's sole result to indicate success.
func (c *testClient) success(t *testing.T, r protocol.Request) wireMessage {
	t.Helper()
	result := c.request(t, r)
	if !result.OK {
		t.Fatalf("%s failed: %+v", r.Op, result.Error)
	}
	return result
}

// event waits for an event kind/profile/phase, retaining no already inspected events.
func (c *testClient) event(t *testing.T, kind, id, state string) wireMessage {
	t.Helper()
	for {
		var e wireMessage
		if len(c.events) > 0 {
			e = c.events[0]
			c.events = c.events[1:]
		} else {
			e = c.read(t)
		}
		if e.Type == kind && e.Profile == id && (state == "" || e.State == state) {
			return e
		}
	}
}

// profileJSON constructs a secret-free fixture using public placeholder addresses.
func profileJSON(id, scenario string) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":1,"id":%q,"name":"Example VPN","backend":"openfortivpn","gateway":{"host":"vpn.example.com"},"username":"jane.doe","realm":%q,"routes":{"mode":"custom","include":["10.20.0.0/16"]},"dns":{"mode":"none"}}`, id, scenario))
}

// connectFixture puts a profile, subscribes, starts it, and answers its password.
// It returns after the connected event proves the fake child's complete transcript.
func connectFixture(t *testing.T, c *testClient, id, scenario, secret string) {
	t.Helper()
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON(id, scenario)})
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "up", Profile: id})
	challenge := c.event(t, "challenge", id, "")
	if challenge.Kind != "password" {
		t.Fatalf("unexpected challenge kind %q", challenge.Kind)
	}
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: secret})
	c.event(t, "state", id, "connected")
}

// TestLifecycle exercises every management operation, secret-safe logs, active
// mutation refusal, a stale token, down, and durable profile deletion.
func TestLifecycle(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	hello := c.success(t, protocol.Request{Op: "hello", Version: "dev"})
	if !strings.Contains(string(hello.Data), `"protocol":1`) {
		t.Fatal("missing protocol version")
	}
	connectFixture(t, c, "work", "leak", "fixture-secret-917")
	for _, op := range []string{"profile.get", "logs"} {
		c.success(t, protocol.Request{Op: op, Profile: "work"})
	}
	for _, op := range []string{"profile.list", "status"} {
		c.success(t, protocol.Request{Op: op})
	}
	for _, r := range []protocol.Request{{Op: "profile.put", ProfileJSON: profileJSON("work", "")}, {Op: "profile.delete", Profile: "work"}} {
		if result := c.request(t, r); result.OK || result.Error.Code != protocol.Conflict {
			t.Fatal("active mutation was accepted")
		}
	}
	relay, err := net.DialTimeout("unix", h.paths.PinentrySocket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.Write(relay, pinentry.Request{Token: strings.Repeat("0", 64), KeyInfo: "example_password", Prompt: "Password:"}); err != nil {
		t.Fatal(err)
	}
	var rejected pinentry.Response
	if err := protocol.NewReader(relay).Read(&rejected); err != nil || !rejected.Cancel {
		t.Fatalf("stale token accepted: %v", err)
	}
	_ = relay.Close()
	c.success(t, protocol.Request{Op: "down", Profile: "work"})
	c.event(t, "state", "work", "disconnected")
	logs := c.success(t, protocol.Request{Op: "logs", Profile: "work", Lines: 500})
	if strings.Contains(string(logs.Data), "fixture-secret-917") {
		t.Fatal("credential leaked into logs")
	}
	if !strings.Contains(string(logs.Data), "pppd: diagnostic fixture retained") || !strings.Contains(string(logs.Data), "unlabelled [redacted]") {
		t.Fatal("child diagnostics were discarded")
	}
	if err := filepath.WalkDir(h.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".json") && !strings.Contains(path, ".log")) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "fixture-secret-917") {
			t.Error("credential leaked to disk")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c.success(t, protocol.Request{Op: "profile.delete", Profile: "work"})
	if result := c.request(t, protocol.Request{Op: "profile.get", Profile: "work"}); result.OK || result.Error.Code != protocol.NotFound {
		t.Fatal("deleted profile remains available")
	}
}

// TestCertificateTrust permits only the helper-captured digest and confirms that
// successful persistence starts a new attempt rather than bypassing verification.
func TestCertificateTrust(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "cert")})
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	cert := c.event(t, "cert", "work", "")
	if len(cert.Digest) != 64 || cert.Subject == "" {
		t.Fatal("incomplete certificate event")
	}
	bad := c.request(t, protocol.Request{Op: "trust", Profile: "work", Digest: strings.Repeat("a", 64)})
	if bad.OK || bad.Error.Code != protocol.Conflict {
		t.Fatal("arbitrary certificate accepted")
	}
	c.success(t, protocol.Request{Op: "trust", Profile: "work", Digest: cert.Digest})
	challenge := c.event(t, "challenge", "work", "")
	if challenge.Attempt <= cert.Attempt {
		t.Fatal("trust did not start a new generation")
	}
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
	c.event(t, "state", "work", "connected")
	stored := c.success(t, protocol.Request{Op: "profile.get", Profile: "work"})
	if !strings.Contains(string(stored.Data), cert.Digest) {
		t.Fatal("certificate was not persisted")
	}
}

// TestAuthenticationFailureDoesNotRetry verifies terminal credential rejection and
// first-answer-wins behavior without relying on a real gateway or long retry sleeps.
func TestAuthenticationFailureDoesNotRetry(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "auth")})
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	challenge := c.event(t, "challenge", "work", "")
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture-password"})
	repeat := c.request(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "late-password"})
	if repeat.OK || repeat.Error.Code != protocol.NotFound {
		t.Fatal("duplicate answer accepted")
	}
	failed := c.event(t, "state", "work", "failed")
	if failed.Detail != "authentication rejected" {
		t.Fatalf("wrong failure: %q", failed.Detail)
	}
	a := h.server.actor("work")
	snap := a.snapshot()
	if snap.Attempt != 1 || snap.State != session.Failed {
		t.Fatalf("unexpected retry: %+v", snap)
	}
	c.success(t, protocol.Request{Op: "down", All: true})
}

// TestUnauthorizedPeer proves peer lookup occurs before an injected denying policy.
func TestUnauthorizedPeer(t *testing.T) {
	h := startHarness(t, func(peer Peer) error {
		if peer.UID != uint32(os.Geteuid()) {
			return errors.New("unexpected kernel uid")
		}
		return errors.New("denied")
	})
	c := h.client(t)
	result := c.read(t)
	if result.Type != "result" || result.OK || result.Error.Code != protocol.Unauthorized {
		t.Fatal("unauthorized peer admitted")
	}
}

// TestConcurrentProfilesAndShutdown ensures independent child groups and bounded
// shutdown escalation for a fake child that deliberately ignores SIGTERM.
func TestConcurrentProfilesAndShutdown(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	connectFixture(t, c, "one", "ignore-term", "fixture-one")
	connectFixture(t, c, "two", "", "fixture-two")
	c.success(t, protocol.Request{Op: "down", Profile: "two"})
	c.event(t, "state", "two", "disconnected")
	if h.server.actor("one").snapshot().State != session.Connected {
		t.Fatal("stopping one profile affected another")
	}
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown failed to kill child group")
	}
	for _, id := range []string{"one", "two"} {
		if !h.server.actor(id).idle() {
			t.Fatal("child remained active after shutdown")
		}
	}
}

// TestFallbackChallengeAndCancellation routes an orphaned Up request to subscribers
// and verifies explicit cancellation cleans up without an automatic reconnect.
func TestFallbackChallengeAndCancellation(t *testing.T) {
	h := startHarness(t, nil)
	origin := h.client(t)
	other := h.client(t)
	other.success(t, protocol.Request{Op: "subscribe"})
	origin.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "")})
	// A live initiating connection receives the challenge even without subscribing.
	origin.success(t, protocol.Request{Op: "up", Profile: "work"})
	challenge := origin.event(t, "challenge", "work", "")
	other.success(t, protocol.Request{Op: "cancel", ChallengeID: challenge.ChallengeID})
	other.event(t, "state", "work", "failed")
	if h.server.actor("work").snapshot().Attempt != 1 {
		t.Fatal("cancel retried")
	}
}

// TestPhaseTimeoutAndEarlyExit verifies a stalled child and an early zero exit never
// produce connected state. Human deadlines also expire unanswered relay requests.
func TestPhaseTimeoutAndEarlyExit(t *testing.T) {
	for _, scenario := range []string{"stall", "early", "", "exit-0", "exit-7", "exit-255", "exit-invalid"} {
		t.Run("scenario-"+scenario, func(t *testing.T) {
			h := startHarness(t, nil)
			c := h.client(t)
			c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", scenario)})
			c.success(t, protocol.Request{Op: "subscribe"})
			c.success(t, protocol.Request{Op: "up", Profile: "work"})
			c.event(t, "state", "work", "failed")
			if h.server.actor("work").snapshot().Attempt != 1 {
				t.Fatal("early failure retried")
			}
		})
	}
}

// TestMalformedControl verifies bounded framing failure does not expose request text.
func TestMalformedControl(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	if _, err := io.WriteString(c.socket, `{"id":"1","op":"status","secret":"hidden","secret":"hidden"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	result := c.read(t)
	if result.OK || result.Error.Code != protocol.Invalid || strings.Contains(result.Error.Message, "hidden") {
		t.Fatal("malformed request was not safely rejected")
	}
}
