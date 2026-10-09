//go:build darwin || linux

package helper

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/native"
	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/ppp"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
	"github.com/avhn/fortix/internal/tun"
)

// assemblyNetwork records native ownership boundaries without executing host commands.
// An injected failure verifies that no data gate opens after network application fails.
type assemblyNetwork struct {
	NoNetwork
	mu           sync.Mutex
	steps        []string
	fail         error
	device       *assemblyDevice
	applied      chan struct{}
	block        bool
	drop         bool
	registerFail error
	renegotiate  chan struct{}
	stall        bool
}

// record appends one serialized resource-lifecycle observation for order assertions.
func (n *assemblyNetwork) record(step string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.steps = append(n.steps, step)
}

// RegisterLink durably acknowledges child-free identity before any fake configuration.
func (n *assemblyNetwork) RegisterLink(ctx context.Context, id string, generation uint64, link backend.LinkIdentity, j *Journal, persist func(Journal) error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if id != j.Profile || generation != j.Attempt || link.PID != 0 || link.Index == 0 {
		return errors.New("bad native identity")
	}
	j.Backend, j.Interface, j.Link = "native", link.Interface, &link
	if err := persist(*j); err != nil {
		return err
	}
	n.record("register")
	return n.registerFail
}

// ConfigureNative persists address intent, standing in for fixed privileged commands.
func (n *assemblyNetwork) ConfigureNative(_ context.Context, e session.Effect, j *Journal, persist func(Journal) error) error {
	j.LocalIP, j.PeerIP, j.MTU = e.LocalIP.String(), e.PeerIP.String(), e.MTU
	if err := persist(*j); err != nil {
		return err
	}
	n.record("configure")
	return nil
}

// Apply acknowledges native routes/DNS or blocks until cancellation for phase tests.
// External profiles retain the existing no-network fixture behavior.
func (n *assemblyNetwork) Apply(ctx context.Context, p *profile.Profile, _ session.Effect, j *Journal, _ func(Journal) error) error {
	if p.Backend != "native" {
		return nil
	}
	if j.Link == nil || j.PID != 0 || j.LocalIP != "10.8.0.2" || j.GatewayIP != "127.0.0.1" {
		return errors.New("incomplete native journal")
	}
	n.record("apply")
	if n.applied != nil {
		close(n.applied)
	}
	if n.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return n.fail
}

// Teardown verifies that the transport is stopped but its device still exists.
func (n *assemblyNetwork) Teardown(_ context.Context, j Journal) error {
	if j.Backend != "native" {
		return nil
	}
	n.mu.Lock()
	device := n.device
	n.mu.Unlock()
	if device != nil {
		select {
		case <-device.closed:
			return errors.New("device closed before network teardown")
		default:
		}
	}
	n.record("teardown")
	return nil
}

// assemblyDevice records device closure separately from cancellable packet I/O.
type assemblyDevice struct {
	*tun.Fake
	network *assemblyNetwork
	closed  chan struct{}
	once    sync.Once
}

// Close records final device release once and preserves Fake's close-unblocking I/O.
func (d *assemblyDevice) Close() error {
	d.once.Do(func() { d.network.record("close"); close(d.closed) })
	return d.Fake.Close()
}

// simulatorPacket encodes bounded PPP control packets for the fake gateway peer.
func simulatorPacket(protocol uint16, code, id byte, data []byte) []byte {
	packet := make([]byte, 6+len(data))
	binary.BigEndian.PutUint16(packet, protocol)
	packet[2], packet[3] = code, id
	binary.BigEndian.PutUint16(packet[4:6], uint16(4+len(data)))
	copy(packet[6:], data)
	return packet
}

// simulatePPP accepts uncompressed LCP/IPCP, allocates IPv4 and echoes data packets.
// All transport operations are bounded and local; termination is explicitly acked.
// A one-shot trigger offers a new MRU and addressing while outbound traffic is idle.
func simulatePPP(conn net.Conn, reader io.Reader, n *assemblyNetwork) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	lcpSent, ipcpSent, renewing := false, false, false
	for {
		packet, err := native.ReadFrame(reader)
		if err != nil {
			return
		}
		if len(packet) < 2 {
			return
		}
		protocol := binary.BigEndian.Uint16(packet)
		if protocol == ppp.ProtocolIPv4 {
			if native.WriteFrame(conn, packet) != nil {
				return
			}
			n.mu.Lock()
			drop := n.drop
			n.drop = false
			n.mu.Unlock()
			if drop {
				return
			}
			continue
		}
		control, err := ppp.DecodeControl(packet[2:])
		if err != nil {
			return
		}
		switch control.Code {
		case ppp.ConfigureRequest:
			code := ppp.ConfigureAck
			data := append([]byte(nil), control.Data...)
			if protocol == ppp.ProtocolIPCP {
				for i := 0; i+6 <= len(data); i += int(data[i+1]) {
					if data[i] == 3 && binary.BigEndian.Uint32(data[i+2:i+6]) == 0 {
						code = ppp.ConfigureNak
						copy(data[i+2:i+6], []byte{10, 8, 0, 2})
						if renewing {
							copy(data[i+2:i+6], []byte{10, 9, 0, 2})
						}
					}
					if data[i] == 129 {
						copy(data[i+2:i+6], []byte{10, 8, 0, 53})
					}
					if data[i] == 131 {
						copy(data[i+2:i+6], []byte{10, 8, 0, 54})
					}
				}
				if !reflect.DeepEqual(data, control.Data) {
					code = ppp.ConfigureNak
				}
			}
			if native.WriteFrame(conn, simulatorPacket(protocol, code, control.ID, data)) != nil {
				return
			}
			if protocol == ppp.ProtocolLCP && !lcpSent {
				lcpSent = true
				if native.WriteFrame(conn, simulatorPacket(protocol, ppp.ConfigureRequest, 71, []byte{1, 4, 5, 74, 5, 6, 0, 0, 0, 42})) != nil {
					return
				}
			}
			if protocol == ppp.ProtocolIPCP && !ipcpSent {
				ipcpSent = true
				peer := []byte{3, 6, 10, 8, 0, 1}
				if renewing {
					peer = []byte{3, 6, 10, 9, 0, 1}
				}
				if native.WriteFrame(conn, simulatorPacket(protocol, ppp.ConfigureRequest, 72, peer)) != nil {
					return
				}
			}
		case ppp.ConfigureAck:
			if protocol != ppp.ProtocolIPCP || renewing {
				continue
			}
			n.mu.Lock()
			trigger := n.renegotiate
			n.renegotiate = nil
			n.mu.Unlock()
			if trigger != nil {
				select {
				case <-trigger:
				case <-time.After(3 * time.Second):
					return
				}
				renewing, ipcpSent = true, false
				if native.WriteFrame(conn, simulatorPacket(ppp.ProtocolLCP, ppp.ConfigureRequest, 73, []byte{1, 4, 4, 176, 5, 6, 0, 0, 0, 43})) != nil {
					return
				}
			}
		case ppp.TerminateRequest:
			n.record("terminate")
			_ = native.WriteFrame(conn, simulatorPacket(protocol, ppp.TerminateAck, control.ID, control.Data))
			return
		}
	}
}

// assemblyBackend serves a fake TLS gateway and injects a packet-only device factory.
// mode stalls setup or returns a typed login failure without host network mutation.
func assemblyBackend(t *testing.T, n *assemblyNetwork, mode string) (backend.Backend, <-chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/remote/logincheck":
			if err := r.ParseForm(); err != nil {
				return
			}
			if mode == "login" {
				entered <- struct{}{}
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
				return
			}
			if mode == "eof" {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			if mode == "auth" {
				_, _ = io.WriteString(w, "ret=0")
				return
			}
			if mode == "mfa" {
				_, _ = io.WriteString(w, "ret=6&tokeninfo=fixture")
				return
			}
			w.Header().Set("Set-Cookie", "SVPNCOOKIE=test-token")
			_, _ = io.WriteString(w, "ret=1")
		case "/remote/fortisslvpn_xml":
			if mode == "http" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "fixture-private-body")
				return
			}
			_, _ = io.WriteString(w, `<sslvpn><assigned-addr ipv4="10.8.0.99"/><dns ip="10.8.0.55"/><split-tunnel-info><addr ip="10.20.0.0" mask="255.255.0.0"/></split-tunnel-info></sslvpn>`)
		case "/remote/sslvpn-tunnel":
			conn, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			if mode == "ppp" {
				_ = native.WriteFrame(conn, []byte{0})
				_ = conn.Close()
				return
			}
			if mode == "negotiation" {
				entered <- struct{}{}
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = io.Copy(io.Discard, buffer)
				_ = conn.Close()
				return
			}
			simulatePPP(conn, buffer, n)
		case "/remote/logout":
			n.record("logout")
			_, _ = io.WriteString(w, "ok")
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	t.Cleanup(server.Close)
	digest := sha256.Sum256(server.Certificate().Raw)
	implementation := native.NewBackend(native.BackendOptions{
		Client: func(p profile.Profile) (*native.Client, error) {
			pin := hex.EncodeToString(digest[:])
			if mode == "trust" {
				pin = ""
			}
			return native.NewClient(native.Options{Host: p.Gateway.Host, TrustedCert: pin, Timeout: time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				if err == nil && mode == "stall" {
					conn = newAssemblyStalledConn(conn, n)
				}
				return conn, err
			}})
		},
		CreateTUN: func(ctx context.Context, mtu int) (tun.Device, error) {
			if mode == "creation" {
				entered <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			fake, err := tun.NewFake("utun42", 42, mtu)
			if err != nil {
				return nil, err
			}
			device := &assemblyDevice{Fake: fake, network: n, closed: make(chan struct{})}
			n.mu.Lock()
			n.device = device
			n.mu.Unlock()
			return device, nil
		},
		PPP: ppp.Config{Magic: 7, RetryInterval: 30 * time.Millisecond, NegotiationTimeout: time.Second}, StopTimeout: 100 * time.Millisecond,
	})
	return implementation, entered
}

// startNativeProfile starts a native attempt through the real socket/challenge broker.
// Password delivery is optional so down can be exercised while the broker waits.
func startNativeProfile(t *testing.T, c *testClient, id string, answer bool) {
	t.Helper()
	data := strings.Replace(string(profileJSON(id, "")), `"backend":"openfortivpn"`, `"backend":"native"`, 1)
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: []byte(data)})
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "up", Profile: id})
	challenge := c.event(t, "challenge", id, "")
	if answer {
		c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "synthetic-password"})
	}
}

// TestNativeAssembly verifies TLS, PPP, durable registration, packet gating, mixed
// external/native attempts and stop ordering through the production supervisor seam.
func TestNativeAssembly(t *testing.T) {
	n := &assemblyNetwork{}
	implementation, _ := assemblyBackend(t, n, "")
	h := startHarness(t, nil, func(o *Options) { o.Network = n; o.Backends = map[string]backend.Backend{"native": implementation} })
	c := h.client(t)
	startNativeProfile(t, c, "native", true)
	c.event(t, "state", "native", "connected")
	n.mu.Lock()
	device := n.device
	n.mu.Unlock()
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 20)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := device.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	if got, err := device.Receive(ctx); err != nil || !reflect.DeepEqual(got, packet) {
		t.Fatalf("packet round trip: %x %v", got, err)
	}
	connectFixture(t, c, "external", "", "other-password")
	c.success(t, protocol.Request{Op: "down", All: true})
	c.event(t, "state", "native", "disconnected")
	// Terminal events may arrive in either profile order; snapshots prove both clean.
	deadline := time.Now().Add(time.Second)
	for !h.server.actors["external"].idle() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !h.server.actors["external"].idle() {
		t.Fatal("external attempt not cleaned")
	}
	n.mu.Lock()
	steps := append([]string(nil), n.steps...)
	n.mu.Unlock()
	want := []string{"register", "configure", "apply", "terminate", "logout", "teardown", "close"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("lifecycle %v, want %v", steps, want)
	}
	if _, err := os.Stat(filepath.Join(h.paths.State, "native.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains: %v", err)
	}
	logs := string(c.success(t, protocol.Request{Op: "logs", Profile: "native", Lines: 500}).Data)
	for _, milestone := range []string{"connecting to gateway", "authenticated", "allocated", "PPP negotiated with local address", "link configured", "tunnel up", "stopping"} {
		if !strings.Contains(logs, milestone) {
			t.Fatalf("missing %q in native logs: %s", milestone, logs)
		}
	}
	if strings.Contains(logs, "test-token") || strings.Contains(logs, "test-password") {
		t.Fatalf("credential leaked: %s", logs)
	}
}

// TestNativeDownPhases verifies cancellation during broker wait, TLS login, PPP,
// network application and data forwarding, retaining no device or attempt journal.
func TestNativeDownPhases(t *testing.T) {
	for _, phase := range []string{"password", "login", "negotiation", "creation", "network", "connected"} {
		t.Run(phase, func(t *testing.T) {
			n := &assemblyNetwork{}
			if phase == "network" {
				n.block = true
				n.applied = make(chan struct{})
			}
			implementation, entered := assemblyBackend(t, n, phase)
			h := startHarness(t, nil, func(o *Options) { o.Network = n; o.Backends = map[string]backend.Backend{"native": implementation} })
			c := h.client(t)
			startNativeProfile(t, c, "phase", phase != "password")
			switch phase {
			case "login", "negotiation", "creation":
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("setup phase not reached")
				}
			case "network":
				select {
				case <-n.applied:
				case <-time.After(2 * time.Second):
					t.Fatal("network phase not reached")
				}
			case "connected":
				c.event(t, "state", "phase", "connected")
			}
			c.success(t, protocol.Request{Op: "down", Profile: "phase"})
			c.event(t, "state", "phase", "disconnected")
			if _, err := os.Stat(filepath.Join(h.paths.State, "phase.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("journal remains: %v", err)
			}
		})
	}
}

// TestNativeFatalOutcomes verifies actionable trust/MFA/auth and network conflicts
// without retries or a silent external-backend fallback after credentials are sent.
func TestNativeFatalOutcomes(t *testing.T) {
	for _, mode := range []string{"auth", "mfa", "trust", "conflict", "registration", "eof", "http", "ppp"} {
		t.Run(mode, func(t *testing.T) {
			n := &assemblyNetwork{}
			if mode == "conflict" {
				n.fail = &network.ConflictError{Detail: "fixture route belongs to another link"}
			}
			if mode == "registration" {
				n.registerFail = &network.ConflictError{Detail: "fixture link already owned"}
			}
			implementation, _ := assemblyBackend(t, n, mode)
			h := startHarness(t, nil, func(o *Options) { o.Network = n; o.Backends = map[string]backend.Backend{"native": implementation} })
			c := h.client(t)
			startNativeProfile(t, c, "failure", true)
			state := "failed"
			if mode == "trust" {
				state = "waiting_trust"
			}
			e := c.event(t, "state", "failure", state)
			if (mode == "conflict" || mode == "registration") && e.Code != protocol.Conflict {
				t.Fatalf("missing conflict code: %+v", e)
			}
			if e.Attempt != 1 {
				t.Fatalf("unexpected retry: %d", e.Attempt)
			}
			if _, err := os.Stat(filepath.Join(h.paths.State, "failure.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unclean fatal attempt: %v", err)
			}
			if mode == "mfa" && !strings.Contains(e.Detail, "second factors") {
				t.Fatalf("MFA failure not actionable: %q", e.Detail)
			}
			if (e.Code == backend.AuthenticationFailedCode) != (mode == "auth") {
				t.Fatalf("incorrect authentication code for %s: %+v", mode, e)
			}
			if mode == "http" && e.Detail != "gateway HTTP status 403" {
				t.Fatalf("HTTP status missing: %q", e.Detail)
			}
			logs := string(c.success(t, protocol.Request{Op: "logs", Profile: "failure", Lines: 500}).Data)
			if !strings.Contains(logs, "connecting to gateway") || !strings.Contains(logs, "terminal error:") {
				t.Fatalf("missing native diagnostics: %s", logs)
			}
			for _, secret := range []string{"test-token", "fixture-private-body", "test-password"} {
				if strings.Contains(logs, secret) {
					t.Fatalf("native logs leaked %q", secret)
				}
			}
			if mode == "eof" && !strings.Contains(logs, "EOF") {
				t.Fatalf("terminal EOF missing: %s", logs)
			}
		})
	}
}

// assemblyRecovery checks exact child-free metadata and can refuse unproved cleanup.
type assemblyRecovery struct {
	NoNetwork
	seen Journal
	fail bool
}

// Recover records native ownership and returns an injected cleanup failure when set.
func (n *assemblyRecovery) Recover(_ context.Context, j Journal) error {
	n.seen = j
	if n.fail {
		return errors.New("fixture ownership discovery failed")
	}
	return nil
}

// TestNativeJournalRecovery verifies child-free crash records reach network recovery
// without process signalling, and remain durable when recovery cannot prove cleanup.
func TestNativeJournalRecovery(t *testing.T) {
	h := startHarness(t, nil)
	h.cancel()
	if err := <-h.done; err != nil {
		t.Fatal(err)
	}
	h.done <- nil
	j := Journal{Profile: "recovered", Attempt: 3, Backend: "native", Interface: "utun42", Link: &backend.LinkIdentity{Interface: "utun42", Index: 42}}
	if err := writeJournal(h.paths.State, j); err != nil {
		t.Fatal(err)
	}
	recovery := &assemblyRecovery{fail: true}
	s, err := New(Options{Paths: h.paths, Network: recovery})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.recover(ctx); err == nil {
		t.Fatal("unproved cleanup accepted")
	}
	if !reflect.DeepEqual(recovery.seen, j) {
		t.Fatalf("wrong recovery journal: %+v", recovery.seen)
	}
	if _, err := os.Stat(filepath.Join(h.paths.State, "recovered.json")); err != nil {
		t.Fatalf("failed recovery lost journal: %v", err)
	}
	recovery.fail = false
	if err := s.recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.paths.State, "recovered.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native crash journal remains: %v", err)
	}
}

// TestNativeReconnect verifies connected transport loss uses the existing reducer's
// retry policy, obtains a fresh password, and cannot reuse the old device or journal.
func TestNativeReconnect(t *testing.T) {
	n := &assemblyNetwork{drop: true}
	implementation, _ := assemblyBackend(t, n, "")
	h := startHarness(t, nil, func(o *Options) { o.Network = n; o.Backends = map[string]backend.Backend{"native": implementation} })
	c := h.client(t)
	startNativeProfile(t, c, "retry", true)
	c.event(t, "state", "retry", "connected")
	n.mu.Lock()
	old := n.device
	n.mu.Unlock()
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 20)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := old.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	c.event(t, "state", "retry", "backoff")
	challenge := c.event(t, "challenge", "retry", "")
	if challenge.Attempt != 2 {
		t.Fatalf("retry generation=%d", challenge.Attempt)
	}
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fresh-synthetic-password"})
	c.event(t, "state", "retry", "connected")
	n.mu.Lock()
	fresh := n.device
	n.mu.Unlock()
	if fresh == old {
		t.Fatal("retry reused old device")
	}
	select {
	case <-old.closed:
	default:
		t.Fatal("old device remained live during retry")
	}
	c.success(t, protocol.Request{Op: "down", Profile: "retry"})
	c.event(t, "state", "retry", "disconnected")
}
