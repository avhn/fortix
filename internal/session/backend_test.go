package session

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/backend"
)

// nativeNegotiating returns an authenticated native attempt without touching the host.
func nativeNegotiating(t testing.TB) State {
	t.Helper()
	s, _ := apply(t, New("work", Options{Backend: "native", MFAMode: "none"}), Up, Starting)
	s, _ = observe(t, s, backend.ConnectedToGateway{}, Authenticating)
	s, _ = observe(t, s, backend.Authenticated{}, Negotiating)
	return s
}

// nativeMetadata returns independent, synthetic authoritative negotiation metadata.
func nativeMetadata() backend.Negotiated {
	return backend.Negotiated{
		LocalIP: netip.MustParseAddr("10.20.0.10"), PeerIP: netip.MustParseAddr("10.20.0.1"), MTU: 1354,
		DNS: []netip.Addr{netip.MustParseAddr("10.20.0.2")}, Suffix: "corp.example.com",
		PushedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
	}
}

// nativeReady records a registered, child-free link and immutable negotiated metadata.
func nativeReady(t testing.TB) State {
	t.Helper()
	s := nativeNegotiating(t)
	s, _ = observe(t, s, backend.LinkReady{Link: backend.LinkIdentity{Interface: "utun7", Index: 7}}, Negotiating)
	s, _ = observe(t, s, nativeMetadata(), Negotiating)
	return s
}

// TestNativeMetadataAndLifecycle checks metadata ownership, network payloads, native
// worker-stop acknowledgement, and cleanup gating without any child PID or host I/O.
func TestNativeMetadataAndLifecycle(t *testing.T) {
	s := nativeNegotiating(t)
	metadata := nativeMetadata()
	before := s
	s, _ = observe(t, s, metadata, Negotiating)
	metadata.DNS[0] = netip.MustParseAddr("192.0.2.1")
	metadata.PushedPrefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	if before.DNS != nil || before.PushedPrefixes != nil || !reflect.DeepEqual(s.DNS, nativeMetadata().DNS) || !reflect.DeepEqual(s.PushedPrefixes, nativeMetadata().PushedPrefixes) {
		t.Fatal("observation slices alias input or previous state")
	}
	link := backend.LinkIdentity{Interface: "utun7", Index: 7}
	s, _ = observe(t, s, backend.LinkReady{Link: link}, Negotiating)
	s, effects := observe(t, s, backend.TunnelUp{}, Configuring)
	found := false
	for _, effect := range effects {
		if effect.Kind != ApplyNetwork {
			continue
		}
		found = true
		if effect.Link != link || effect.Interface != link.Interface || effect.PeerIP != s.PeerIP || effect.MTU != 1354 || !reflect.DeepEqual(effect.DNS, s.DNS) || !reflect.DeepEqual(effect.PushedPrefixes, s.PushedPrefixes) {
			t.Fatalf("incomplete network payload: %+v", effect)
		}
		effect.DNS[0] = netip.MustParseAddr("192.0.2.2")
		effect.PushedPrefixes[0] = netip.MustParsePrefix("198.51.100.0/24")
	}
	if !found || !reflect.DeepEqual(s.DNS, nativeMetadata().DNS) || !reflect.DeepEqual(s.PushedPrefixes, nativeMetadata().PushedPrefixes) {
		t.Fatal("network effect missing or aliases state")
	}
	s, _ = apply(t, s, NetworkApplied, Connected)
	unchanged, effects := observe(t, s, metadata, Connected)
	if !reflect.DeepEqual(unchanged, s) || effects != nil {
		t.Fatal("late metadata changed active networking")
	}
	s, effects = apply(t, s, Down, Stopping)
	if s.Exited || hasEffect(effects, RemoveNetwork) || !hasEffect(effects, StopProcess) {
		t.Fatal("cleanup did not wait for native workers")
	}
	timer := input(s, Deadline)
	timer.TimerID = s.TimerID
	s, effects = Next(s, timer)
	if hasEffect(effects, KillProcess) || hasEffect(effects, RemoveNetwork) || !hasEffect(effects, StopProcess) {
		t.Fatal("native stop attempted process signalling or early cleanup")
	}
	s, effects = observe(t, s, backend.Outcome{}, Stopping)
	if !s.Exited || !hasEffect(effects, RemoveNetwork) || hasEffect(effects, KillProcess) {
		t.Fatal("worker completion did not request cleanup")
	}
	s, _ = apply(t, s, CleanupDone, Disconnected)
	s, _ = apply(t, s, Up, Starting)
	if s.Link != (backend.LinkIdentity{}) || s.PeerIP.IsValid() || s.PushedPrefixes != nil || s.MTU != 0 || s.DNS != nil {
		t.Fatal("new attempt retained prior metadata")
	}
}

// TestNativeIncompleteMetadata rejects missing link registration, child identity,
// unsupported addresses, malformed pushed routes, and impossible payload sizes.
func TestNativeIncompleteMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*State)
	}{
		{"missing link", func(s *State) { s.Link = backend.LinkIdentity{} }},
		{"missing interface", func(s *State) { s.Interface = "" }},
		{"different link", func(s *State) { s.Link.Interface = "utun8" }},
		{"child pid", func(s *State) { s.Link.PID = 99 }},
		{"child start", func(s *State) { s.Link.StartTime = "123" }},
		{"missing peer", func(s *State) { s.PeerIP = netip.Addr{} }},
		{"ipv6 peer", func(s *State) { s.PeerIP = netip.MustParseAddr("2001:db8::1") }},
		{"unspecified local", func(s *State) { s.LocalIP = netip.MustParseAddr("0.0.0.0") }},
		{"ipv6 local", func(s *State) { s.LocalIP = netip.MustParseAddr("2001:db8::2") }},
		{"missing mtu", func(s *State) { s.MTU = 0 }},
		{"small mtu", func(s *State) { s.MTU = 127 }},
		{"large mtu", func(s *State) { s.MTU = 65536 }},
		{"invalid prefix", func(s *State) { s.PushedPrefixes = []netip.Prefix{{}} }},
		{"ipv6 prefix", func(s *State) { s.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")} }},
		{"unmasked prefix", func(s *State) { s.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.50.0.1/16")} }},
		{"ipv6 dns", func(s *State) { s.DNS = []netip.Addr{netip.MustParseAddr("2001:db8::3")} }},
		{"unspecified dns", func(s *State) { s.DNS = []netip.Addr{netip.MustParseAddr("0.0.0.0")} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := nativeReady(t)
			tc.change(&s)
			s, effects := observe(t, s, backend.TunnelUp{}, Stopping)
			if s.Failure != NetworkFailure || hasEffect(effects, ApplyNetwork) {
				t.Fatal("invalid metadata reached networking")
			}
		})
	}
	for _, link := range []backend.LinkIdentity{{Interface: "utun7", PID: 99}, {Interface: "utun7", StartTime: "123"}} {
		s, _ := observe(t, nativeNegotiating(t), backend.LinkReady{Link: link}, Stopping)
		if s.Failure != InterfaceFailure || s.Link.PID != 0 {
			t.Fatal("native accepted an external child identity")
		}
	}
	s := nativeNegotiating(t)
	for _, observed := range []backend.Event{backend.InterfaceUp{Name: "utun7"}, backend.GotAddresses{LocalIP: nativeMetadata().LocalIP}} {
		next, effects := observe(t, s, observed, Negotiating)
		if !reflect.DeepEqual(next, s) || effects != nil {
			t.Fatal("legacy partial metadata bypassed native registration")
		}
	}
}

// TestNativeSecondFactorRejected checks native never falls back or prompts for a code
// after credentials were sent; external callers retain their existing challenge path.
func TestNativeSecondFactorRejected(t *testing.T) {
	s, _ := apply(t, New("work", Options{Backend: "native", MFAMode: "none"}), Up, Starting)
	s, effects := observe(t, s, backend.CredentialRequested{Request: backend.Request{Kind: backend.Password}}, WaitingPassword)
	if !hasEffect(effects, EmitChallenge) {
		t.Fatal("password challenge omitted")
	}
	s, _ = apply(t, s, CredentialsAnswered, Authenticating)
	s, effects = observe(t, s, backend.CredentialRequested{Request: backend.Request{Kind: backend.Code}}, Stopping)
	if s.Target != Failed || s.Failure != AuthFailure || !strings.Contains(s.Detail, "select openfortivpn") || hasEffect(effects, EmitChallenge) || hasEffect(effects, StartProcess) {
		t.Fatal("native MFA silently continued or changed backend")
	}
	for _, phase := range []Phase{Negotiating, Configuring, Connected, Stopping, Backoff} {
		t.Run(string(phase), func(t *testing.T) {
			s := nativeReady(t)
			s.Phase, s.Target = phase, Backoff
			e := input(s, Output)
			e.Observation = backend.CredentialRequested{Request: backend.Request{Kind: backend.Code}}
			next, effects := Next(s, e)
			if next.Failure != AuthFailure || !strings.Contains(next.Detail, "select openfortivpn") || (next.Phase == Stopping && next.Target != Failed) || hasEffect(effects, EmitChallenge) || hasEffect(effects, StartProcess) {
				t.Fatal("late native MFA challenge was ignored or retried")
			}
		})
	}
}

// TestRouteRejectedPrecedence verifies typed route failures suppress retries in active
// and buffered phases without exposing raw diagnostics or overriding failed cleanup.
func TestRouteRejectedPrecedence(t *testing.T) {
	for _, phase := range []Phase{Starting, Authenticating, Negotiating, Configuring, Connected, Stopping, Backoff, WaitingTrust, Failed, Disconnected} {
		for _, reason := range []backend.RouteRejectReason{backend.RouteConflict, backend.RouteFailed, "unknown"} {
			t.Run(string(phase)+"/"+string(reason), func(t *testing.T) {
				s := New("work", Options{})
				s.Attempt, s.Phase, s.Wanted = 1, phase, true
				s.Target, s.Failure = Backoff, TransportFailure
				e := input(s, Output)
				e.Observation = backend.RouteRejected{Prefix: netip.MustParsePrefix("10.50.0.0/16"), Reason: reason, Message: "untrusted diagnostic"}
				next, effects := Next(s, e)
				if phase == Failed || phase == Disconnected {
					if !reflect.DeepEqual(next, s) || effects != nil {
						t.Fatal("idle route observation changed state")
					}
					return
				}
				want := NetworkFailure
				if reason == backend.RouteConflict {
					want = ConflictFailure
				}
				if next.Failure != want || (next.Phase == Stopping && next.Target != Failed) || strings.Contains(next.Detail, "untrusted") || hasEffect(effects, ApplyNetwork) || hasEffect(effects, StartProcess) {
					t.Fatalf("route failure not terminal: %+v, %+v", next, effects)
				}
				if phase == Stopping {
					s.CleanupRetries = 1
					next, effects = Next(s, e)
					if !reflect.DeepEqual(next, s) || effects != nil {
						t.Fatal("buffered route failure hid failed cleanup")
					}
				}
			})
		}
	}
}

// TestTypedOutcome preserves terminal causes, acknowledges child-free completion,
// rejects stale outcomes, and retains certificate trust until successful cleanup.
func TestTypedOutcome(t *testing.T) {
	s := nativeReady(t)
	s, effects := observe(t, s, backend.Outcome{Failure: AuthFailure}, Stopping)
	if !s.Exited || s.Failure != AuthFailure || s.Target != Failed || !hasEffect(effects, RemoveNetwork) || hasEffect(effects, StopProcess) {
		t.Fatal("typed outcome lost terminal cause or requested another stop")
	}
	e := input(s, Output)
	e.Observation = backend.Outcome{}
	duplicate, effects := Next(s, e)
	if !reflect.DeepEqual(duplicate, s) || effects != nil {
		t.Fatal("duplicate outcome changed cleanup")
	}
	e.Attempt--
	stale, effects := Next(s, e)
	if !reflect.DeepEqual(stale, s) || effects != nil {
		t.Fatal("stale outcome changed cleanup")
	}
	s, _ = apply(t, s, CleanupDone, Failed)
	s, _ = apply(t, s, Up, Starting)
	s, _ = observe(t, s, backend.Outcome{ExitCode: 0}, Stopping)
	if s.Target != Failed || s.Failure != ProcessFailure {
		t.Fatal("early zero exit was successful")
	}
	s = nativeNegotiating(t)
	s, _ = observe(t, s, backend.CertificateRejected{Digest: strings.Repeat("a", 64)}, Stopping)
	s, _ = observe(t, s, backend.Outcome{Failure: CertFailure}, Stopping)
	s, effects = apply(t, s, CleanupDone, WaitingTrust)
	if !hasEffect(effects, EmitCert) || s.Certificate.Digest == "" {
		t.Fatal("terminal certificate outcome suppressed trust")
	}
	s = connectedSession(t, "none")
	s, _ = observe(t, s, backend.Teardown{}, Stopping)
	s, _ = observe(t, s, backend.Outcome{Failure: AuthFailure}, Stopping)
	if s.Target != Failed || s.Failure != AuthFailure {
		t.Fatal("fatal terminal outcome retained reconnect")
	}
}
