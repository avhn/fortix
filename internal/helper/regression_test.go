package helper

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// TestRuntimeAncestorModes distinguishes system runtime directories from executable
// paths without creating or modifying any root-owned files on the host.
func TestRuntimeAncestorModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		stat unix.Stat_t
		want bool
	}{
		{"root group writable", unix.Stat_t{Mode: unix.S_IFDIR | 0775}, true},
		{"read only", unix.Stat_t{Gid: 12345, Mode: unix.S_IFDIR | 0755}, true},
		{"unknown group writable", unix.Stat_t{Gid: 12345, Mode: unix.S_IFDIR | 0775}, false},
		{"user owned", unix.Stat_t{Uid: 501, Mode: unix.S_IFDIR | 0755}, false},
		{"world writable", unix.Stat_t{Mode: unix.S_IFDIR | 0777}, false},
		{"sticky", unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0755}, false},
		{"regular file", unix.Stat_t{Mode: unix.S_IFREG | 0664}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trustedMode(tc.stat, true); got != tc.want {
				t.Fatalf("runtime policy: %v", got)
			}
			if tc.stat.Mode&0020 != 0 && trustedMode(tc.stat, false) {
				t.Fatal("executable policy allowed group writes")
			}
		})
	}
}

// TestControlReadBudgets verifies subscribers survive idle periods while idle
// non-subscribers and partial records close silently rather than emitting INVALID.
func TestControlReadBudgets(t *testing.T) {
	h := startHarness(t, nil, func(o *Options) {
		o.IdleTimeout = 40 * time.Millisecond
		o.RecordTimeout = 40 * time.Millisecond
	})
	c := h.client(t)
	c.success(t, protocol.Request{Op: "subscribe"})
	timer := time.AfterFunc(150*time.Millisecond, func() {
		h.server.emit(protocol.Event{Type: "state", Profile: "work", State: "disconnected"}, nil)
	})
	defer timer.Stop()
	c.event(t, "state", "work", "disconnected")
	c.success(t, protocol.Request{Op: "hello"})
	for _, partial := range []bool{false, true} {
		peer := h.client(t)
		if partial {
			peer.success(t, protocol.Request{Op: "subscribe"})
			if _, err := io.WriteString(peer.socket, "{"); err != nil {
				t.Fatal(err)
			}
		}
		if err := peer.socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var message wireMessage
		if err := peer.decoder.Decode(&message); err != io.EOF {
			t.Fatalf("idle/partial close: %v, message %+v", err, message)
		}
	}
}

// TestProfilePutPreservesConfiguration proves incoming pins cannot create, change,
// or remove helper-owned certificate trust. Non-trust profile fields still round trip.
func TestProfilePutPreservesConfiguration(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	p, err := profile.Decode(strings.NewReader(string(profileJSON("work", ""))))
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("a", 64)
	p.TrustedCert = pin
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: data})
	stored, err := h.server.store.Get("work")
	if err != nil || stored.TrustedCert != "" {
		t.Fatalf("put installed client pin: %+v, %v", stored, err)
	}
	if result := c.request(t, protocol.Request{Op: "trust", Profile: "work", Digest: pin}); result.OK || result.Error.Code != protocol.Conflict {
		t.Fatal("trust accepted a digest without a captured rejection")
	}
	// Seed the store through the helper-owned persistence path, not the client op.
	if _, err := h.server.store.Put(data); err != nil {
		t.Fatal(err)
	}
	for _, incoming := range []string{"", pin, strings.Repeat("b", 64)} {
		p.TrustedCert = incoming
		data, err = json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: data})
		stored, err = h.server.store.Get("work")
		if err != nil || stored.TrustedCert != pin {
			t.Fatalf("put changed helper-owned pin: %+v, %v", stored, err)
		}
	}
	listed := c.success(t, protocol.Request{Op: "profile.list"})
	var items []profileState
	if err := json.Unmarshal(listed.Data, &items); err != nil || len(items) != 1 || items[0].Profile != "work" {
		t.Fatalf("list shape: %s, %v", listed.Data, err)
	}
}

// recordingCleanup captures teardown identities without touching host networking.
type recordingCleanup struct {
	NoNetwork
	journals chan Journal
}

// Teardown records the immutable ownership metadata supplied by the actor.
func (n recordingCleanup) Teardown(_ context.Context, j Journal) error {
	n.journals <- j
	return nil
}

// TestFailedStartResetsGeneration verifies early spawn failures cannot signal or
// clean up the previous attempt's process and network ownership metadata.
func TestFailedStartResetsGeneration(t *testing.T) {
	n := recordingCleanup{journals: make(chan Journal, 1)}
	s := &Server{opts: Options{Paths: paths.Paths{Pinentry: "/missing-fortix-pinentry"}, Network: n}}
	a := newSupervisor(s, &profile.Profile{ID: "work"})
	a.state.Attempt = 2
	a.command = exec.Command("/bin/false")
	a.journal = Journal{Profile: "work", Attempt: 1, PID: 123, StartTime: "old"}
	if a.start() == nil {
		t.Fatal("missing executable started")
	}
	if a.command != nil || !reflect.DeepEqual(a.journal, Journal{Profile: "work", Attempt: 2}) {
		t.Fatal("stale attempt identity retained")
	}
	a.network(session.Effect{Profile: "work", Attempt: 2}, true)
	select {
	case j := <-n.journals:
		if j.Attempt != 2 || j.PID != 0 {
			t.Fatalf("stale teardown: %+v", j)
		}
	case <-time.After(time.Second):
		t.Fatal("teardown did not complete")
	}
	a.children.Wait()
}

// TestChallengeQueueFallback proves a saturated origin cannot suppress a prompt
// that an available subscriber can answer instead.
func TestChallengeQueueFallback(t *testing.T) {
	h := startHarness(t, nil)
	peer := h.client(t)
	origin := &connection{socket: peer.socket.(*net.UnixConn), open: true, events: make(chan protocol.Event, 1)}
	origin.events <- protocol.Event{Type: "state"}
	observer := &connection{open: true, subscribed: true, events: make(chan protocol.Event, 1)}
	s := &Server{clients: map[*connection]bool{origin: true, observer: true}}
	s.emit(protocol.Event{Type: "challenge", ChallengeID: "pending"}, origin)
	if origin.open {
		t.Fatal("saturated origin still open")
	}
	select {
	case e := <-observer.events:
		if e.ChallengeID != "pending" {
			t.Fatal("wrong fallback event")
		}
	default:
		t.Fatal("challenge lost")
	}
}

// TestDiagnosticRedaction preserves useful failures while excluding credential
// labels, raw/escaped known answers, Assuan records, and terminal control bytes.
func TestDiagnosticRedaction(t *testing.T) {
	log := &rotatingLog{}
	log.protect([]byte("fixture%secret"))
	for _, tc := range []struct{ input, want string }{
		{"pppd: failed to negotiate an address", "pppd: failed to negotiate an address"},
		{"TLS handshake failed: peer closed connection", "TLS handshake failed: peer closed connection"},
		{"unlabelled fixture%secret", "unlabelled [redacted]"},
		{"unlabelled fixture%25secret", "unlabelled [redacted]"},
		{"password=hidden value", "password=[redacted]"},
		{"passwd: hidden", "passwd=[redacted]"},
		{"OTP hidden", "OTP [redacted]"},
		{"token=hidden", "token=[redacted]"},
		{"cookie: hidden", "cookie=[redacted]"},
		{"SVPNCOOKIE=hidden", "SVPNCOOKIE=[redacted]"},
		{"DEBUG: D hidden", "Assuan data [redacted]"},
		{"\x1b[31mpassword\x1b[0m=hidden", "password=[redacted]"},
	} {
		if got := log.redact(tc.input); got != tc.want {
			t.Errorf("redaction: got %q want %q", got, tc.want)
		}
	}
	if len(log.redact(strings.Repeat("x", protocol.MaxLine))) > 4120 {
		t.Fatal("diagnostic not bounded")
	}
}

// FuzzDiagnosticRedaction exercises arbitrary child text, checking bounded output,
// control stripping and masking of a known attempt credential without panics.
func FuzzDiagnosticRedaction(f *testing.F) {
	for _, seed := range []string{"password=secret", "D secret", "TLS failure", "fixture-secret"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		log := &rotatingLog{}
		log.protect([]byte("fixture-secret"))
		got := log.redact(text)
		if len(got) > 4120 || strings.Contains(got, "fixture-secret") || strings.ContainsFunc(got, unicode.IsControl) {
			t.Fatal("unsafe diagnostic")
		}
	})
}

// TestHumanDeadlineIsTimeout ensures the supervisor, not the relay, classifies an
// unanswered credential request when a non-default human budget expires.
func TestHumanDeadlineIsTimeout(t *testing.T) {
	h := startHarness(t, nil, func(o *Options) { o.Deadlines.Human = 60 * time.Millisecond })
	c := h.client(t)
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "")})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	c.event(t, "challenge", "work", "")
	failed := c.event(t, "state", "work", "failed")
	if !strings.Contains(failed.Detail, "timeout") && !strings.Contains(failed.Detail, "deadline") {
		t.Fatalf("unexpected failure: %s", failed.Detail)
	}
}
