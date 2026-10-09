//go:build darwin || linux

package helper

import (
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/protocol"
)

// TestEscapedCredentialRelay verifies an oversized escaped answer is rejected without
// consuming the challenge. A subsequent answer survives Assuan escaping and decoding
// in the fake child, and multi-record echoes never disclose credential fragments.
func TestEscapedCredentialRelay(t *testing.T) {
	h := startHarness(t, nil)
	c := h.client(t)
	c.success(t, protocol.Request{Op: "subscribe"})
	c.success(t, protocol.Request{Op: "profile.put", ProfileJSON: profileJSON("work", "roundtrip")})
	c.success(t, protocol.Request{Op: "up", Profile: "work"})
	challenge := c.event(t, "challenge", "work", "")
	result := c.request(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: strings.Repeat("%", 333)})
	if result.OK || result.Error.Code != protocol.Invalid {
		t.Fatal("accepted answer that cannot fit an Assuan record")
	}
	c.success(t, protocol.Request{Op: "answer", ChallengeID: challenge.ChallengeID, Secret: "fixture%password+\r\n\x00"})
	c.event(t, "state", "work", "connected")
	c.success(t, protocol.Request{Op: "down", Profile: "work"})
	c.event(t, "state", "work", "disconnected")
	logs := c.success(t, protocol.Request{Op: "logs", Profile: "work", Lines: 500})
	if strings.Contains(string(logs.Data), "fixture%password") || strings.Contains(string(logs.Data), "fixture%25password") {
		t.Fatal("credential fragment leaked into diagnostics")
	}
	if !strings.Contains(string(logs.Data), "child diagnostic [redacted]") {
		t.Fatal("multi-record diagnostics were not masked")
	}
}

// TestMultiRecordCredentialRedaction checks each record-separating byte independently,
// since scanner framing can remove those bytes before a known-secret match is possible.
func TestMultiRecordCredentialRedaction(t *testing.T) {
	for _, separator := range []string{"\r", "\n", "\x00"} {
		t.Run(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(separator, "\r", "cr"), "\n", "lf"), "\x00", "nul"), func(t *testing.T) {
			log := &rotatingLog{}
			log.protect([]byte("fixture" + separator + "password"))
			for _, fragment := range []string{"fixture", "password", "unlabelled fixture", "unlabelled password"} {
				if got := log.redact(fragment); got != "child diagnostic [redacted]" {
					t.Fatalf("record fragment was retained: %q", got)
				}
			}
		})
	}
}
