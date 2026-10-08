package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConflictStateCode preserves optional stable conflict codes on state events while
// ordinary state payloads remain unchanged and unrelated event kinds omit the code.
func TestConflictStateCode(t *testing.T) {
	for _, kind := range []string{"state", "challenge", "cert", "log"} {
		e := Event{Type: kind, Profile: "work", Attempt: 1, State: "failed", Detail: "another full tunnel is active", Code: Conflict}
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"code"`) != (kind == "state") {
			t.Fatalf("code attached to wrong event: %s", data)
		}
		var decoded Event
		if err := Decode(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if kind == "state" && decoded.Code != Conflict {
			t.Fatal("conflict code lost in strict decoding")
		}
	}
	data, err := json.Marshal(Event{Type: "state", Profile: "work", Attempt: 1, State: "connected"})
	if err != nil || strings.Contains(string(data), `"code"`) {
		t.Fatalf("ordinary state payload changed: %s %v", data, err)
	}
}
