package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestStrictRecords checks malformed envelopes, exact key spelling, and framing
// boundaries without permitting decoder errors to echo potentially secret input.
func TestStrictRecords(t *testing.T) {
	tests := []struct {
		name, input string
		valid       bool
	}{
		{"hello", `{"id":"1","op":"hello","version":"dev"}` + "\n", true},
		{"duplicate", `{"id":"1","id":"2","op":"status"}` + "\n", false},
		{"alias", `{"ID":"1","op":"status"}` + "\n", false},
		{"unknown", `{"id":"1","op":"status","password":"sensitive"}` + "\n", false},
		{"null", `{"id":"1","op":null}` + "\n", false},
		{"array", `[]` + "\n", false},
		{"trailing", `{"id":"1","op":"status"}{}` + "\n", false},
		{"partial", `{"id":"1","op":"status"}`, false},
		{"utf8", "{\"id\":\"\xff\",\"op\":\"status\"}\n", false},
		{"duplicate nested", `{"id":"1","op":"profile.put","profile_json":{"id":"a","id":"b"}}` + "\n", false},
		{"deep", `{"id":"1","op":"profile.put","profile_json":` + strings.Repeat("[", 40) + `1` + strings.Repeat("]", 40) + "}\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r Request
			err := NewReader(strings.NewReader(tt.input)).Read(&r)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v err=%v", tt.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "sensitive") {
				t.Fatal("input leaked in error")
			}
		})
	}
	for _, n := range []int{MaxLine - 1, MaxLine, MaxLine + 1} {
		line := []byte(`{"id":"1","op":"status"}`)
		line = append(line, bytes.Repeat([]byte(" "), n-len(line)-1)...)
		line = append(line, '\n')
		var r Request
		err := NewReader(bytes.NewReader(line)).Read(&r)
		if (err == nil) != (n <= MaxLine) {
			t.Fatalf("size %d: %v", n, err)
		}
	}
	reader := NewReader(strings.NewReader("{\"id\":\"1\",\"op\":\"status\"}\n{\"id\":\"2\",\"op\":\"status\"}\n"))
	for _, id := range []string{"1", "2"} {
		var r Request
		if err := reader.Read(&r); err != nil || r.ID != id {
			t.Fatalf("coalesced record: %+v %v", r, err)
		}
	}
	var r Request
	if err := reader.Read(&r); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF: %v", err)
	}
}

// TestRecordStartCallback distinguishes idle EOF from records already buffered by
// an earlier read and propagates deadline setup errors without decoding any payload.
func TestRecordStartCallback(t *testing.T) {
	reader := NewReader(strings.NewReader("{\"id\":\"1\",\"op\":\"status\"}\n{\"id\":\"2\",\"op\":\"status\"}\n"))
	calls := 0
	started := func() error { calls++; return nil }
	for _, id := range []string{"1", "2"} {
		var r Request
		if err := reader.ReadStarted(&r, started); err != nil || r.ID != id {
			t.Fatalf("buffered record: %+v %v", r, err)
		}
	}
	var r Request
	if err := reader.ReadStarted(&r, started); err != io.EOF || calls != 2 {
		t.Fatalf("idle start callback: calls=%d err=%v", calls, err)
	}
	setupErr := errors.New("deadline setup failed")
	reader = NewReader(strings.NewReader("{}\n"))
	if err := reader.ReadStarted(&r, func() error { return setupErr }); !errors.Is(err, setupErr) {
		t.Fatalf("callback error lost: %v", err)
	}
}

// TestRequestArguments covers every operation and representative invalid mixtures.
func TestRequestArguments(t *testing.T) {
	valid := []Request{{Op: "hello"}, {Op: "subscribe"}, {Op: "profile.list"}, {Op: "status"}, {Op: "profile.get", Profile: "work"},
		{Op: "profile.put", ProfileJSON: []byte(`{}`)}, {Op: "profile.delete", Profile: "work"}, {Op: "up", Profile: "work"},
		{Op: "down", All: true}, {Op: "down", Profile: "work"}, {Op: "answer", ChallengeID: "c", Secret: ""}, {Op: "cancel", ChallengeID: "c"},
		{Op: "trust", Profile: "work", Digest: strings.Repeat("a", 64)}, {Op: "logs", Profile: "work", Lines: 500},
		{Op: "answer", ChallengeID: "c", Secret: strings.Repeat("%", 332) + "a"}}
	for _, r := range valid {
		r.ID = "1"
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", r.Op, err)
		}
	}
	invalid := []Request{{Op: "unknown"}, {Op: "up"}, {Op: "down", Profile: "work", All: true}, {Op: "status", Secret: "secret"},
		{Op: "profile.put"}, {Op: "answer"}, {Op: "trust", Profile: "work", Digest: "a"}, {Op: "logs", Profile: "work", Lines: 501},
		{Op: "answer", ChallengeID: "c", Secret: strings.Repeat("s", 998)},
		{Op: "answer", ChallengeID: "c", Secret: strings.Repeat("%", 333)},
		{Op: "answer", ChallengeID: "c", Secret: strings.Repeat("\r\n\x00", 111)}}
	for _, r := range invalid {
		r.ID = "1"
		if r.Validate() == nil {
			t.Errorf("accepted %s", r.Op)
		}
	}
}

// shortWriter models a writer that accepts fewer bytes without reporting an error.
type shortWriter struct{}

// Write returns a deliberate short write so codec error propagation can be checked.
func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

// TestWrite verifies short writes, unencodable values, and bounded output records.
func TestWrite(t *testing.T) {
	if err := Write(shortWriter{}, Request{ID: "1", Op: "status"}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if Write(io.Discard, make(chan int)) == nil {
		t.Fatal("accepted unsupported value")
	}
	if Write(io.Discard, Request{ID: strings.Repeat("x", MaxLine)}) == nil {
		t.Fatal("accepted oversized output")
	}
}

// FuzzDecode exercises strict object/token parsing and bounded line framing.
// Valid requests must survive a canonical encoding and decoding round trip.
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{`{"id":"1","op":"status"}`, `{"id":"1","op":"answer","challenge_id":"c","secret":"%\n"}`, `null`, `{"op":"up","op":"down"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Request
		err := Decode(data, &r)
		var framed Request
		_ = NewReader(bytes.NewReader(data)).Read(&framed)
		if err == nil {
			var b bytes.Buffer
			if err := Write(&b, r); err == nil {
				var next Request
				if err := NewReader(&b).Read(&next); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

// TestEventShapes keeps required empty strings on the wire without adding fields
// from another event kind. Unknown event kinds cannot be serialized accidentally.
func TestEventShapes(t *testing.T) {
	for _, tt := range []struct {
		kind string
		keys []string
	}{
		{"state", []string{"type", "profile", "attempt", "state", "detail"}},
		{"challenge", []string{"type", "profile", "attempt", "challenge_id", "kind", "prompt"}},
		{"cert", []string{"type", "profile", "attempt", "digest", "subject", "issuer"}},
		{"log", []string{"type", "profile", "attempt", "line"}},
	} {
		data, err := json.Marshal(Event{Type: tt.kind, Profile: "work", Attempt: 1})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != len(tt.keys) {
			t.Fatalf("%s has extra fields", tt.kind)
		}
		for _, key := range tt.keys {
			if _, ok := fields[key]; !ok {
				t.Errorf("%s lacks %s", tt.kind, key)
			}
		}
	}
	if _, err := json.Marshal(Event{Type: "unknown"}); err == nil {
		t.Fatal("encoded unknown event")
	}
}
