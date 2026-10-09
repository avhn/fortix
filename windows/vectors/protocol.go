package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
)

// protocolFile is the protocol-frames.json document: limits plus named exact frames.
// Every frame string includes its terminating newline, exactly as the helper writes it.
type protocolFile struct {
	MaxLine         int          `json:"max_line"`
	Version         int          `json:"version"`
	Codes           []string     `json:"codes"`
	Requests        []namedFrame `json:"requests"`
	InvalidRequests []namedFrame `json:"invalid_requests"`
	Results         []namedFrame `json:"results"`
	Events          []namedFrame `json:"events"`
	InvalidResults  []namedFrame `json:"invalid_results"`
	Malformed       []namedFrame `json:"malformed"`
}

// namedFrame names one encoded record so test failures identify the shape that drifted.
type namedFrame struct {
	Name  string `json:"name"`
	Frame string `json:"frame"`
}

// clientFrame mirrors the Go client's shared result and event envelope for strict decoding.
// Malformed vectors must fail protocol.Decode against both this envelope and Request.
type clientFrame struct {
	Type           string          `json:"type"`
	Code           protocol.Code   `json:"code,omitempty"`
	Wanted         bool            `json:"wanted,omitempty"`
	Initiated      bool            `json:"initiated,omitempty"`
	CleanupPending bool            `json:"cleanup_pending,omitempty"`
	ID             string          `json:"id,omitempty"`
	OK             bool            `json:"ok,omitempty"`
	Error          *protocol.Error `json:"error,omitempty"`
	Data           json.RawMessage `json:"data,omitempty"`
	Profile        string          `json:"profile,omitempty"`
	Attempt        uint64          `json:"attempt,omitempty"`
	State          string          `json:"state,omitempty"`
	Detail         string          `json:"detail,omitempty"`
	ChallengeID    string          `json:"challenge_id,omitempty"`
	Kind           string          `json:"kind,omitempty"`
	Prompt         string          `json:"prompt,omitempty"`
	Digest         string          `json:"digest,omitempty"`
	Subject        string          `json:"subject,omitempty"`
	Issuer         string          `json:"issuer,omitempty"`
	Line           string          `json:"line,omitempty"`
}

// statusSnapshot mirrors the helper's status entry, including its RFC 3339 timestamp.
type statusSnapshot struct {
	Wanted         bool      `json:"wanted"`
	Initiated      bool      `json:"initiated"`
	CleanupPending bool      `json:"cleanup_pending"`
	Profile        string    `json:"profile"`
	State          string    `json:"state"`
	Detail         string    `json:"detail"`
	Attempt        uint64    `json:"attempt"`
	Interface      string    `json:"interface"`
	LocalIP        string    `json:"local_ip"`
	Since          time.Time `json:"since"`
}

// encodeFrame writes message with the production writer and returns the exact record text.
func encodeFrame(message any) (string, error) {
	var buffer bytes.Buffer
	if err := protocol.Write(&buffer, message); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

// protocolVectors builds every request, result, and event shape, checking each with the
// production validator and strict decoder so the vectors cannot record unaccepted frames.
func protocolVectors() (any, error) {
	file := protocolFile{MaxLine: protocol.MaxLine, Version: protocol.Version}
	for _, code := range []protocol.Code{protocol.Unauthorized, protocol.NotFound, protocol.Invalid, protocol.Conflict, protocol.Busy, protocol.Internal, protocol.InterfaceMismatch} {
		file.Codes = append(file.Codes, string(code))
	}
	stored := profile.Profile{SchemaVersion: 1, ID: "work", Name: "Work <&> 東京", Gateway: profile.Gateway{Host: "vpn.example.com"}, Username: "jane.doe",
		Routes: profile.Routes{Mode: "gateway", Exclude: []string{"198.51.100.0/24"}}, DNS: profile.DNS{Mode: "split", Domains: []string{"corp.example.com"}}}
	stored.ApplyDefaults()
	if err := stored.Validate(); err != nil {
		return nil, err
	}
	profileJSON, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	digest := strings.Repeat("ab", 32)
	requests := []struct {
		name    string
		request protocol.Request
	}{
		{"hello", protocol.Request{ID: "1", Op: "hello", Version: "0.3.0"}},
		{"subscribe", protocol.Request{ID: "2", Op: "subscribe"}},
		{"subscribe-logs", protocol.Request{ID: "3", Op: "subscribe", Logs: true}},
		{"profile-list", protocol.Request{ID: "4", Op: "profile.list"}},
		{"profile-get", protocol.Request{ID: "5", Op: "profile.get", Profile: "work"}},
		{"profile-put", protocol.Request{ID: "6", Op: "profile.put", ProfileJSON: profileJSON}},
		{"profile-delete", protocol.Request{ID: "7", Op: "profile.delete", Profile: "work"}},
		{"up", protocol.Request{ID: "8", Op: "up", Profile: "work"}},
		{"down", protocol.Request{ID: "9", Op: "down", Profile: "work"}},
		{"down-all", protocol.Request{ID: "10", Op: "down", All: true}},
		{"status", protocol.Request{ID: "11", Op: "status"}},
		{"answer", protocol.Request{ID: "12", Op: "answer", ChallengeID: "c1", Secret: "synthetic <&> 密碼 100%"}},
		{"answer-limit", protocol.Request{ID: "13", Op: "answer", ChallengeID: "c1", Secret: strings.Repeat("x", 997)}},
		{"answer-escaped-limit", protocol.Request{ID: "14", Op: "answer", ChallengeID: "c1", Secret: strings.Repeat("%", 332) + "x"}},
		{"cancel", protocol.Request{ID: "15", Op: "cancel", ChallengeID: "c1"}},
		{"trust", protocol.Request{ID: "16", Op: "trust", Profile: "work", Digest: digest}},
		{"logs", protocol.Request{ID: "17", Op: "logs", Profile: "work"}},
		{"logs-lines", protocol.Request{ID: "18", Op: "logs", Profile: "work", Lines: 500}},
		{"id-limit", protocol.Request{ID: strings.Repeat("9", 128), Op: "status"}},
	}
	for _, r := range requests {
		if err := r.request.Validate(); err != nil {
			return nil, fmt.Errorf("request %s: %w", r.name, err)
		}
		frame, err := encodeFrame(r.request)
		if err != nil {
			return nil, err
		}
		var decoded protocol.Request
		if err := protocol.Decode([]byte(frame), &decoded); err != nil {
			return nil, fmt.Errorf("request %s: %w", r.name, err)
		}
		file.Requests = append(file.Requests, namedFrame{r.name, frame})
	}
	invalid := []struct {
		name    string
		request protocol.Request
	}{
		{"empty-id", protocol.Request{Op: "status"}},
		{"long-id", protocol.Request{ID: strings.Repeat("9", 129), Op: "status"}},
		{"unknown-op", protocol.Request{ID: "1", Op: "restart"}},
		{"hello-with-profile", protocol.Request{ID: "1", Op: "hello", Profile: "work"}},
		{"status-with-all", protocol.Request{ID: "1", Op: "status", All: true}},
		{"up-without-profile", protocol.Request{ID: "1", Op: "up"}},
		{"down-without-target", protocol.Request{ID: "1", Op: "down"}},
		{"down-all-and-profile", protocol.Request{ID: "1", Op: "down", Profile: "work", All: true}},
		{"put-without-json", protocol.Request{ID: "1", Op: "profile.put"}},
		{"answer-without-challenge", protocol.Request{ID: "1", Op: "answer", Secret: "x"}},
		{"cancel-with-secret", protocol.Request{ID: "1", Op: "cancel", ChallengeID: "c1", Secret: "x"}},
		{"secret-too-long", protocol.Request{ID: "1", Op: "answer", ChallengeID: "c1", Secret: strings.Repeat("x", 998)}},
		{"secret-escaped-too-long", protocol.Request{ID: "1", Op: "answer", ChallengeID: "c1", Secret: strings.Repeat("\n", 333) + "x"}},
		{"trust-short-digest", protocol.Request{ID: "1", Op: "trust", Profile: "work", Digest: digest[:63]}},
		{"logs-too-many", protocol.Request{ID: "1", Op: "logs", Profile: "work", Lines: 501}},
		{"logs-negative", protocol.Request{ID: "1", Op: "logs", Profile: "work", Lines: -1}},
		{"subscribe-with-lines", protocol.Request{ID: "1", Op: "subscribe", Lines: 5}},
	}
	for _, r := range invalid {
		if r.request.Validate() == nil {
			return nil, fmt.Errorf("invalid request %s was accepted", r.name)
		}
		frame, err := encodeFrame(r.request)
		if err != nil {
			return nil, err
		}
		file.InvalidRequests = append(file.InvalidRequests, namedFrame{r.name, frame})
	}
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	results := []struct {
		name   string
		result protocol.Result
	}{
		{"hello", protocol.Result{Type: "result", ID: "1", OK: true, Data: struct {
			HelperVersion string `json:"helper_version"`
			Protocol      int    `json:"protocol"`
		}{"0.3.0", protocol.Version}}},
		{"empty", protocol.Result{Type: "result", ID: "2", OK: true}},
		{"profile-list", protocol.Result{Type: "result", ID: "4", OK: true, Data: []struct {
			Profile string `json:"profile"`
			State   string `json:"state"`
		}{{"home", "disconnected"}, {"work", "connected"}}}},
		{"profile-get", protocol.Result{Type: "result", ID: "5", OK: true, Data: stored}},
		{"up", protocol.Result{Type: "result", ID: "8", OK: true, Data: struct {
			Attempt uint64 `json:"attempt"`
		}{18446744073709551615}}},
		{"status", protocol.Result{Type: "result", ID: "11", OK: true, Data: []statusSnapshot{
			{Wanted: true, Initiated: true, Profile: "work", State: "connected", Detail: "connected", Attempt: 3, Interface: "Fortix", LocalIP: "198.51.100.10", Since: since},
			{Profile: "home", State: "disconnected"},
		}}},
		{"status-empty", protocol.Result{Type: "result", ID: "11", OK: true, Data: []statusSnapshot{}}},
		{"logs", protocol.Result{Type: "result", ID: "17", OK: true, Data: []string{"INFO: connected", "sanitized <&> 東京"}}},
		{"unauthorized-before-request", protocol.Result{Type: "result", Error: &protocol.Error{Code: protocol.Unauthorized, Message: "peer is not authorized"}}},
	}
	for _, code := range file.Codes {
		results = append(results, struct {
			name   string
			result protocol.Result
		}{"error-" + strings.ToLower(code), protocol.Result{Type: "result", ID: "20", Error: &protocol.Error{Code: protocol.Code(code), Message: "Synthetic operation failure"}}})
	}
	for _, r := range results {
		frame, err := encodeFrame(r.result)
		if err != nil {
			return nil, err
		}
		var decoded clientFrame
		if err := protocol.Decode([]byte(frame), &decoded); err != nil {
			return nil, fmt.Errorf("result %s: %w", r.name, err)
		}
		file.Results = append(file.Results, namedFrame{r.name, frame})
	}
	events := []struct {
		name  string
		event protocol.Event
	}{
		{"state", protocol.Event{Type: "state", Profile: "work", Attempt: 1, State: "connected", Wanted: true, Initiated: true}},
		{"state-empty-detail", protocol.Event{Type: "state", Profile: "work", Attempt: 2, State: "disconnected"}},
		{"state-code", protocol.Event{Type: "state", Profile: "work", Attempt: 2, State: "failed", Detail: "network cleanup failed", Code: protocol.InterfaceMismatch, Wanted: true, CleanupPending: true}},
		{"challenge", protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "c1", Kind: "password", Prompt: "Password for jane.doe"}},
		{"challenge-empty-prompt", protocol.Event{Type: "challenge", Profile: "work", Attempt: 1, ChallengeID: "c2", Kind: "code"}},
		{"cert", protocol.Event{Type: "cert", Profile: "work", Attempt: 1, Digest: digest, Subject: "CN=vpn.example.com", Issuer: "CN=Example CA"}},
		{"log", protocol.Event{Type: "log", Profile: "work", Attempt: 1, Line: "sanitized <&> 東京"}},
		{"max-attempt", protocol.Event{Type: "log", Profile: "work", Attempt: 18446744073709551615, Line: ""}},
	}
	for _, e := range events {
		frame, err := encodeFrame(e.event)
		if err != nil {
			return nil, err
		}
		var decoded clientFrame
		if err := protocol.Decode([]byte(frame), &decoded); err != nil {
			return nil, fmt.Errorf("event %s: %w", e.name, err)
		}
		file.Events = append(file.Events, namedFrame{e.name, frame})
	}
	// Envelopes the Go client rejects after strict decoding, by result semantics or type.
	file.InvalidResults = []namedFrame{
		{"ok-with-error", `{"type":"result","id":"1","ok":true,"error":{"code":"INVALID","message":"x"}}` + "\n"},
		{"failure-without-error", `{"type":"result","id":"1","ok":false}` + "\n"},
		{"missing-id", `{"type":"result","ok":true}` + "\n"},
		{"unknown-type", `{"type":"notice","profile":"work","attempt":1}` + "\n"},
	}
	for _, f := range file.InvalidResults {
		var decoded clientFrame
		if err := protocol.Decode([]byte(f.Frame), &decoded); err != nil {
			return nil, fmt.Errorf("invalid result %s must decode structurally: %w", f.Name, err)
		}
	}
	deep := `{"type":"result","id":"1","ok":true,"data":` + strings.Repeat("[", 33) + strings.Repeat("]", 33) + "}\n"
	file.Malformed = []namedFrame{
		{"duplicate-key", `{"type":"result","id":"1","id":"2","ok":true}` + "\n"},
		{"escaped-duplicate-key", `{"type":"result","id":"1","id":"2","ok":true}` + "\n"},
		{"null-value", `{"type":"result","id":"1","ok":true,"data":null}` + "\n"},
		{"nested-null", `{"type":"result","id":"1","ok":true,"data":[1,null]}` + "\n"},
		{"unknown-field", `{"type":"result","id":"1","ok":true,"extra":1}` + "\n"},
		{"case-alias", `{"type":"result","ID":"1","ok":true}` + "\n"},
		{"trailing-data", `{"type":"result","id":"1","ok":true} {}` + "\n"},
		{"not-object", `["result"]` + "\n"},
		{"wrong-type", `{"type":"result","id":1,"ok":true}` + "\n"},
		{"fractional-attempt", `{"type":"log","profile":"work","attempt":1.5,"line":""}` + "\n"},
		{"negative-attempt", `{"type":"log","profile":"work","attempt":-1,"line":""}` + "\n"},
		{"too-deep", deep},
		{"truncated", `{"type":"result","id":"1"` + "\n"},
	}
	for _, f := range file.Malformed {
		var decodedFrame clientFrame
		var decodedRequest protocol.Request
		if protocol.Decode([]byte(f.Frame), &decodedFrame) == nil || protocol.Decode([]byte(f.Frame), &decodedRequest) == nil {
			return nil, errors.New("malformed frame accepted: " + f.Name)
		}
	}
	return file, nil
}
