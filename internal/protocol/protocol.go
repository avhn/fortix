// Package protocol defines bounded newline-delimited messages for the local helper.
// Decoders reject ambiguous objects and never include input data in errors.
package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Limits bound each encoded record including its newline and identify this protocol.
const (
	MaxLine = 64 * 1024
	Version = 1
)

// Code identifies a stable failure category, independent of diagnostic messages.
type Code string

// Error codes are shared by clients and the helper; none contain caller input.
const (
	Unauthorized Code = "UNAUTHORIZED"
	NotFound     Code = "NOT_FOUND"
	Invalid      Code = "INVALID"
	Conflict     Code = "CONFLICT"
	Busy         Code = "BUSY"
	Internal     Code = "INTERNAL"
)

// Error is a public operation failure with a stable code and secret-free message.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

// Request carries an operation's inline arguments. ProfileJSON is an object, not
// a JSON-encoded string. Validate rejects arguments belonging to other operations.
// Secret is an immutable Go string for JSON/client compatibility: releasing it does
// not erase its backing bytes. Mutable framing and supervisor buffers are cleared.
type Request struct {
	ID          string          `json:"id"`
	Op          string          `json:"op"`
	Version     string          `json:"version,omitempty"`
	Profile     string          `json:"profile,omitempty"`
	ProfileJSON json.RawMessage `json:"profile_json,omitempty"`
	All         bool            `json:"all,omitempty"`
	ChallengeID string          `json:"challenge_id,omitempty"`
	Secret      string          `json:"secret,omitempty"`
	Digest      string          `json:"digest,omitempty"`
	Lines       int             `json:"lines,omitempty"`
}

// Result is the single reply to a request. Data is operation-specific and omitted
// on failure; Error is omitted on success. ID echoes only a validated request ID.
type Result struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error *Error `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

// Event carries one state, challenge, certificate, or redacted log notification.
// Attempt distinguishes successive children for the same profile; secrets are absent.
type Event struct {
	Type        string `json:"type"`
	Profile     string `json:"profile"`
	Attempt     uint64 `json:"attempt"`
	State       string `json:"state,omitempty"`
	Detail      string `json:"detail,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Prompt      string `json:"prompt,omitempty"`
	Digest      string `json:"digest,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Line        string `json:"line,omitempty"`
	Code        Code   `json:"code,omitempty"`
}

// MarshalJSON emits only the fields defined for this event kind, including empty
// required strings. Unknown event kinds fail without encoding any payload data.
func (e Event) MarshalJSON() ([]byte, error) {
	fields := map[string]any{"type": e.Type, "profile": e.Profile, "attempt": e.Attempt}
	switch e.Type {
	case "state":
		fields["state"] = e.State
		fields["detail"] = e.Detail
		if e.Code != "" {
			fields["code"] = e.Code
		}
	case "challenge":
		fields["challenge_id"] = e.ChallengeID
		fields["kind"] = e.Kind
		fields["prompt"] = e.Prompt
	case "cert":
		fields["digest"] = e.Digest
		fields["subject"] = e.Subject
		fields["issuer"] = e.Issuer
	case "log":
		fields["line"] = e.Line
	default:
		return nil, errors.New("protocol: unknown event type")
	}
	return json.Marshal(fields)
}

// Reader retains buffered bytes between records and bounds allocations per record.
// A malformed or oversized record is terminal; callers must close that connection.
type Reader struct{ input *bufio.Reader }

// NewReader wraps r without reading it; callers must supply a non-nil reader.
func NewReader(r io.Reader) *Reader { return &Reader{input: bufio.NewReaderSize(r, MaxLine)} }

// Read decodes one newline-terminated object into a struct pointer. EOF is returned
// only between records; truncated, oversized, non-UTF-8, or ambiguous input fails.
func (r *Reader) Read(dst any) error {
	return r.ReadStarted(dst, nil)
}

// ReadStarted invokes started after the first byte is available, including buffered
// records, so callers can distinguish idle waits from bounded record assembly.
// Callback and transport errors propagate without adding record contents.
func (r *Reader) ReadStarted(dst any, started func() error) error {
	if _, err := r.input.Peek(1); err != nil {
		return err
	}
	if started != nil {
		if err := started(); err != nil {
			return err
		}
	}
	line, err := r.input.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return io.EOF
			}
			return errors.New("protocol: incomplete record")
		}
		return errors.Join(errors.New("protocol: incomplete or oversized record"), err)
	}
	if len(line) > MaxLine {
		return errors.New("protocol: record exceeds limit")
	}
	defer clear(line)
	return Decode(line, dst)
}

// Decode validates a bounded UTF-8 object against exact struct field spellings.
// Duplicate keys, null values, unknown fields, trailing data, and type mismatches
// fail with a fixed error, so even malformed credential requests remain private.
func Decode(data []byte, dst any) error {
	invalid := errors.New("protocol: invalid object")
	t := reflect.TypeOf(dst)
	if len(data) > MaxLine || !utf8.Valid(data) || t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(dst).IsNil() || t.Elem().Kind() != reflect.Struct {
		return invalid
	}
	fields := make(map[string]bool)
	for i := 0; i < t.Elem().NumField(); i++ {
		name := strings.Split(t.Elem().Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			fields[name] = true
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return invalid
	}
	if err := object(decoder, fields, 0); err != nil {
		return invalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return invalid
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return invalid
	}
	return nil
}

// object checks an opened JSON object, bounding recursion and rejecting duplicates.
// A nil field set permits arbitrary nested keys for separately validated payloads.
func object(d *json.Decoder, fields map[string]bool, depth int) error {
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || (fields != nil && !fields[key]) {
			return errors.New("invalid key")
		}
		seen[key] = true
		if err := value(d, depth+1); err != nil {
			return err
		}
	}
	token, err := d.Token()
	if err != nil || token != json.Delim('}') {
		return errors.New("invalid object")
	}
	return nil
}

// value consumes one JSON value without retaining its text; depth above 32 fails.
// Null is deliberately excluded because the request schema has no nullable values.
func value(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("excessive nesting")
	}
	token, err := d.Token()
	if err != nil || token == nil {
		return errors.New("invalid value")
	}
	switch token {
	case json.Delim('{'):
		return object(d, nil, depth)
	case json.Delim('['):
		for d.More() {
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
		token, err = d.Token()
		if err != nil || token != json.Delim(']') {
			return errors.New("invalid array")
		}
	}
	return nil
}

// Write emits one complete bounded JSON record. Encoding and short-write errors
// are returned without including payload text. The caller serializes concurrent writes.
func Write(w io.Writer, message any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return errors.New("protocol: cannot encode message")
	}
	defer clear(data)
	if len(data)+1 > MaxLine {
		return errors.New("protocol: record exceeds limit")
	}
	data = append(data, '\n')
	defer clear(data)
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// Validate checks operation-specific arguments after strict structural decoding.
// Credential answers must fit one Assuan data record after escaping, so an accepted
// answer cannot be discarded later by pinentry. Failures never reflect caller input.
func (r Request) Validate() error {
	invalid := errors.New("protocol: invalid request arguments")
	if r.ID == "" || len(r.ID) > 128 || len(r.Secret) > 997 {
		return invalid
	}
	escapedSize := len(r.Secret)
	for i := range len(r.Secret) {
		switch r.Secret[i] {
		case '%', '\r', '\n', '\x00':
			escapedSize += 2
		}
	}
	if escapedSize > 997 {
		return invalid
	}
	allowed := map[string]string{
		"hello": "version", "subscribe": "", "profile.list": "", "profile.get": "profile",
		"profile.put": "profile_json", "profile.delete": "profile", "up": "profile", "down": "profile all",
		"status": "", "answer": "challenge_id secret", "cancel": "challenge_id", "trust": "profile digest", "logs": "profile lines",
	}
	args, ok := allowed[r.Op]
	if !ok {
		return invalid
	}
	present := map[string]bool{"version": r.Version != "", "profile": r.Profile != "", "profile_json": len(r.ProfileJSON) > 0,
		"all": r.All, "challenge_id": r.ChallengeID != "", "secret": r.Secret != "", "digest": r.Digest != "", "lines": r.Lines != 0}
	for field, has := range present {
		if has && !strings.Contains(" "+args+" ", " "+field+" ") {
			return invalid
		}
	}
	if strings.Contains(args, "profile") && r.Op != "profile.put" && r.Profile == "" && (r.Op != "down" || !r.All) {
		return invalid
	}
	if r.Op == "down" && r.All && r.Profile != "" {
		return invalid
	}
	if r.Op == "profile.put" && len(r.ProfileJSON) == 0 {
		return invalid
	}
	if strings.Contains(args, "challenge_id") && r.ChallengeID == "" {
		return invalid
	}
	if r.Op == "trust" && len(r.Digest) != 64 {
		return invalid
	}
	if r.Op == "logs" && (r.Lines < 0 || r.Lines > 500) {
		return invalid
	}
	return nil
}
