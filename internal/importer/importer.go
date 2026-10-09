// Package importer creates secret-free profile drafts from FortiClient configuration.
// Conversion captures the whole plist, but secret fields are never decoded, copied into drafts, or logged.
// Import is read-only and macOS-only; Decode is a platform-independent, bounded JSON parser.
package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/avhn/fortix/internal/profile"
)

// Import limits bound conversion output, nesting, and the number of candidate profiles.
const (
	DefaultPath = "/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist"
	maxBytes    = 4 * 1024 * 1024
	maxDepth    = 32
	maxProfiles = 4096
)

// ErrUnsupported explains the current platform boundary without attempting conversion.
var ErrUnsupported = errors.New("FortiClient import is macOS-only for now")

// Converter converts a plist path to caller-owned JSON without mutating the source.
// Import clears the returned buffer after parsing. Conversion errors must not include
// captured configuration or command output.
type Converter interface {
	Convert(ctx context.Context, path string) ([]byte, error)
}

// Plutil invokes the system plist converter directly, never through a shell.
// Output is bounded and stderr is discarded so secret fields cannot enter diagnostics.
type Plutil struct{}

// Convert returns the whole plist JSON, including opaque secret fields, under a ten-second deadline.
// Failures return sanitized errors; callers must not log the returned configuration.
func (Plutil) Convert(ctx context.Context, path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", "--", path)
	cmd.WaitDelay = time.Second
	out := &boundedOutput{}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("FortiClient plist conversion failed")
	}
	return out.Bytes(), nil
}

// boundedOutput rejects converter output larger than maxBytes instead of retaining secrets indefinitely.
type boundedOutput struct{ bytes.Buffer }

// Write appends converter bytes only when the entire chunk fits the output limit.
func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > maxBytes-b.Len() {
		return 0, errors.New("conversion output exceeds size limit")
	}
	return b.Buffer.Write(data)
}

// Import converts path (or DefaultPath when empty), returning validated drafts and warnings.
// Linux and other systems return ErrUnsupported before calling the injected converter.
func Import(ctx context.Context, path string, converter Converter) ([]profile.Profile, []string, error) {
	if runtime.GOOS != "darwin" {
		return nil, nil, ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if path == "" {
		path = DefaultPath
	}
	if converter == nil {
		converter = Plutil{}
	}
	data, err := converter.Convert(ctx, path)
	defer clear(data)
	if err != nil {
		return nil, nil, errors.New("FortiClient plist conversion failed")
	}
	return Decode(bytes.NewReader(data))
}

// Decode finds VpnType-bearing records in plist dictionaries or arrays in stable key order.
// Only Name, Server, ServerPort, User, and VpnType are decoded from each record.
// Other VPN types and invalid SSL profiles are skipped with non-secret warnings.
func Decode(r io.Reader) ([]profile.Profile, []string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	defer clear(data)
	if err != nil {
		return nil, nil, errors.New("cannot read FortiClient configuration")
	}
	if len(data) > maxBytes {
		return nil, nil, errors.New("FortiClient configuration exceeds size limit")
	}
	var raw json.RawMessage
	defer func() { clear(raw) }()
	d := json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&raw); err != nil {
		return nil, nil, errors.New("invalid FortiClient JSON")
	}
	if err := d.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("trailing FortiClient JSON")
	}
	parser := decoder{used: make(map[string]bool)}
	if err := parser.walk(raw, 0); err != nil {
		return nil, nil, err
	}
	return parser.drafts, parser.warnings, nil
}

// decoder keeps deterministic identifiers and validated results for one import operation.
// It never decodes secret values; warnings include only bounded, escaped profile names.
type decoder struct {
	used     map[string]bool
	drafts   []profile.Profile
	warnings []string
	count    int
}

// walk recursively examines container structure, skipping credential-bearing subtrees.
// Depth and record limits reject hostile input before unbounded recursive work.
func (d *decoder) walk(raw json.RawMessage, depth int) error {
	if depth > maxDepth {
		return errors.New("FortiClient configuration nesting exceeds limit")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return errors.New("empty FortiClient configuration")
	}
	switch raw[0] {
	case '{':
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return errors.New("invalid FortiClient object")
		}
		if _, ok := fields["VpnType"]; ok {
			return d.record(fields)
		}
		keys := make([]string, 0, len(fields))
		for key := range fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") {
				continue
			}
			if err := d.walk(fields[key], depth+1); err != nil {
				return err
			}
		}
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return errors.New("invalid FortiClient array")
		}
		for _, item := range items {
			if err := d.walk(item, depth+1); err != nil {
				return err
			}
		}
	default:
		if depth == 0 {
			return errors.New("FortiClient configuration must be an object or array")
		}
	}
	return nil
}

// record projects one VPN record into a validated, defaulted profile or a named warning.
// Backend remains omitted so the editor can select MFA before resolving its default.
// Server must contain a host only; embedded ports are rejected rather than guessed.
// Numeric strings are accepted because plist exporters can encode ports and types either way.
func (d *decoder) record(fields map[string]json.RawMessage) error {
	d.count++
	if d.count > maxProfiles {
		return errors.New("too many FortiClient profiles")
	}
	var name string
	_ = json.Unmarshal(fields["Name"], &name)
	warn := func(reason string) {
		d.warnings = append(d.warnings, "Skipped VPN profile "+warningName(name)+": "+reason)
	}
	kind, err := integer(fields["VpnType"])
	if err != nil {
		warn("invalid type")
		return nil
	}
	if kind != 0 {
		warn("non-SSL VPN type")
		return nil
	}
	var p profile.Profile
	p.SchemaVersion = 1
	for _, field := range []struct {
		key    string
		target *string
	}{{"Name", &p.Name}, {"Server", &p.Gateway.Host}, {"User", &p.Username}} {
		raw, ok := fields[field.key]
		if !ok {
			warn("missing " + field.key)
			return nil
		}
		if err := json.Unmarshal(raw, field.target); err != nil || *field.target == "" {
			warn("invalid " + field.key)
			return nil
		}
	}
	if port, ok := fields["ServerPort"]; ok {
		p.Gateway.Port, err = integer(port)
		if err != nil || p.Gateway.Port < 1 || p.Gateway.Port > 65535 {
			warn("invalid port")
			return nil
		}
	}
	base := slug(p.Name)
	p.ID = base
	for suffix := 2; d.used[p.ID]; suffix++ {
		ending := "-" + strconv.Itoa(suffix)
		p.ID = strings.TrimRight(base[:min(len(base), 63-len(ending))], "-") + ending
	}
	p.ApplyDefaults()
	if err := p.Validate(); err != nil {
		warn("invalid SSL VPN fields")
		return nil
	}
	// Validate the resolved choice but do not pin the draft before MFA is edited.
	p.Backend = ""
	d.used[p.ID] = true
	d.drafts = append(d.drafts, p)
	return nil
}

// warningName bounds a non-secret display name and escapes controls for safe diagnostics.
// Missing or malformed names use a fixed label, never another configuration field.
func warningName(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	var bounded strings.Builder
	for i, r := range name {
		if i >= 128 {
			break
		}
		bounded.WriteRune(r)
	}
	return strconv.QuoteToASCII(bounded.String())
}

// integer parses a decimal JSON integer or string without accepting fractions or null.
func integer(raw json.RawMessage) (int, error) {
	text := string(bytes.TrimSpace(raw))
	if strings.HasPrefix(text, "\"") {
		if err := json.Unmarshal(raw, &text); err != nil {
			return 0, errors.New("invalid integer")
		}
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return 0, errors.New("invalid integer")
	}
	return value, nil
}

// slug makes a bounded ASCII profile identifier from a display name, collapsing separators.
// Names without ASCII letters or digits use vpn; deduplication is handled by record.
func slug(name string) string {
	var b strings.Builder
	separator := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if separator && b.Len() > 0 && b.Len() < 62 {
				b.WriteByte('-')
			}
			if b.Len() >= 63 {
				break
			}
			b.WriteRune(r)
			separator = false
		} else {
			separator = true
		}
	}
	result := strings.TrimRight(b.String(), "-")
	if result == "" {
		return "vpn"
	}
	return result
}
