package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

// fixture returns sanitized FortiClient conversion output with synthetic ignored secret values.
func fixture(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/vpn.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestDecode checks schema defaults, deduplication, non-SSL warnings, and secret exclusion.
func TestDecode(t *testing.T) {
	drafts, warnings, err := Decode(bytes.NewReader(fixture(t)))
	if err != nil || len(drafts) != 2 || len(warnings) != 2 {
		t.Fatalf("decode: %v %v %v", drafts, warnings, err)
	}
	for i, p := range drafts {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		wantID := "work-vpn"
		wantPort := 443
		if i == 1 {
			wantID = "work-vpn-2"
			wantPort = 10443
		}
		if p.ID != wantID || p.Gateway.Host != "vpn.example.com" || p.Gateway.Port != wantPort || p.Username != "jane.doe" || p.MFA.Mode != "none" || p.DNS.Mode != "none" || p.Routes.PreserveLAN == nil || !*p.Routes.PreserveLAN {
			t.Fatalf("profile: %+v", p)
		}
	}
	serialized, err := json.Marshal(drafts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "ignored-test-value") || strings.Contains(strings.Join(warnings, " "), "ignored-test-value") {
		t.Fatal("copied a secret")
	}
}

// TestInvalidRecords checks container shapes and refusal of malformed or unsupported records.
func TestInvalidRecords(t *testing.T) {
	for _, tc := range []struct {
		name, input     string
		count, warnings int
		invalid         bool
	}{
		{"dictionary", `{"profiles":{"one":{"Name":"Work","Server":"vpn.example.com","User":"jane.doe","VpnType":0}}}`, 1, 0, false},
		{"empty", `{}`, 0, 0, false},
		{"null", `null`, 0, 0, true},
		{"truncated", `[`, 0, 0, true},
		{"trailing", `{} {}`, 0, 0, true},
		{"type", `[{"VpnType":"bad"}]`, 0, 1, false},
		{"other type", `[{"VpnType":2}]`, 0, 1, false},
		{"missing fields", `[{"VpnType":0}]`, 0, 1, false},
		{"invalid gateway", `[{"Name":"Work","Server":"https://vpn.example.com","User":"jane.doe","VpnType":0}]`, 0, 1, false},
		{"invalid port", `[{"Name":"Work","Server":"vpn.example.com","User":"jane.doe","VpnType":0,"ServerPort":0}]`, 0, 1, false},
		{"fractional port", `[{"Name":"Work","Server":"vpn.example.com","User":"jane.doe","VpnType":0,"ServerPort":443.5}]`, 0, 1, false},
		{"secret subtree", `{"Password":{"Name":"Work","Server":"vpn.example.com","User":"jane.doe","VpnType":0}}`, 0, 0, false},
		{"oversized", strings.Repeat(" ", maxBytes+1), 0, 0, true},
		{"deep", strings.Repeat("[", maxDepth+2) + `{}` + strings.Repeat("]", maxDepth+2), 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drafts, warnings, err := Decode(strings.NewReader(tc.input))
			if (err != nil) != tc.invalid || len(drafts) != tc.count || len(warnings) != tc.warnings {
				t.Fatalf("counts: %d %d err=%v", len(drafts), len(warnings), err)
			}
		})
	}
}

// fakeConverter records a path and returns synthetic JSON or a sanitized test error.
type fakeConverter struct {
	data  []byte
	err   error
	path  string
	calls int
}

// Convert records the source path without touching a real FortiClient installation.
func (c *fakeConverter) Convert(_ context.Context, path string) ([]byte, error) {
	c.path = path
	c.calls++
	return append([]byte(nil), c.data...), c.err
}

// TestImport ensures source selection is read-only and Linux never attempts conversion.
func TestImport(t *testing.T) {
	c := &fakeConverter{data: fixture(t)}
	drafts, _, err := Import(context.Background(), "", c)
	if runtime.GOOS != "darwin" {
		if !errors.Is(err, ErrUnsupported) || c.calls != 0 {
			t.Fatal(err)
		}
		return
	}
	if err != nil || len(drafts) != 2 || c.path != DefaultPath {
		t.Fatalf("import: %v %q", err, c.path)
	}
	if _, _, err := Import(context.Background(), "/temporary/vpn.plist", c); err != nil || c.path != "/temporary/vpn.plist" {
		t.Fatal(err)
	}
	c.err = errors.New("ignored-test-value")
	if _, _, err := Import(context.Background(), "", c); err == nil || strings.Contains(err.Error(), "ignored-test-value") {
		t.Fatal("unsafe converter error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Import(ctx, "", c); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// TestSlug checks ASCII normalization, empty names, length bounds, and suffix collisions.
func TestSlug(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{" Work__VPN! ", "work-vpn"}, {"***", "vpn"}, {"東京", "vpn"}, {"A---B", "a-b"}, {strings.Repeat("a", 80), strings.Repeat("a", 63)},
	} {
		if got := slug(tc.input); got != tc.want {
			t.Fatalf("slug %q: %q", tc.input, got)
		}
	}
	records := make([]string, 0, 5)
	for _, name := range []string{"Work", "Work-2", "Work", strings.Repeat("a", 64), strings.Repeat("a", 64)} {
		records = append(records, fmt.Sprintf(`{"Name":%q,"Server":"vpn.example.com","User":"jane.doe","VpnType":0}`, name))
	}
	drafts, warnings, err := Decode(strings.NewReader("[" + strings.Join(records, ",") + "]"))
	if err != nil || len(warnings) != 0 || len(drafts) != 5 || drafts[2].ID != "work-3" || len(drafts[4].ID) != 63 {
		t.Fatalf("deduplication: %v %v %v", drafts, warnings, err)
	}
}

// TestBoundedOutput verifies converter capture refuses oversized data without retaining it.
func TestBoundedOutput(t *testing.T) {
	b := &boundedOutput{}
	if n, err := b.Write([]byte("{}")); err != nil || n != 2 {
		t.Fatal(err)
	}
	if _, err := b.Write(make([]byte, maxBytes)); err == nil || b.Len() != 2 {
		t.Fatal("unbounded converter output")
	}
}

// FuzzDecode ensures every returned draft validates and hostile JSON cannot panic.
func FuzzDecode(f *testing.F) {
	f.Add(string(fixture(f)))
	for _, input := range []string{`{}`, `null`, `{"VpnType":0}`, `[{"Name":"Work","Server":"vpn.example.com","User":"jane.doe","VpnType":0}]`} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		drafts, _, err := Decode(strings.NewReader(input))
		if err != nil {
			return
		}
		seen := make(map[string]bool)
		for _, p := range drafts {
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			if seen[p.ID] {
				t.Fatal("duplicate identifier")
			}
			seen[p.ID] = true
		}
	})
}

// TestWarningNames identifies skipped records without allowing name controls into diagnostics.
func TestWarningNames(t *testing.T) {
	for _, tc := range []struct{ input, reason string }{
		{`{"Name":"Work","VpnType":1}`, "non-SSL"},
		{`{"Name":"Work","VpnType":0}`, "missing Server"},
		{`{"Name":"Work","VpnType":0,"Server":"vpn.example.com"}`, "missing User"},
		{`{"Name":"Work","VpnType":0,"Server":"vpn.example.com:10443","User":"jane.doe"}`, "invalid SSL VPN fields"},
	} {
		drafts, warnings, err := Decode(strings.NewReader(tc.input))
		if err != nil || len(drafts) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], `"Work"`) || !strings.Contains(warnings[0], tc.reason) {
			t.Fatalf("warnings: %v %v", warnings, err)
		}
	}
	name := warningName("Work\n\x1b" + strings.Repeat("x", 200))
	if strings.ContainsAny(name, "\n\x1b") || len(name) > 160 {
		t.Fatalf("unsafe warning name: %q", name)
	}
}
