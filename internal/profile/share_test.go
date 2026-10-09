// Package profile tests sharing boundaries, optional-field presence, and local completion.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// sharedTestProfile returns an independent valid example using documentation-only addresses.
// It supplies personal identity locally and never loads external fixtures or credentials.
func sharedTestProfile() Profile {
	p := Profile{SchemaVersion: 1, ID: "example", Name: "Example", Username: "example-user",
		Gateway: Gateway{Host: "vpn.example.com", Port: 443}, Realm: "example",
		TrustedCert: strings.Repeat("ab", 32),
		Routes:      Routes{Mode: "custom", Include: []string{"192.0.2.0/24"}},
		DNS:         DNS{Mode: "split", Domains: []string{"internal.example.com"}}}
	p.ApplyDefaults()
	return p
}

// shareInput wraps raw profile objects in the supported envelope without changing their JSON.
// It permits malformed profile fields for focused Parse rejection tests.
func shareInput(profiles ...string) []byte {
	return []byte(`{"format":"fortix-profile","version":1,"profiles":[` + strings.Join(profiles, ",") + `]}`)
}

// requireShareKind requires a typed, value-free sharing failure with the expected stable kind.
// It fails the calling test if Parse returned drafts together with an error.
func requireShareKind(t testing.TB, data []byte, kind string) {
	t.Helper()
	drafts, err := Parse(data)
	var problem *ShareError
	if drafts != nil || !errors.As(err, &problem) || problem.Kind != kind {
		t.Fatalf("wanted ShareError %s, got drafts %v, error %v", kind, drafts, err)
	}
}

// TestShareRoundTrip checks stable export, identity removal, local completion, and schema carry.
// Native, second-factor, and explicit false settings must survive without mutating input.
func TestShareRoundTrip(t *testing.T) {
	for _, mode := range []string{"none", "totp", "push", "prompt", "static"} {
		t.Run(mode, func(t *testing.T) {
			original := sharedTestProfile()
			original.MFA = MFA{Mode: mode}
			original.Backend = ""
			original.Routes.PreserveLAN = new(false)
			original.ApplyDefaults()
			before := cloneSharedProfile(original)
			data, err := Export(original)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("username")) || bytes.Contains(data, []byte(original.Username)) {
				t.Fatalf("personal identity exported: %s", data)
			}
			if !bytes.HasSuffix(data, []byte("\n")) || !bytes.Contains(data, []byte("\n  \"format\"")) {
				t.Fatalf("missing indentation or final newline: %s", data)
			}
			again, err := Export(original)
			if err != nil || !bytes.Equal(data, again) {
				t.Fatalf("unstable encoding: %v", err)
			}
			drafts, err := Parse(data)
			if err != nil || len(drafts) != 1 {
				t.Fatalf("parse: %v, %v", drafts, err)
			}
			if !reflect.DeepEqual(drafts[0].Missing(), []string{"username"}) {
				t.Fatal(drafts[0].Missing())
			}
			completed, err := Complete(drafts[0], original.Username, "")
			if err != nil || !reflect.DeepEqual(original, completed) {
				t.Fatalf("round trip: %+v, %v", completed, err)
			}
			if !reflect.DeepEqual(original, before) {
				t.Fatal("export changed the original profile")
			}
		})
	}
}

// TestShareSecrets checks every forbidden key at root, profile, object, and array depths.
// Secret detection must precede unknown-field, duplicate-key, null, and typed-decoding errors.
func TestShareSecrets(t *testing.T) {
	for _, key := range []string{"password", "passwd", "credential", "credentials", "secret", "token", "otp", "cookie", "svpncookie"} {
		for _, spelling := range []string{key, strings.ToUpper(key)} {
			for _, input := range []string{
				`{"` + spelling + `":"do-not-echo-this-value"}`,
				string(shareInput(`{"` + spelling + `":"do-not-echo-this-value"}`)),
				string(shareInput(`{"gateway":{"extra":{"` + spelling + `":"do-not-echo-this-value"}}}`)),
				string(shareInput(`{"extra":[[{"nested":{"` + spelling + `":"do-not-echo-this-value"}}]]}`)),
				string(shareInput(`{"id":"first","id":"second","extra":null,"nested":{"` + spelling + `":"do-not-echo-this-value"}}`)),
				string(shareInput(`{"extra":{"` + spelling + `":"do-not-echo-this-value"},"extra":{}}`)),
			} {
				requireShareKind(t, []byte(input), "secret")
				_, err := Parse([]byte(input))
				if strings.Contains(err.Error(), "do-not-echo-this-value") {
					t.Fatalf("secret value exposed: %v", err)
				}
			}
		}
	}
	requireShareKind(t, shareInput(`{"extra":{"password":"do-not-echo-this-value"}}`), "secret")
}

// TestShareStructure rejects unknown exact keys, wrong shapes/types, nulls, and ambiguous JSON.
// Envelope marker/version failures expose their own typed kinds and no supplied values.
func TestShareStructure(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		kind string
	}{
		{"format", []byte(`{"format":"other","version":1,"profiles":[{}]}`), "format"},
		{"missing format", []byte(`{"version":1,"profiles":[{}]}`), "format"},
		{"format type", []byte(`{"format":1,"version":1,"profiles":[{}]}`), "format"},
		{"version", []byte(`{"format":"fortix-profile","version":2,"profiles":[{}]}`), "version"},
		{"missing version", []byte(`{"format":"fortix-profile","profiles":[{}]}`), "version"},
		{"version type", []byte(`{"format":"fortix-profile","version":"1","profiles":[{}]}`), "version"},
		{"top unknown", []byte(`{"format":"fortix-profile","version":1,"profiles":[{}],"extra":true}`), "field"},
		{"profile unknown", shareInput(`{"naem":"Example"}`), "field"},
		{"personal username", shareInput(`{"username":"example-user"}`), "field"},
		{"case alias", shareInput(`{"ID":"example"}`), "field"},
		{"nested case alias", shareInput(`{"gateway":{"HOST":"vpn.example.com"}}`), "field"},
		{"nested gateway unknown", shareInput(`{"gateway":{"post":443}}`), "field"},
		{"nested mfa unknown", shareInput(`{"mfa":{"digit":6}}`), "field"},
		{"nested routes unknown", shareInput(`{"routes":{"includes":[]}}`), "field"},
		{"nested dns unknown", shareInput(`{"dns":{"domain":[]}}`), "field"},
		{"duplicate", shareInput(`{"id":"example","id":"other"}`), "duplicate_key"},
		{"escaped duplicate", shareInput(`{"id":"example","id":"other"}`), "duplicate_key"},
		{"nested duplicate", shareInput(`{"gateway":{"host":"vpn.example.com","host":"other.example.com"}}`), "duplicate_key"},
		{"null", shareInput(`{"routes":{"preserve_lan":null}}`), "field"},
		{"null list element", shareInput(`{"dns":{"domains":[null]}}`), "field"},
		{"profile array", shareInput(`[]`), "field"},
		{"gateway string", shareInput(`{"gateway":"vpn.example.com"}`), "field"},
		{"wrong field type", shareInput(`{"gateway":{"port":"443"}}`), "json"},
		{"wrong list type", shareInput(`{"routes":{"include":"192.0.2.0/24"}}`), "json"},
		{"wrong profiles type", []byte(`{"format":"fortix-profile","version":1,"profiles":{}}`), "json"},
		{"root array", []byte(`[]`), "field"},
		{"empty", nil, "json"},
		{"truncated", []byte(`{"format":`), "json"},
		{"trailing", append(shareInput(`{}`), []byte(`{}`)...), "json"},
		{"invalid UTF-8", shareInput(`{"name":"` + string([]byte{0xff}) + `"}`), "json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireShareKind(t, tc.data, tc.kind) })
	}
}

// TestDraftMissing checks minimal drafts, defaultable omissions, and conditional required lists.
// Parse does not inject defaults; completion requires only non-defaultable local information.
func TestDraftMissing(t *testing.T) {
	tests := []struct {
		profile string
		missing []string
	}{
		{`{}`, []string{"id", "name", "gateway.host", "username"}},
		{`{"gateway":{"host":"vpn.example.com"},"dns":{"domains":["example.com"]}}`, []string{"id", "name", "username"}},
		{`{"id":"example","name":"Example","gateway":{"host":"vpn.example.com"}}`, []string{"username"}},
		{`{"gateway":{},"routes":{"mode":"custom"},"dns":{"mode":"split"}}`, []string{"id", "name", "gateway.host", "username", "routes.include", "dns.domains"}},
		{`{"mfa":{"mode":"totp"}}`, []string{"id", "name", "gateway.host", "username"}},
	}
	for _, tc := range tests {
		drafts, err := Parse(shareInput(tc.profile))
		if err != nil {
			t.Fatal(err)
		}
		if got := drafts[0].Missing(); !reflect.DeepEqual(got, tc.missing) {
			t.Fatalf("%s: wanted %v, got %v", tc.profile, tc.missing, got)
		}
		if drafts[0].SchemaVersion != nil || drafts[0].Backend != nil {
			t.Fatal("Parse filled absent fields")
		}
	}
	drafts, err := Parse(shareInput(`{"name":"Example","gateway":{"host":"vpn.example.com"}}`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Complete(drafts[0], "example-user", "local-example")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "local-example" || p.SchemaVersion != 1 || p.Gateway.Port != 443 || p.Backend != "native" || p.MFA.Mode != "none" || p.Routes.Mode != "gateway" || !*p.Routes.PreserveLAN || p.DNS.Mode != "none" {
		t.Fatalf("wrong completion defaults: %+v", p)
	}
	if _, err := Complete(drafts[0], "", "local-example"); !hasField(err, "username") {
		t.Fatalf("missing username accepted: %v", err)
	}
	if _, err := Complete(drafts[0], "example-user", ""); !hasField(err, "id") {
		t.Fatalf("missing id accepted: %v", err)
	}
}

// TestDraftApply checks nested overlays, whole-list replacement, and identity preservation.
// Results must not alias the base or draft, and an empty draft must change no base fields.
func TestDraftApply(t *testing.T) {
	base := sharedTestProfile()
	base.MFA = MFA{Mode: "totp", Digits: new(6), Period: new(30), Algorithm: new("SHA1")}
	base.Backend = "openfortivpn"
	before := cloneSharedProfile(base)
	drafts, err := Parse(shareInput(`{"gateway":{"port":10443},"realm":"","mfa":{"digits":8},"routes":{"include":["198.51.100.0/24"],"preserve_lan":false},"dns":{"domains":["*.Example2.com"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	d := drafts[0]
	p := d.Apply(base)
	if p.Username != base.Username || p.ID != base.ID || p.Name != base.Name || p.Gateway.Host != base.Gateway.Host || p.Gateway.Port != 10443 || p.Realm != "" {
		t.Fatalf("unrelated fields changed or supplied fields lost: %+v", p)
	}
	if !reflect.DeepEqual(p.Routes.Include, []string{"198.51.100.0/24"}) || !reflect.DeepEqual(p.DNS.Domains, []string{"example2.com"}) || *p.Routes.PreserveLAN || *p.MFA.Digits != 8 || *p.MFA.Period != 30 {
		t.Fatalf("overlay or list replacement failed: %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Routes.Include[0], p.DNS.Domains[0], *p.MFA.Digits = "192.0.2.1/32", "other.example.com", 6
	*p.MFA.Period = 60
	if !reflect.DeepEqual(base, before) || (*d.Routes.Include)[0] != "198.51.100.0/24" || (*d.DNS.Domains)[0] != "example2.com" || *d.MFA.Digits != 8 {
		t.Fatal("Apply result aliases base or draft")
	}
	base.DNS.Domains = []string{"*.Example.com"}
	if got := (Draft{}).Apply(base); !reflect.DeepEqual(got, base) {
		t.Fatal("absent fields normalized or overwritten")
	}
	cleared := (Draft{Routes: &DraftRoutes{Include: new([]string{})}, DNS: &DraftDNS{Domains: new([]string{})}}).Apply(before)
	if cleared.Routes.Include == nil || len(cleared.Routes.Include) != 0 || cleared.DNS.Domains == nil || len(cleared.DNS.Domains) != 0 {
		t.Fatal("explicit empty lists did not replace the base")
	}
}

// TestShareNormalization verifies wildcard removal, lowercase domains, and masked trimmed CIDRs.
// Normalization must not repair malformed names or weaken prefix breadth, overlap, or IPv4 rules.
func TestShareNormalization(t *testing.T) {
	if got := NormalizeDomain("*.Example2.com"); got != "example2.com" {
		t.Fatal(got)
	}
	for _, domain := range []string{"*.*.example.com", "example.com.", " example.com", "example_.com"} {
		if normalized := NormalizeDomain(domain); validDNSName(normalized) {
			t.Fatalf("invalid domain repaired: %q", normalized)
		}
	}
	drafts, err := Parse(shareInput(`{"id":"example","name":"Example","gateway":{"host":"vpn.example.com"},"routes":{"mode":"custom","include":[" \t192.0.2.19/24\n"]},"dns":{"mode":"split","domains":["*.Example2.com"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Complete(drafts[0], "example-user", "override-example")
	if err != nil || p.ID != "override-example" || p.Routes.Include[0] != "192.0.2.0/24" || p.DNS.Domains[0] != "example2.com" {
		t.Fatalf("normalization failed: %+v, %v", p, err)
	}
	original := sharedTestProfile()
	original.DNS.Domains = []string{"*.Example2.com"}
	original.Routes.Include = []string{" 192.0.2.19/24 "}
	before := cloneSharedProfile(original)
	data, err := Export(original)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("*.")) || !bytes.Contains(data, []byte("192.0.2.0/24")) || !reflect.DeepEqual(before, original) {
		t.Fatal("export is not canonical and non-mutating")
	}
	if !hasField(original.Validate(), "dns.domains[0]") || !hasField(original.Validate(), "routes.include[0]") {
		t.Fatal("full validation unexpectedly accepts noncanonical input")
	}
}

// TestSharePartialValidation exercises each supplied field and existing cross-field constraints.
// The same ValidationError field and message used for full profiles must remain inspectable.
func TestSharePartialValidation(t *testing.T) {
	tests := []struct{ profile, field string }{
		{`{"schema_version":0}`, "schema_version"}, {`{"id":"../example"}`, "id"},
		{`{"name":""}`, "name"}, {`{"backend":"other"}`, "backend"},
		{`{"gateway":{"host":"https://vpn.example.com"}}`, "gateway.host"},
		{`{"gateway":{"port":0}}`, "gateway.port"}, {`{"gateway":{"port":65536}}`, "gateway.port"},
		{`{"realm":"not allowed"}`, "realm"}, {`{"trusted_cert":"bad"}`, "trusted_cert"},
		{`{"mfa":{"mode":""}}`, "mfa.mode"}, {`{"mfa":{"mode":"other"}}`, "mfa.mode"},
		{`{"mfa":{"digits":7}}`, "mfa.digits"}, {`{"mfa":{"digits":0}}`, "mfa.digits"},
		{`{"mfa":{"period":14}}`, "mfa.period"}, {`{"mfa":{"period":121}}`, "mfa.period"},
		{`{"mfa":{"algorithm":"sha1"}}`, "mfa.algorithm"},
		{`{"mfa":{"mode":"none","digits":6}}`, "mfa.digits"},
		{`{"backend":"native","mfa":{"mode":"push"}}`, "backend"},
		{`{"routes":{"mode":""}}`, "routes.mode"}, {`{"routes":{"mode":"other"}}`, "routes.mode"},
		{`{"routes":{"include":[]}}`, "routes.include"},
		{`{"routes":{"mode":"gateway","include":[]}}`, "routes.include"},
		{`{"routes":{"include":["192.0.2.0/7"]}}`, "routes.include[0]"},
		{`{"routes":{"include":["2001:db8::/32"]}}`, "routes.include[0]"},
		{`{"routes":{"include":["::ffff:192.0.2.0/120"]}}`, "routes.include[0]"},
		{`{"routes":{"include":["bad"]}}`, "routes.include[0]"},
		{`{"routes":{"include":["192.0.2.0/024"]}}`, "routes.include[0]"},
		{`{"routes":{"include":["192.0.2.0/24","192.0.2.1/24"]}}`, "routes.include[1]"},
		{`{"routes":{"include":["192.0.2.0/24","192.0.2.128/25"]}}`, "routes.include[1]"},
		{`{"dns":{"mode":""}}`, "dns.mode"}, {`{"dns":{"mode":"other"}}`, "dns.mode"},
		{`{"dns":{"domains":[]}}`, "dns.domains"},
		{`{"dns":{"mode":"none","domains":[]}}`, "dns.domains"},
		{`{"dns":{"domains":["example"]}}`, "dns.domains[0]"},
		{`{"dns":{"domains":["*.*.example.com"]}}`, "dns.domains[0]"},
		{`{"dns":{"domains":["example.com."]}}`, "dns.domains[0]"},
		{`{"dns":{"domains":["*.Example.com","example.com"]}}`, "dns.domains[1]"},
	}
	for _, tc := range tests {
		t.Run(tc.profile, func(t *testing.T) {
			drafts, err := Parse(shareInput(tc.profile))
			if drafts != nil || !hasField(err, tc.field) {
				t.Fatalf("wanted %s, got drafts %v, error %v", tc.field, drafts, err)
			}
		})
	}
	for _, text := range []string{`{"backend":"native"}`, `{"mfa":{"digits":8}}`, `{"routes":{"preserve_lan":false}}`, `{"realm":""}`, `{"trusted_cert":""}`} {
		if _, err := Parse(shareInput(text)); err != nil {
			t.Fatalf("valid partial %s rejected: %v", text, err)
		}
	}
	p, err := Complete(Draft{Gateway: &DraftGateway{Port: new(0)}}, "example-user", "example")
	if !hasField(err, "gateway.port") || !reflect.DeepEqual(p, Profile{}) {
		t.Fatalf("explicit zero defaulted: %+v, %v", p, err)
	}
	drafts, err := Parse(shareInput(`{"trusted_cert":"` + strings.Repeat("AB:", 31) + `AB"}`))
	if err != nil || *drafts[0].TrustedCert != strings.Repeat("ab", 32) {
		t.Fatalf("certificate normalization failed: %v", err)
	}
}

// TestShareLimits tests exact byte/count boundaries and duplicate supplied identifiers.
// Multiple drafts without IDs remain legal because each can receive a distinct local ID.
func TestShareLimits(t *testing.T) {
	minimal := shareInput(`{}`)
	exact := append(bytes.Clone(minimal), bytes.Repeat([]byte(" "), maxShareBytes-len(minimal))...)
	if _, err := Parse(exact); err != nil {
		t.Fatal(err)
	}
	requireShareKind(t, append(exact, ' '), "size")
	requireShareKind(t, shareInput(), "count")
	inputs := make([]string, 32, 33)
	profiles := make([]Profile, 32)
	for i := range inputs {
		inputs[i] = fmt.Sprintf(`{"id":"example-%d"}`, i)
		profiles[i] = sharedTestProfile()
		profiles[i].ID = fmt.Sprintf("example-%d", i)
	}
	if drafts, err := Parse(shareInput(inputs...)); err != nil || len(drafts) != 32 {
		t.Fatalf("32 drafts rejected: %v", err)
	}
	data, err := Export(profiles...)
	if err != nil {
		t.Fatal(err)
	}
	var doc sharedDocument
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Profiles) != 32 || *doc.Profiles[31].ID != "example-31" {
		t.Fatalf("export count or order: %v", err)
	}
	requireShareKind(t, shareInput(append(inputs, `{}`)...), "count")
	requireShareKind(t, shareInput(`{"id":"example"}`, `{"id":"example"}`), "duplicate_id")
	if drafts, err := Parse(shareInput(`{}`, `{}`)); err != nil || len(drafts) != 2 {
		t.Fatalf("absent ids treated as duplicates: %v", err)
	}
	for _, invalid := range [][]Profile{nil, append(profiles, sharedTestProfile()), {profiles[0], profiles[0]}} {
		if data, err := Export(invalid...); data != nil || err == nil {
			t.Fatal("invalid export count or duplicate accepted")
		}
	}
	invalid := sharedTestProfile()
	invalid.SchemaVersion = 2
	if data, err := Export(invalid); data != nil || !hasField(err, "schema_version") {
		t.Fatalf("invalid export profile accepted: %v", err)
	}
}

// FuzzShareParse checks panic safety, absence reporting, and valid successful completion.
// Partial drafts may fail completion, but every successfully completed profile must export.
func FuzzShareParse(f *testing.F) {
	for _, seed := range [][]byte{shareInput(`{}`), shareInput(`{"id":"example","name":"Example","gateway":{"host":"vpn.example.com"}}`), shareInput(`{"extra":{"password":"do-not-echo-this-value"}}`), []byte(`null`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		drafts, err := Parse(data)
		if err != nil {
			return
		}
		for _, d := range drafts {
			if missing := d.Missing(); len(missing) == 0 {
				t.Fatal("shared draft has no missing username")
			}
			p, err := Complete(d, "example-user", "example")
			if err != nil {
				continue
			}
			if _, err := Export(p); err != nil {
				t.Fatalf("completed profile cannot export: %v", err)
			}
		}
	})
}

// TestShareExclude carries excluded ranges through export and import, normalizing
// pasted prefixes the same way as included ones.
func TestShareExclude(t *testing.T) {
	original := sharedTestProfile()
	original.Backend = "native"
	original.Routes = Routes{Mode: "gateway", Exclude: []string{"198.51.100.0/24"}, PreserveLAN: new(true)}
	data, err := Export(original)
	if err != nil || !bytes.Contains(data, []byte(`"exclude"`)) {
		t.Fatalf("export: %s %v", data, err)
	}
	drafts, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := Complete(drafts[0], original.Username, "")
	if err != nil || !reflect.DeepEqual(completed.Routes.Exclude, original.Routes.Exclude) {
		t.Fatalf("round trip: %+v, %v", completed.Routes, err)
	}
	drafts, err = Parse(shareInput(`{"routes":{"mode":"gateway","exclude":[" 198.51.100.0/24 "]}}`))
	if err != nil || (*drafts[0].Routes.Exclude)[0] != "198.51.100.0/24" {
		t.Fatalf("normalize: %v", err)
	}
}
