// Package profile tests strict decoding, defaults, and field-level validation.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// example loads the public example for tests and fails the test on fixture I/O errors.
func example(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// validProfile decodes the fixture and returns an independent defaulted profile.
// Any unexpected fixture error fails the calling test immediately.
func validProfile(t testing.TB) *Profile {
	t.Helper()
	p, err := Decode(bytes.NewReader(example(t)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestValidate covers each schema rule using independent mutations of a valid profile.
// Invalid cases must expose the expected JSON path through joined ValidationError values.
func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Profile)
		field  string
	}{
		{"valid", func(_ *Profile) {}, ""},
		{"schema", func(p *Profile) { p.SchemaVersion = 2 }, "schema_version"},
		{"schema zero", func(p *Profile) { p.SchemaVersion = 0 }, "schema_version"},
		{"id empty", func(p *Profile) { p.ID = "" }, "id"},
		{"id path", func(p *Profile) { p.ID = "../work" }, "id"},
		{"id uppercase", func(p *Profile) { p.ID = "Work" }, "id"},
		{"id leading hyphen", func(p *Profile) { p.ID = "-work" }, "id"},
		{"id underscore", func(p *Profile) { p.ID = "work_vpn" }, "id"},
		{"id long", func(p *Profile) { p.ID = strings.Repeat("a", 64) }, "id"},
		{"id max", func(p *Profile) { p.ID = strings.Repeat("a", 63) }, ""},
		{"id single digit", func(p *Profile) { p.ID = "0" }, ""},
		{"name empty", func(p *Profile) { p.Name = "" }, "name"},
		{"name long", func(p *Profile) { p.Name = strings.Repeat("é", 65) }, "name"},
		{"name max unicode", func(p *Profile) { p.Name = strings.Repeat("é", 64) }, ""},
		{"name controls", func(p *Profile) { p.Name = "Work\n" }, "name"},
		{"name C1 control", func(p *Profile) { p.Name = "Work\u0085" }, "name"},
		{"name malformed utf8", func(p *Profile) { p.Name = string([]byte{0xff}) }, "name"},
		{"backend", func(p *Profile) { p.Backend = "other" }, "backend"},
		{"host empty", func(p *Profile) { p.Gateway.Host = "" }, "gateway.host"},
		{"host scheme", func(p *Profile) { p.Gateway.Host = "https://vpn.example.com" }, "gateway.host"},
		{"host port", func(p *Profile) { p.Gateway.Host = "vpn.example.com:443" }, "gateway.host"},
		{"host path", func(p *Profile) { p.Gateway.Host = "vpn.example.com/path" }, "gateway.host"},
		{"host label long", func(p *Profile) { p.Gateway.Host = strings.Repeat("a", 64) + ".com" }, "gateway.host"},
		{"host label max", func(p *Profile) { p.Gateway.Host = strings.Repeat("a", 63) + ".com" }, ""},
		{"host length max", func(p *Profile) {
			p.Gateway.Host = strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61)
		}, ""},
		{"host length long", func(p *Profile) {
			p.Gateway.Host = strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 62)
		}, "gateway.host"},
		{"host empty label", func(p *Profile) { p.Gateway.Host = "vpn..example.com" }, "gateway.host"},
		{"host trailing dot", func(p *Profile) { p.Gateway.Host = "vpn.example.com." }, "gateway.host"},
		{"host leading hyphen", func(p *Profile) { p.Gateway.Host = "-vpn.example.com" }, "gateway.host"},
		{"host trailing hyphen", func(p *Profile) { p.Gateway.Host = "vpn-.example.com" }, "gateway.host"},
		{"host underscore", func(p *Profile) { p.Gateway.Host = "vpn_test.example.com" }, "gateway.host"},
		{"host ipv4", func(p *Profile) { p.Gateway.Host = "192.0.2.1" }, ""},
		{"host ipv6", func(p *Profile) { p.Gateway.Host = "2001:db8::1" }, ""},
		{"host bracketed ipv6", func(p *Profile) { p.Gateway.Host = "[2001:db8::1]" }, "gateway.host"},
		{"host scoped ipv6", func(p *Profile) { p.Gateway.Host = "fe80::1%en0" }, "gateway.host"},
		{"host uppercase", func(p *Profile) { p.Gateway.Host = "VPN.example.com" }, ""},
		{"host single label", func(p *Profile) { p.Gateway.Host = "vpn" }, ""},
		{"port low", func(p *Profile) { p.Gateway.Port = -1 }, "gateway.port"},
		{"port zero without defaults", func(p *Profile) { p.Gateway.Port = 0 }, "gateway.port"},
		{"port high", func(p *Profile) { p.Gateway.Port = 65536 }, "gateway.port"},
		{"port min", func(p *Profile) { p.Gateway.Port = 1 }, ""},
		{"port max", func(p *Profile) { p.Gateway.Port = 65535 }, ""},
		{"realm empty", func(p *Profile) { p.Realm = "" }, ""},
		{"realm alphabet", func(p *Profile) { p.Realm = "Az09._-" }, ""},
		{"realm max", func(p *Profile) { p.Realm = strings.Repeat("a", 64) }, ""},
		{"realm long", func(p *Profile) { p.Realm = strings.Repeat("a", 65) }, "realm"},
		{"realm whitespace", func(p *Profile) { p.Realm = "work realm" }, "realm"},
		{"realm nonascii", func(p *Profile) { p.Realm = "é" }, "realm"},
		{"username empty", func(p *Profile) { p.Username = "" }, "username"},
		{"username max", func(p *Profile) { p.Username = strings.Repeat("é", 256) }, ""},
		{"username long", func(p *Profile) { p.Username = strings.Repeat("a", 257) }, "username"},
		{"username controls", func(p *Profile) { p.Username = "jane\x00doe" }, "username"},
		{"username start whitespace", func(p *Profile) { p.Username = " jane.doe" }, "username"},
		{"username end unicode whitespace", func(p *Profile) { p.Username = "jane.doe " }, "username"},
		{"username internal space", func(p *Profile) { p.Username = "jane doe" }, ""},
		{"cert absent", func(p *Profile) { p.TrustedCert = "" }, ""},
		{"cert short", func(p *Profile) { p.TrustedCert = strings.Repeat("a", 63) }, "trusted_cert"},
		{"cert long", func(p *Profile) { p.TrustedCert = strings.Repeat("a", 65) }, "trusted_cert"},
		{"cert nonhex", func(p *Profile) { p.TrustedCert = strings.Repeat("g", 64) }, "trusted_cert"},
		{"cert uppercase", func(p *Profile) { p.TrustedCert = strings.Repeat("A", 64) }, ""},
		{"cert colon separated", func(p *Profile) { p.TrustedCert = strings.Repeat("AB:", 31) + "AB" }, ""},
		{"cert only separators", func(p *Profile) { p.TrustedCert = ":::" }, "trusted_cert"},
		{"mfa push", func(p *Profile) { p.MFA.Mode = "push" }, ""},
		{"mfa none", func(p *Profile) { p.MFA.Mode = "none" }, ""},
		{"mfa prompt", func(p *Profile) { p.MFA.Mode = "prompt" }, ""},
		{"mfa static", func(p *Profile) { p.MFA.Mode = "static" }, ""},
		{"mfa unknown", func(p *Profile) { p.MFA.Mode = "other" }, "mfa.mode"},
		{"mfa totp defaults", func(p *Profile) { p.MFA.Mode = "totp"; p.ApplyDefaults() }, ""},
		{"mfa digits forbidden", func(p *Profile) { p.MFA.Digits = new(0) }, "mfa.digits"},
		{"mfa period forbidden", func(p *Profile) { p.MFA.Period = new(0) }, "mfa.period"},
		{"mfa algorithm forbidden", func(p *Profile) { p.MFA.Algorithm = new("") }, "mfa.algorithm"},
		{"totp digits bad", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Digits = new(7); p.ApplyDefaults() }, "mfa.digits"},
		{"totp digits zero", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Digits = new(0); p.ApplyDefaults() }, "mfa.digits"},
		{"totp digits eight", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Digits = new(8); p.ApplyDefaults() }, ""},
		{"totp period low", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Period = new(14); p.ApplyDefaults() }, "mfa.period"},
		{"totp period high", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Period = new(121); p.ApplyDefaults() }, "mfa.period"},
		{"totp period min", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Period = new(15); p.ApplyDefaults() }, ""},
		{"totp period max", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Period = new(120); p.ApplyDefaults() }, ""},
		{"totp algorithm bad", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Algorithm = new("sha1"); p.ApplyDefaults() }, "mfa.algorithm"},
		{"totp SHA256", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Algorithm = new("SHA256"); p.ApplyDefaults() }, ""},
		{"totp SHA512", func(p *Profile) { p.MFA.Mode = "totp"; p.MFA.Algorithm = new("SHA512"); p.ApplyDefaults() }, ""},
		{"routes unknown", func(p *Profile) { p.Routes.Mode = "other" }, "routes.mode"},
		{"routes gateway", func(p *Profile) { p.Routes.Mode = "gateway"; p.Routes.Include = nil }, ""},
		{"routes full", func(p *Profile) { p.Routes.Mode = "full"; p.Routes.Include = nil }, ""},
		{"routes gateway include", func(p *Profile) { p.Routes.Mode = "gateway" }, "routes.include"},
		{"routes full include", func(p *Profile) { p.Routes.Mode = "full" }, "routes.include"},
		{"routes gateway empty include", func(p *Profile) { p.Routes.Mode = "gateway"; p.Routes.Include = []string{} }, "routes.include"},
		{"routes custom empty", func(p *Profile) { p.Routes.Include = nil }, "routes.include"},
		{"routes malformed", func(p *Profile) { p.Routes.Include = []string{"not-a-prefix"} }, "routes.include[0]"},
		{"routes ipv6", func(p *Profile) { p.Routes.Include = []string{"2001:db8::/32"} }, "routes.include[0]"},
		{"routes ipv4 mapped", func(p *Profile) { p.Routes.Include = []string{"::ffff:192.0.2.0/120"} }, "routes.include[0]"},
		{"routes unmasked", func(p *Profile) { p.Routes.Include = []string{"10.20.0.1/16"} }, "routes.include[0]"},
		{"routes padded prefix", func(p *Profile) { p.Routes.Include = []string{"10.20.0.0/016"} }, "routes.include[0]"},
		{"routes duplicate", func(p *Profile) { p.Routes.Include = []string{"10.20.0.0/16", "10.20.0.0/16"} }, "routes.include[1]"},
		{"routes overlap", func(p *Profile) { p.Routes.Include = []string{"10.20.0.0/16", "10.20.1.0/24"} }, "routes.include[1]"},
		{"routes reverse overlap", func(p *Profile) { p.Routes.Include = []string{"10.20.1.0/24", "10.20.0.0/16"} }, "routes.include[1]"},
		{"routes disjoint", func(p *Profile) { p.Routes.Include = []string{"10.20.0.0/16", "10.21.0.0/16"} }, ""},
		{"routes min prefix", func(p *Profile) { p.Routes.Include = []string{"10.0.0.0/8"} }, ""},
		{"routes max prefix", func(p *Profile) { p.Routes.Include = []string{"10.20.0.1/32"} }, ""},
		{"preserve LAN false", func(p *Profile) { p.Routes.PreserveLAN = new(false); p.ApplyDefaults() }, ""},
		{"dns unknown", func(p *Profile) { p.DNS.Mode = "other" }, "dns.mode"},
		{"dns none", func(p *Profile) { p.DNS.Mode = "none"; p.DNS.Domains = nil }, ""},
		{"dns none domains", func(p *Profile) { p.DNS.Mode = "none" }, "dns.domains"},
		{"dns none empty domains", func(p *Profile) { p.DNS.Mode = "none"; p.DNS.Domains = []string{} }, "dns.domains"},
		{"dns split empty", func(p *Profile) { p.DNS.Domains = nil }, "dns.domains"},
		{"dns split too many", func(p *Profile) { p.DNS.Domains = make([]string, 33) }, "dns.domains"},
		{"dns uppercase", func(p *Profile) { p.DNS.Domains = []string{"CORP.example.com"} }, "dns.domains[0]"},
		{"dns trailing dot", func(p *Profile) { p.DNS.Domains = []string{"corp.example.com."} }, "dns.domains[0]"},
		{"dns wildcard", func(p *Profile) { p.DNS.Domains = []string{"*.example.com"} }, "dns.domains[0]"},
		{"dns duplicate", func(p *Profile) { p.DNS.Domains = []string{"corp.example.com", "corp.example.com"} }, "dns.domains[1]"},
		{"dns invalid label", func(p *Profile) { p.DNS.Domains = []string{"corp_.example.com"} }, "dns.domains[0]"},
		{"dns max list", func(p *Profile) {
			p.DNS.Domains = make([]string, 32)
			for i := range p.DNS.Domains {
				p.DNS.Domains[i] = fmt.Sprintf("corp%d.example.com", i)
			}
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validProfile(t)
			tc.change(p)
			err := p.Validate()
			if tc.field == "" {
				if err != nil {
					t.Fatal(err)
				}
				if p.TrustedCert != "" && !certPattern.MatchString(p.TrustedCert) {
					t.Fatalf("certificate not normalized: %q", p.TrustedCert)
				}
				return
			}
			if !hasField(err, tc.field) {
				t.Fatalf("wanted %s, got %v", tc.field, err)
			}
		})
	}
	for bits := 0; bits < 8; bits++ {
		t.Run(fmt.Sprintf("broad /%d", bits), func(t *testing.T) {
			p := validProfile(t)
			p.Routes.Include = []string{fmt.Sprintf("0.0.0.0/%d", bits)}
			if !hasField(p.Validate(), "routes.include[0]") {
				t.Fatal("accepted overly broad prefix")
			}
		})
	}
}

// hasField traverses joined validation errors to find field, returning false if absent.
// It accepts nil and both individual and errors.Join error trees without panicking.
func hasField(err error, field string) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if hasField(child, field) {
				return true
			}
		}
		return false
	}
	var problem *ValidationError
	return errors.As(err, &problem) && problem.Field == field
}

// TestJoinedErrors proves validation reports all independent problems and inspectable messages.
// Nil receivers must fail validation but remain safe for default application.
func TestJoinedErrors(t *testing.T) {
	p := validProfile(t)
	p.SchemaVersion, p.ID, p.Gateway.Port = 0, "", -1
	err := p.Validate()
	for _, field := range []string{"schema_version", "id", "gateway.port"} {
		if !hasField(err, field) {
			t.Fatalf("missing %s in %v", field, err)
		}
	}
	var problem *ValidationError
	if !errors.As(err, &problem) || problem.Message == "" {
		t.Fatalf("not inspectable: %v", err)
	}
	if !strings.Contains(err.Error(), "gateway.port: must be 1..65535") {
		t.Fatal(err)
	}
	var absent *Profile
	absent.ApplyDefaults()
	if !hasField(absent.Validate(), "$") {
		t.Fatal("nil profile accepted")
	}
}

// TestApplyDefaults verifies omitted values and idempotence.
// Explicit false and all supplied TOTP parameters must survive default application.
func TestApplyDefaults(t *testing.T) {
	p := &Profile{}
	p.ApplyDefaults()
	if p.Gateway.Port != 443 || p.MFA.Mode != "none" || p.Routes.Mode != "gateway" ||
		p.Routes.PreserveLAN == nil || !*p.Routes.PreserveLAN || p.DNS.Mode != "none" {
		t.Fatalf("incorrect defaults: %+v", p)
	}
	p.MFA.Mode = "totp"
	p.ApplyDefaults()
	if *p.MFA.Digits != 6 || *p.MFA.Period != 30 || *p.MFA.Algorithm != "SHA1" {
		t.Fatal("incorrect TOTP defaults")
	}
	p.MFA = MFA{Mode: "totp", Digits: new(8), Period: new(120), Algorithm: new("SHA512")}
	p.Routes.PreserveLAN = new(false)
	before := *p
	p.ApplyDefaults()
	if !reflect.DeepEqual(before, *p) {
		t.Fatal("explicit values changed")
	}
	p.ApplyDefaults()
	if !reflect.DeepEqual(before, *p) {
		t.Fatal("defaults are not idempotent")
	}
}

// TestDecode rejects structural ambiguity, secret fields, malformed input, and wrong types.
// Valid examples must round trip and receive defaults before their field validation.
func TestDecode(t *testing.T) {
	data := string(example(t))
	minimal := `{"schema_version":1,"id":"work","name":"Work","backend":"openfortivpn","gateway":{"host":"vpn.example.com"},"username":"jane.doe"}`
	tests := []struct{ name, input, want string }{
		{"example", data, ""},
		{"minimal", minimal, ""},
		{"zero port defaults", strings.Replace(minimal, `"host":"vpn.example.com"`, `"host":"vpn.example.com","port":0`, 1), ""},
		{"normalized cert", strings.Replace(data, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", strings.Repeat("AB:", 31)+"AB", 1), ""},
		{"separator-only cert", strings.Replace(data, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ":::", 1), "trusted_cert"},
		{"password unknown", strings.Replace(data, "{", `{"password":"x",`, 1), "unknown field"},
		{"seed unknown", strings.Replace(data, `"mode": "none"`, `"mode":"none","seed":"x"`, 1), "unknown field"},
		{"otp unknown", strings.Replace(data, `"mode": "none"`, `"mode":"none","otp":"x"`, 1), "unknown field"},
		{"option unknown", strings.Replace(data, "{", `{"options":"x",`, 1), "unknown field"},
		{"nested unknown", strings.Replace(data, `"host":`, `"extra":true,"host":`, 1), "unknown field"},
		{"case alias", strings.Replace(data, `"id":`, `"ID":`, 1), "unknown field"},
		{"duplicate top", strings.Replace(data, "{", `{"id":"another",`, 1), "duplicate key"},
		{"duplicate nested", strings.Replace(data, `"host":`, `"host":"other.example.com","host":`, 1), "duplicate key"},
		{"duplicate escaped", strings.Replace(data, "{", "{\"\\u0069d\":\"another\",", 1), "duplicate key"},
		{"duplicate in array", strings.Replace(data, `"10.20.0.0/16"`, `{"x":1,"x":2}`, 1), "duplicate key"},
		{"duplicate deep", strings.Replace(data, `"name": "Work"`, `"name":{"nested":{"x":1,"x":2}}`, 1), "duplicate key"},
		{"trailing object", data + `{}`, "trailing data"},
		{"trailing scalar", data + `true`, "trailing data"},
		{"trailing malformed", data + `!`, "trailing data"},
		{"trailing whitespace", data + " \n\t", ""},
		{"array", `[]`, "top level"},
		{"null", `null`, "top level"},
		{"string", `"text"`, "top level"},
		{"number", `1`, "top level"},
		{"bool", `true`, "top level"},
		{"empty", ``, "decode profile"},
		{"truncated", `{"id":`, "EOF"},
		{"unclosed array", `{"routes":{"include":[`, "EOF"},
		{"unclosed object", `{"gateway":{"host":"vpn.example.com"`, "EOF"},
		{"wrong type", strings.Replace(data, `"port": 10443`, `"port":"10443"`, 1), "cannot unmarshal"},
		{"null bool", strings.Replace(data, `"preserve_lan": true`, `"preserve_lan":null`, 1), "null is not allowed"},
		{"null MFA parameter", strings.Replace(data, `"mode": "none"`, `"mode":"none","digits":null`, 1), "null is not allowed"},
		{"forbidden zero digits", strings.Replace(data, `"mode": "none"`, `"mode":"none","digits":0`, 1), "mfa.digits"},
		{"invalid fields", `{}`, "schema_version"},
		{"oversized", data + strings.Repeat(" ", maxProfileBytes), "64 KiB"},
		{"exact size", data + strings.Repeat(" ", maxProfileBytes-len(data)), ""},
		{"bad encoding", strings.Replace(data, "Work", string([]byte{0xff}), 1), "UTF-8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Decode(strings.NewReader(tc.input))
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) || p != nil {
					t.Fatalf("wanted %q, got %v, %v", tc.want, p, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertRoundTrip(t, p)
		})
	}
	p, err := Decode(strings.NewReader(minimal))
	if err != nil || p.Gateway.Port != 443 || p.MFA.Mode != "none" || !*p.Routes.PreserveLAN {
		t.Fatalf("defaults not applied: %v, %v", p, err)
	}
	if p, err := Decode(nil); p != nil || err == nil {
		t.Fatal("nil reader accepted")
	}
	if p, err := Decode(failingReader{}); p != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost read error: %v", err)
	}
}

// failingReader simulates a reader failure without any external I/O or state.
type failingReader struct{}

// Read returns no bytes and io.ErrUnexpectedEOF for every buffer passed by the decoder.
func (failingReader) Read(_ []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// assertRoundTrip marshals p, decodes the result, and requires identical defaulted values.
// Encoding, decoding, validation, or equality failures fail the current test.
func assertRoundTrip(t testing.TB, p *Profile) {
	t.Helper()
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, again) {
		t.Fatalf("round trip changed profile: %+v != %+v", p, again)
	}
}

// FuzzDecode checks arbitrary byte input for panic safety and successful round-trip equality.
// Rejected input is expected; any successful decode must remain valid after JSON encoding.
func FuzzDecode(f *testing.F) {
	f.Add(example(f))
	for _, seed := range []string{`{}`, `null`, `{"id":"work","id":"other"}`, `{"password":"x"}`, `{"routes":{"include":[{"x":1,"x":2}]}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		assertRoundTrip(t, p)
	})
}
