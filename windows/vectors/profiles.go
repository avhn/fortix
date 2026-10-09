package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/avhn/fortix/internal/profile"
)

// profileCase is one profile-validation.json entry decoded by profile.Decode.
// Exactly one of Profile, Errors, or DecodeError is set; Errors keeps helper order.
type profileCase struct {
	Name        string           `json:"name"`
	Input       string           `json:"input"`
	Profile     *profile.Profile `json:"profile,omitempty"`
	Errors      []fieldError     `json:"errors,omitempty"`
	DecodeError string           `json:"decode_error,omitempty"`
}

// fieldError is the wire form of one profile.ValidationError.
type fieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// flatten returns every ValidationError in a joined tree in its original order.
// It reports false when err contains anything other than validation errors.
func flatten(err error) ([]fieldError, bool) {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var all []fieldError
		for _, child := range joined.Unwrap() {
			list, ok := flatten(child)
			if !ok {
				return nil, false
			}
			all = append(all, list...)
		}
		return all, true
	}
	var problem *profile.ValidationError
	if errors.As(err, &problem) {
		return []fieldError{{problem.Field, problem.Message}}, true
	}
	return nil, false
}

// base returns a valid minimal profile object that cases mutate by replacing members.
func base() map[string]any {
	return map[string]any{"schema_version": 1, "id": "work", "name": "Work", "gateway": map[string]any{"host": "vpn.example.com"}, "username": "alice"}
}

// with returns the base profile with top-level members replaced, encoded in key order.
func with(changes map[string]any) string {
	p := base()
	for key, value := range changes {
		if value == nil {
			delete(p, key)
			continue
		}
		p[key] = value
	}
	data, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// host builds a profile with the given gateway host.
func host(name string) string { return with(map[string]any{"gateway": map[string]any{"host": name}}) }

// routes builds a profile with the given routes object.
func routes(value map[string]any) string { return with(map[string]any{"routes": value}) }

// prefixes repeats distinct /24 prefixes inside 10.0.0.0/8 for list length limits.
func prefixes(count int) []string {
	list := make([]string, count)
	for i := range list {
		list[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	return list
}

// domains returns count distinct valid split DNS domains.
func domains(count int) []string {
	list := make([]string, count)
	for i := range list {
		list[i] = fmt.Sprintf("d%d.example.com", i)
	}
	return list
}

// profileVectors decodes each input with the production decoder and records the result.
func profileVectors() (any, error) {
	pin := strings.Repeat("AB:", 31) + "AB"
	inputs := []struct{ name, input string }{
		{"minimal", with(nil)},
		{"full-native", with(map[string]any{"backend": "native", "realm": "Corp_1.a-b", "trusted_cert": pin, "gateway": map[string]any{"host": "vpn.example.com", "port": 10443},
			"routes": map[string]any{"mode": "full", "exclude": []string{"198.51.100.0/24", "203.0.113.0/25"}, "preserve_lan": false}, "dns": map[string]any{"mode": "split", "domains": []string{"corp.example.com", "example.org"}}})},
		{"totp-defaults", with(map[string]any{"mfa": map[string]any{"mode": "totp"}})},
		{"totp-explicit", with(map[string]any{"backend": "openfortivpn", "mfa": map[string]any{"mode": "totp", "digits": 8, "period": 120, "algorithm": "SHA512"}})},
		{"push", with(map[string]any{"mfa": map[string]any{"mode": "push"}})},
		{"custom-routes", routes(map[string]any{"mode": "custom", "include": []string{"10.0.0.0/8", "192.0.2.0/24", "198.51.100.7/32"}})},
		{"ipv4-gateway", host("192.0.2.10")},
		{"ipv6-gateway", host("2001:db8::1")},
		{"ipv6-unspecified", host("::")},
		{"ipv6-mapped", host("::ffff:192.0.2.1")},
		{"ipv6-embedded", host("64:ff9b::192.0.2.33")},
		{"ipv6-full", host("2001:0db8:0000:0000:0000:ff00:0042:8329")},
		{"ipv6-trailing-ellipsis", host("1:2:3:4:5:6:7::")},
		{"leading-zero-ipv4-is-hostname", host("192.0.2.010")},
		{"uppercase-host", host("VPN.Example.COM")},
		{"unicode-text", with(map[string]any{"name": "Büro 東京", "username": "İpek.東京"})},
		{"explicit-zero-port", with(map[string]any{"gateway": map[string]any{"host": "vpn.example.com", "port": 0}})},
		{"max-lengths", with(map[string]any{"id": "a" + strings.Repeat("b", 62), "name": strings.Repeat("n", 64), "realm": strings.Repeat("r", 64), "username": strings.Repeat("u", 256)})},
		{"exclude-limit", routes(map[string]any{"mode": "gateway", "exclude": prefixes(64)})},
		{"split-limit", with(map[string]any{"dns": map[string]any{"mode": "split", "domains": domains(32)}})},
		{"empty-object", "{}"},
		{"schema-version", with(map[string]any{"schema_version": 2})},
		{"id-uppercase", with(map[string]any{"id": "Work"})},
		{"id-hyphen-start", with(map[string]any{"id": "-work"})},
		{"id-too-long", with(map[string]any{"id": strings.Repeat("a", 64)})},
		{"name-empty", with(map[string]any{"name": ""})},
		{"name-too-long", with(map[string]any{"name": strings.Repeat("n", 65)})},
		{"name-control", with(map[string]any{"name": "Work\u0007"})},
		{"name-c1-control", with(map[string]any{"name": "Work\u0085"})},
		{"backend-unknown", with(map[string]any{"backend": "wireguard"})},
		{"native-with-mfa", with(map[string]any{"backend": "native", "mfa": map[string]any{"mode": "push"}})},
		{"host-scheme", host("https://vpn.example.com")},
		{"host-port", host("vpn.example.com:443")},
		{"host-zone", host("fe80::1%eth0")},
		{"host-bracketed", host("[2001:db8::1]")},
		{"host-empty-label", host("vpn..example.com")},
		{"host-trailing-dot", host("vpn.example.com.")},
		{"host-hyphen-label", host("-vpn.example.com")},
		{"host-underscore", host("vpn_1.example.com")},
		{"host-long-label", host(strings.Repeat("a", 64) + ".example.com")},
		{"host-too-long", host(strings.Repeat("a.", 126) + "ab")},
		{"host-double-ellipsis", host("1::2::3")},
		{"host-too-many-groups", host("1:2:3:4:5:6:7:8:9")},
		{"host-full-with-ellipsis", host("1:2:3:4:5:6:7:8::")},
		{"host-five-digit-group", host("12345::")},
		{"host-unicode", host("bücher.example.com")},
		{"host-empty", host("")},
		{"port-high", with(map[string]any{"gateway": map[string]any{"host": "vpn.example.com", "port": 65536}})},
		{"port-negative", with(map[string]any{"gateway": map[string]any{"host": "vpn.example.com", "port": -1}})},
		{"realm-space", with(map[string]any{"realm": "corp realm"})},
		{"realm-too-long", with(map[string]any{"realm": strings.Repeat("r", 65)})},
		{"realm-unicode", with(map[string]any{"realm": "bü"})},
		{"username-empty", with(map[string]any{"username": ""})},
		{"username-leading-space", with(map[string]any{"username": " alice"})},
		{"username-trailing-nbsp", with(map[string]any{"username": "alice\u00a0"})},
		{"username-trailing-ideographic-space", with(map[string]any{"username": "alice\u3000"})},
		{"username-too-long", with(map[string]any{"username": strings.Repeat("u", 257)})},
		{"username-inner-space", with(map[string]any{"username": "alice smith"})},
		{"trusted-cert-short", with(map[string]any{"trusted_cert": "abcd"})},
		{"trusted-cert-separators", with(map[string]any{"trusted_cert": "::"})},
		{"trusted-cert-non-hex", with(map[string]any{"trusted_cert": strings.Repeat("g", 64)})},
		{"mfa-unknown", with(map[string]any{"mfa": map[string]any{"mode": "sms"}})},
		{"totp-bad-parameters", with(map[string]any{"mfa": map[string]any{"mode": "totp", "digits": 7, "period": 10, "algorithm": "MD5"}})},
		{"totp-zero-parameters", with(map[string]any{"mfa": map[string]any{"mode": "totp", "digits": 0, "period": 0, "algorithm": ""}})},
		{"push-with-parameters", with(map[string]any{"mfa": map[string]any{"mode": "push", "digits": 6, "period": 30, "algorithm": "SHA1"}})},
		{"routes-unknown", routes(map[string]any{"mode": "split"})},
		{"gateway-with-include", routes(map[string]any{"mode": "gateway", "include": []string{"10.0.0.0/8"}})},
		{"full-with-empty-include", routes(map[string]any{"mode": "full", "include": []string{}})},
		{"custom-empty", routes(map[string]any{"mode": "custom", "include": []string{}})},
		{"custom-missing", routes(map[string]any{"mode": "custom"})},
		{"custom-with-exclude", routes(map[string]any{"mode": "custom", "include": []string{"10.0.0.0/8"}, "exclude": []string{"192.0.2.0/24"}})},
		{"exclude-empty", routes(map[string]any{"mode": "gateway", "exclude": []string{}})},
		{"exclude-too-many", routes(map[string]any{"mode": "gateway", "exclude": prefixes(65)})},
		{"exclude-openfortivpn", with(map[string]any{"backend": "openfortivpn", "routes": map[string]any{"mode": "gateway", "exclude": []string{"192.0.2.0/24"}}})},
		{"exclude-mfa-default-backend", with(map[string]any{"mfa": map[string]any{"mode": "prompt"}, "routes": map[string]any{"mode": "full", "exclude": []string{"192.0.2.0/24"}}})},
		{"prefix-problems", routes(map[string]any{"mode": "custom", "include": []string{"10.0.0.1/8", "10.0.0.0/4", "2001:db8::/32", "10.0.0.0", "192.0.2.0/08", "192.0.2.0/33", " 192.0.2.0/24", "010.0.0.0/8", "192.0.2.0/-1", "192.0.2.0/+8", "192.0.2.0/"}})},
		{"prefix-duplicate-overlap", routes(map[string]any{"mode": "custom", "include": []string{"10.0.0.0/8", "10.0.0.0/8", "10.1.0.0/16", "192.0.2.0/24", "192.0.2.128/25", "0.0.0.0/0"}})},
		{"exclude-prefix-problems", routes(map[string]any{"mode": "full", "exclude": []string{"192.0.2.1/24", "192.0.2.0/24", "192.0.2.0/24", "::/0"}})},
		{"dns-unknown", with(map[string]any{"dns": map[string]any{"mode": "full"}})},
		{"dns-none-with-domains", with(map[string]any{"dns": map[string]any{"mode": "none", "domains": []string{"corp.example.com"}}})},
		{"dns-split-empty", with(map[string]any{"dns": map[string]any{"mode": "split", "domains": []string{}}})},
		{"dns-split-missing", with(map[string]any{"dns": map[string]any{"mode": "split"}})},
		{"dns-split-too-many", with(map[string]any{"dns": map[string]any{"mode": "split", "domains": domains(33)}})},
		{"dns-domain-problems", with(map[string]any{"dns": map[string]any{"mode": "split", "domains": []string{"Corp.example.com", "*.example.com", "example", "example.com.", "corp.example.com", "corp.example.com", "-a.example.com"}}})},
		{"many-problems", `{"schema_version":0,"id":"","name":"","backend":"x","gateway":{"host":"","port":70000},"realm":"!","username":" ","trusted_cert":"z","mfa":{"mode":"none","digits":6},"routes":{"mode":"x","include":["1.2.3.4/7"]},"dns":{"mode":"x","domains":["A"]}}`},
		{"unknown-top-level", `{"schema_version":1,"password":"x"}`},
		{"unknown-case-alias", `{"schema_version":1,"ID":"work"}`},
		{"unknown-nested", `{"gateway":{"host":"vpn.example.com","path":"/"}}`},
		{"unknown-nested-quoted", `{"dns":{"mode":"none","dömains\"":[]}}`},
		{"duplicate-top-level", `{"id":"work","id":"home"}`},
		{"duplicate-escaped", `{"id":"work","id":"home"}`},
		{"duplicate-nested", `{"gateway":{"host":"a.example.com","host":"b.example.com"}}`},
		{"duplicate-before-unknown", `{"bogus":1,"bogus":2}`},
		{"null-top-level", `{"realm":null}`},
		{"null-in-list", `{"routes":{"mode":"custom","include":["10.0.0.0/8",null]}}`},
		{"null-nested-in-list", `{"routes":{"include":[[null]]}}`},
		{"top-level-array", `[]`},
		{"top-level-string", `"profile"`},
		{"trailing-object", `{} {}`},
		{"trailing-garbage", `{} x`},
	}
	cases := make([]profileCase, 0, len(inputs))
	for _, in := range inputs {
		c := profileCase{Name: in.name, Input: in.input}
		p, err := profile.Decode(bytes.NewReader([]byte(in.input)))
		switch {
		case err == nil:
			c.Profile = p
		default:
			if list, ok := flatten(err); ok {
				c.Errors = list
			} else {
				c.DecodeError = err.Error()
			}
		}
		cases = append(cases, c)
	}
	return cases, nil
}
