package profile

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestBackendDefaults verifies omission resolves only after MFA is defaulted and that
// explicit backend choices survive defaulting, serialization, and decoding.
func TestBackendDefaults(t *testing.T) {
	for _, mode := range []string{"", "none", "push", "prompt", "totp", "static"} {
		for _, selected := range []string{"", "native", "openfortivpn"} {
			t.Run(mode+"/"+selected, func(t *testing.T) {
				p := validProfile(t)
				p.Backend, p.MFA = selected, MFA{Mode: mode}
				p.ApplyDefaults()
				want := selected
				if want == "" {
					want = "openfortivpn"
					if mode == "" || mode == "none" {
						want = "native"
					}
				}
				if p.Backend != want {
					t.Fatalf("backend = %q, want %q", p.Backend, want)
				}
				invalid := want == "native" && p.MFA.Mode != "none"
				if err := p.Validate(); (err != nil) != invalid || (invalid && !hasField(err, "backend")) {
					t.Fatalf("validate = %v, invalid = %v", err, invalid)
				}
				data, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := Decode(bytes.NewReader(data))
				if (err != nil) != invalid || (!invalid && decoded.Backend != want) {
					t.Fatalf("decode = %+v, %v", decoded, err)
				}
				p.ApplyDefaults()
				if p.Backend != want {
					t.Fatal("defaulting changed an explicit backend")
				}
			})
		}
	}
}

// TestOmittedBackendWire verifies omitted and empty backend values decode consistently,
// while null, duplicate, unknown, and case-aliased backend fields remain rejected.
func TestOmittedBackendWire(t *testing.T) {
	minimal := `{"schema_version":1,"id":"work","name":"Work","gateway":{"host":"vpn.example.com"},"username":"jane.doe"}`
	for _, tc := range []struct {
		name, fields, want string
		invalid            bool
	}{
		{"omitted", "", "native", false},
		{"empty", `"backend":"",`, "native", false},
		{"omitted push", `"mfa":{"mode":"push"},`, "openfortivpn", false},
		{"native", `"backend":"native",`, "native", false},
		{"external", `"backend":"openfortivpn",`, "openfortivpn", false},
		{"native push", `"backend":"native","mfa":{"mode":"push"},`, "", true},
		{"unknown", `"backend":"other",`, "", true},
		{"null", `"backend":null,`, "", true},
		{"duplicate", `"backend":"native","backend":"openfortivpn",`, "", true},
		{"case alias", `"Backend":"native",`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Decode(strings.NewReader(strings.Replace(minimal, "{", "{"+tc.fields, 1)))
			if (err != nil) != tc.invalid || (!tc.invalid && p.Backend != tc.want) {
				t.Fatalf("decode = %+v, %v", p, err)
			}
		})
	}
	p := validProfile(t)
	p.Backend = ""
	data, err := json.Marshal(p)
	if err != nil || bytes.Contains(data, []byte(`"backend"`)) {
		t.Fatalf("omitted backend serialized: %s, %v", data, err)
	}
}
