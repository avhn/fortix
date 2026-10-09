package main

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/avhn/fortix/internal/profile"
)

// shareFile is the share-format.json document covering export, parse, and completion.
type shareFile struct {
	Export   []exportCase   `json:"export"`
	Parse    []parseCase    `json:"parse"`
	Complete []completeCase `json:"complete"`
}

// shareFailure records either a ShareError or a list of validation errors, never both.
type shareFailure struct {
	Kind    string       `json:"kind,omitempty"`
	Field   string       `json:"field,omitempty"`
	Message string       `json:"message,omitempty"`
	Errors  []fieldError `json:"errors,omitempty"`
}

// exportCase exports Profiles, given as plain JSON objects, to an exact Document or an error.
type exportCase struct {
	Name     string            `json:"name"`
	Profiles []json.RawMessage `json:"profiles"`
	Document string            `json:"document,omitempty"`
	Error    *shareFailure     `json:"error,omitempty"`
}

// parseCase parses Document into drafts with their missing fields, or records the failure.
type parseCase struct {
	Name     string          `json:"name"`
	Document string          `json:"document"`
	Drafts   []profile.Draft `json:"drafts,omitempty"`
	Missing  [][]string      `json:"missing,omitempty"`
	Error    *shareFailure   `json:"error,omitempty"`
}

// completeCase completes the first draft of Document with Username and ID overrides.
type completeCase struct {
	Name     string           `json:"name"`
	Document string           `json:"document"`
	Username string           `json:"username"`
	ID       string           `json:"id"`
	Profile  *profile.Profile `json:"profile,omitempty"`
	Error    *shareFailure    `json:"error,omitempty"`
}

// failure converts a share or validation error to its vector form.
func failure(err error) (*shareFailure, error) {
	var shareErr *profile.ShareError
	if errors.As(err, &shareErr) {
		return &shareFailure{Kind: shareErr.Kind, Field: shareErr.Field, Message: shareErr.Message}, nil
	}
	if list, ok := flatten(err); ok {
		return &shareFailure{Errors: list}, nil
	}
	return nil, err
}

// document wraps raw profile objects in a version 1 share document.
func document(profiles ...string) string {
	return `{"format":"fortix-profile","version":1,"profiles":[` + strings.Join(profiles, ",") + `]}`
}

// shareVectors runs the production share functions over fixed inputs.
func shareVectors() (any, error) {
	var file shareFile
	pin := strings.Repeat("Ab:", 31) + "Ab"
	exports := []struct {
		name     string
		profiles []string
	}{
		{"single", []string{with(map[string]any{"backend": "native", "mfa": map[string]any{"mode": "none"}, "routes": map[string]any{"mode": "gateway", "preserve_lan": true}, "dns": map[string]any{"mode": "none"}})}},
		{"normalizes", []string{with(map[string]any{"name": "Büro <&> \u2028", "trusted_cert": pin, "realm": "corp", "backend": "native", "mfa": map[string]any{"mode": "none"},
			"routes": map[string]any{"mode": "full", "exclude": []string{" 192.0.2.7/24 "}, "preserve_lan": false}, "dns": map[string]any{"mode": "split", "domains": []string{"*.Corp.Example.com"}}})}},
		{"several", []string{
			with(map[string]any{"id": "one", "backend": "openfortivpn", "mfa": map[string]any{"mode": "totp", "digits": 6, "period": 30, "algorithm": "SHA1"}, "routes": map[string]any{"mode": "custom", "include": []string{"10.1.2.3/16"}, "preserve_lan": true}, "dns": map[string]any{"mode": "none"}}),
			with(map[string]any{"id": "two", "backend": "native", "mfa": map[string]any{"mode": "none"}, "routes": map[string]any{"mode": "gateway", "preserve_lan": true}, "dns": map[string]any{"mode": "none"}}),
		}},
		{"missing-preserve-lan", []string{with(map[string]any{"backend": "native", "mfa": map[string]any{"mode": "none"}, "routes": map[string]any{"mode": "gateway"}, "dns": map[string]any{"mode": "none"}})}},
		{"invalid", []string{with(map[string]any{"name": "", "mfa": map[string]any{"mode": "none"}, "routes": map[string]any{"mode": "gateway"}, "dns": map[string]any{"mode": "none"}})}},
		{"duplicate-id", []string{
			with(map[string]any{"backend": "native", "mfa": map[string]any{"mode": "none"}, "routes": map[string]any{"mode": "gateway"}, "dns": map[string]any{"mode": "none"}}),
			with(map[string]any{"backend": "native", "mfa": map[string]any{"mode": "none"}, "routes": map[string]any{"mode": "gateway"}, "dns": map[string]any{"mode": "none"}}),
		}},
		{"empty", nil},
	}
	for _, e := range exports {
		c := exportCase{Name: e.name, Profiles: []json.RawMessage{}}
		profiles := make([]profile.Profile, 0, len(e.profiles))
		for _, text := range e.profiles {
			var p profile.Profile
			if err := json.Unmarshal([]byte(text), &p); err != nil {
				return nil, err
			}
			profiles = append(profiles, p)
			c.Profiles = append(c.Profiles, json.RawMessage(text))
		}
		data, err := profile.Export(profiles...)
		if err != nil {
			if c.Error, err = failure(err); err != nil {
				return nil, err
			}
		} else {
			c.Document = string(data)
		}
		file.Export = append(file.Export, c)
	}
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = `{}`
	}
	parses := []struct{ name, document string }{
		{"empty-draft", document(`{}`)},
		{"partial", document(`{"name":"Office","gateway":{"host":"vpn.example.com"}}`)},
		{"full", document(`{"schema_version":1,"id":"work","name":"Work","backend":"native","gateway":{"host":"vpn.example.com","port":443},"realm":"corp","trusted_cert":"` + pin + `","mfa":{"mode":"none"},"routes":{"mode":"full","exclude":[" 192.0.2.7/24"],"preserve_lan":false},"dns":{"mode":"split","domains":["*.Corp.example.com"]}}`)},
		{"custom-needs-include", document(`{"routes":{"mode":"custom"},"dns":{"mode":"split"}}`)},
		{"list-implies-mode", document(`{"routes":{"include":["10.0.0.0/8"]},"dns":{"domains":["corp.example.com"]}}`)},
		{"totp-parameters-only", document(`{"mfa":{"digits":8}}`)},
		{"explicit-empty-lists", document(`{"routes":{"mode":"gateway","exclude":[]},"dns":{"mode":"none","domains":[]}}`)},
		{"two-profiles", document(`{"id":"a"}`, `{"id":"b"}`)},
		{"whitespace", "  \n" + document(`{"id":"a"}`) + "\n\t "},
		{"secret-key", document(`{"id":"a","Password":"x"}`)},
		{"secret-nested", document(`{"gateway":{"token":"x"}}`)},
		{"secret-top-level", `{"format":"fortix-profile","version":1,"profiles":[{}],"cookie":"x"}`},
		{"secret-after-duplicate", document(`{"id":"a","id":"b","otp":"1"}`)},
		{"secret-after-null", document(`{"id":null,"svpncookie":"1"}`)},
		{"secret-in-array", document(`{"routes":{"include":[{"credentials":1}]}}`)},
		{"duplicate-key", document(`{"id":"a","id":"b"}`)},
		{"null", document(`{"id":null}`)},
		{"null-in-list", document(`{"dns":{"domains":[null]}}`)},
		{"trailing", document(`{}`) + " {}"},
		{"invalid-json", `{"format":`},
		{"not-object", `[]`},
		{"unknown-top-level", `{"format":"fortix-profile","version":1,"profiles":[{}],"extra":1}`},
		{"username-forbidden", document(`{"username":"alice"}`)},
		{"unknown-profile-field", document(`{"color":"blue"}`)},
		{"unknown-nested-field", document(`{"gateway":{"host":"a.example.com","path":"/"}}`)},
		{"nested-not-object", document(`{"gateway":"a.example.com"}`)},
		{"profile-not-object", document(`"a"`)},
		{"profiles-not-array", `{"format":"fortix-profile","version":1,"profiles":{}}`},
		{"wrong-format", `{"format":"other","version":1,"profiles":[{}]}`},
		{"missing-format", `{"version":1,"profiles":[{}]}`},
		{"format-not-string", `{"format":1,"version":1,"profiles":[{}]}`},
		{"wrong-version", `{"format":"fortix-profile","version":2,"profiles":[{}]}`},
		{"fractional-version", `{"format":"fortix-profile","version":1.0,"profiles":[{}]}`},
		{"missing-profiles", `{"format":"fortix-profile","version":1}`},
		{"zero-profiles", document()},
		{"too-many-profiles", document(tooMany...)},
		{"field-type", document(`{"id":5}`)},
		{"port-fraction", document(`{"gateway":{"port":443.5}}`)},
		{"duplicate-id", document(`{"id":"a"}`, `{"id":"a"}`)},
		{"invalid-supplied", document(`{"id":"Bad","name":"","gateway":{"port":0},"routes":{"include":["10.0.0.1/8","2001:db8::/32"]},"dns":{"domains":["bad"]}}`)},
		{"invalid-mfa", document(`{"backend":"native","mfa":{"mode":"push"}}`)},
		{"exclude-openfortivpn", document(`{"backend":"openfortivpn","routes":{"exclude":["192.0.2.0/24"]}}`)},
		{"exclude-implied-backend", document(`{"mfa":{"mode":"push"},"routes":{"exclude":["192.0.2.0/24"]}}`)},
	}
	for _, p := range parses {
		c := parseCase{Name: p.name, Document: p.document}
		drafts, err := profile.Parse([]byte(p.document))
		if err != nil {
			if c.Error, err = failure(err); err != nil {
				return nil, err
			}
		} else {
			c.Drafts = drafts
			for _, d := range drafts {
				c.Missing = append(c.Missing, d.Missing())
			}
		}
		file.Parse = append(file.Parse, c)
	}
	completes := []struct{ name, document, username, id string }{
		{"defaults", document(`{"name":"Office","gateway":{"host":"vpn.example.com"}}`), "alice", "office"},
		{"shared-id", document(`{"id":"work","name":"Work","gateway":{"host":"vpn.example.com"},"mfa":{"mode":"totp"}}`), "alice", ""},
		{"override-id", document(`{"id":"work","name":"Work","gateway":{"host":"vpn.example.com"}}`), "alice", "home"},
		{"missing-username", document(`{"id":"work","name":"Work","gateway":{"host":"vpn.example.com"}}`), "", ""},
		{"missing-fields", document(`{}`), "alice", ""},
		{"explicit-port-zero", document(`{"id":"work","name":"Work","gateway":{"host":"vpn.example.com","port":0}}`), "alice", ""},
		{"empty-mode", document(`{"id":"work","name":"Work","gateway":{"host":"vpn.example.com"},"routes":{"mode":""}}`), "alice", ""},
	}
	for _, p := range completes {
		c := completeCase{Name: p.name, Document: p.document, Username: p.username, ID: p.id}
		drafts, err := profile.Parse([]byte(p.document))
		if err != nil {
			// Parse rejects explicit invalid values; completion vectors record that rejection.
			if c.Error, err = failure(err); err != nil {
				return nil, err
			}
			file.Complete = append(file.Complete, c)
			continue
		}
		completed, err := profile.Complete(drafts[0], p.username, p.id)
		if err != nil {
			if c.Error, err = failure(err); err != nil {
				return nil, err
			}
		} else {
			c.Profile = &completed
		}
		file.Complete = append(file.Complete, c)
	}
	return file, nil
}
