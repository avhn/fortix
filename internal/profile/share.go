// Package profile supports bounded, secret-free configuration exchange without personal fields.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"
)

// Share limits bound the entire encoded document, including whitespace, and profile count.
const (
	maxShareBytes     = 1 << 20
	maxSharedProfiles = 32
)

// ShareError identifies a rejected shared document without including any input values.
// Kind is json, size, format, version, count, field, duplicate_key, duplicate_id, or secret.
// Field identifies a schema field or a forbidden key; Message describes the failure.
// Invalid supplied profile values instead return inspectable ValidationError values.
type ShareError struct {
	Kind    string
	Field   string
	Message string
}

// Error returns the rejected field and a fixed explanation, never a supplied field value.
func (e *ShareError) Error() string { return e.Field + ": " + e.Message }

// Draft holds optional shared fields; nil means absent and non-nil means explicitly supplied.
// Username is deliberately unavailable so shared documents cannot overwrite personal identity.
// Parse validates supplied values without filling absent fields. Complete fills defaults.
type Draft struct {
	SchemaVersion *int          `json:"schema_version,omitempty"`
	ID            *string       `json:"id,omitempty"`
	Name          *string       `json:"name,omitempty"`
	Backend       *string       `json:"backend,omitempty"`
	Gateway       *DraftGateway `json:"gateway,omitempty"`
	Realm         *string       `json:"realm,omitempty"`
	TrustedCert   *string       `json:"trusted_cert,omitempty"`
	MFA           *DraftMFA     `json:"mfa,omitempty"`
	Routes        *DraftRoutes  `json:"routes,omitempty"`
	DNS           *DraftDNS     `json:"dns,omitempty"`
}

// DraftGateway preserves independent presence of host and port for partial gateway updates.
// A nil host requires local completion; an omitted port defaults to 443 in Complete.
type DraftGateway struct {
	Host *string `json:"host,omitempty"`
	Port *int    `json:"port,omitempty"`
}

// DraftMFA preserves mode and each optional TOTP parameter independently.
// Omitted parameters may receive defaults in Complete, but supplied invalid values fail Parse.
type DraftMFA struct {
	Mode      *string `json:"mode,omitempty"`
	Digits    *int    `json:"digits,omitempty"`
	Period    *int    `json:"period,omitempty"`
	Algorithm *string `json:"algorithm,omitempty"`
}

// DraftRoutes preserves routing mode, complete prefix-list presence, and explicit false.
// A supplied Include replaces the base list, including when it is explicitly empty.
type DraftRoutes struct {
	Mode        *string   `json:"mode,omitempty"`
	Include     *[]string `json:"include,omitempty"`
	PreserveLAN *bool     `json:"preserve_lan,omitempty"`
}

// DraftDNS preserves DNS mode and complete domain-list presence independently.
// A supplied Domains replaces the base list rather than appending to it.
type DraftDNS struct {
	Mode    *string   `json:"mode,omitempty"`
	Domains *[]string `json:"domains,omitempty"`
}

// sharedDocument keeps the format marker, exchange version, and ordered drafts stable on export.
// Per-profile schema versions remain independent of the document version.
type sharedDocument struct {
	Format   string  `json:"format"`
	Version  int     `json:"version"`
	Profiles []Draft `json:"profiles"`
}

// Export validates independent copies of profiles and returns indented JSON with a final newline.
// It preserves profile order and schema versions, canonicalizes domains and route prefixes,
// and never writes username. Invalid profiles, duplicate IDs, and size/count limits fail.
func Export(profiles ...Profile) ([]byte, error) {
	if len(profiles) < 1 || len(profiles) > maxSharedProfiles {
		return nil, &ShareError{Kind: "count", Field: "profiles", Message: "must contain 1..32 profiles"}
	}
	doc := sharedDocument{Format: "fortix-profile", Version: 1, Profiles: make([]Draft, 0, len(profiles))}
	seen := make(map[string]bool, len(profiles))
	for _, original := range profiles {
		// Normalize private copies so export cannot change the caller's slices or certificate pin.
		p := draftFromProfile(original).Apply(original)
		if err := p.Validate(); err != nil {
			return nil, err
		}
		if seen[p.ID] {
			return nil, &ShareError{Kind: "duplicate_id", Field: "profiles.id", Message: "duplicate profile id"}
		}
		seen[p.ID] = true
		doc.Profiles = append(doc.Profiles, draftFromProfile(p))
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > maxShareBytes {
		return nil, &ShareError{Kind: "size", Field: "$", Message: "exceeds 1 MiB limit"}
	}
	return data, nil
}

// Parse checks a UTF-8 document of at most 1 MiB and returns 1..32 validated partial drafts.
// A raw token pass rejects forbidden keys at any depth before schema decoding and never
// echoes their values. Unknown fields, nulls, duplicate keys/IDs, and invalid supplied
// fields fail; absent fields remain absent and are reported by each draft's Missing method.
func Parse(data []byte) ([]Draft, error) {
	if len(data) > maxShareBytes {
		return nil, &ShareError{Kind: "size", Field: "$", Message: "exceeds 1 MiB limit"}
	}
	if !utf8.Valid(data) {
		return nil, &ShareError{Kind: "json", Field: "$", Message: "invalid UTF-8"}
	}
	if err := scanSharedJSON(data); err != nil {
		return nil, err
	}
	fields := map[string]bool{"format": true, "version": true, "profiles": true}
	if err := checkSharedObject(data, fields); err != nil {
		return nil, err
	}
	var raw struct {
		Format   json.RawMessage   `json:"format"`
		Version  json.RawMessage   `json:"version"`
		Profiles []json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &ShareError{Kind: "json", Field: "$", Message: "invalid document field type"}
	}
	var format string
	if err := json.Unmarshal(raw.Format, &format); err != nil || format != "fortix-profile" {
		return nil, &ShareError{Kind: "format", Field: "format", Message: "must be fortix-profile"}
	}
	var version int
	if err := json.Unmarshal(raw.Version, &version); err != nil || version != 1 {
		return nil, &ShareError{Kind: "version", Field: "version", Message: "must be 1"}
	}
	if len(raw.Profiles) < 1 || len(raw.Profiles) > maxSharedProfiles {
		return nil, &ShareError{Kind: "count", Field: "profiles", Message: "must contain 1..32 profiles"}
	}
	drafts := make([]Draft, 0, len(raw.Profiles))
	seen := make(map[string]bool, len(raw.Profiles))
	for _, value := range raw.Profiles {
		if err := checkSharedObject(value, objectFields["$"]); err != nil {
			return nil, err
		}
		var d Draft
		if err := json.Unmarshal(value, &d); err != nil {
			return nil, &ShareError{Kind: "json", Field: "profiles", Message: "invalid profile field type"}
		}
		d.normalize()
		if err := d.validate(); err != nil {
			return nil, err
		}
		if d.ID != nil {
			if seen[*d.ID] {
				return nil, &ShareError{Kind: "duplicate_id", Field: "profiles.id", Message: "duplicate profile id"}
			}
			seen[*d.ID] = true
		}
		drafts = append(drafts, d)
	}
	return drafts, nil
}

// Missing returns required absent fields in schema order, always including username.
// Fields supplied by Complete defaults (including schema_version and TOTP parameters)
// are excluded. Explicit custom/split modes additionally require their absent lists.
// Invalid present values are not missing; Parse or Complete reports their validation errors.
func (d Draft) Missing() []string {
	var fields []string
	if d.ID == nil {
		fields = append(fields, "id")
	}
	if d.Name == nil {
		fields = append(fields, "name")
	}
	if d.Gateway == nil || d.Gateway.Host == nil {
		fields = append(fields, "gateway.host")
	}
	fields = append(fields, "username")
	if d.Routes != nil && d.Routes.Mode != nil && *d.Routes.Mode == "custom" && d.Routes.Include == nil {
		fields = append(fields, "routes.include")
	}
	if d.DNS != nil && d.DNS.Mode != nil && *d.DNS.Mode == "split" && d.DNS.Domains == nil {
		fields = append(fields, "dns.domains")
	}
	return fields
}

// Apply overlays only present fields onto an independent copy of base and keeps its username.
// Routes.Include and DNS.Domains replace entire lists, not append; other nested fields
// merge independently. Domains and prefixes are canonicalized, but no defaults or validation
// are performed, so the caller must Validate a completed result before storing it.
func (d Draft) Apply(base Profile) Profile {
	p := cloneSharedProfile(base)
	if d.SchemaVersion != nil {
		p.SchemaVersion = *d.SchemaVersion
	}
	if d.ID != nil {
		p.ID = *d.ID
	}
	if d.Name != nil {
		p.Name = *d.Name
	}
	if d.Backend != nil {
		p.Backend = *d.Backend
	}
	if d.Gateway != nil {
		if d.Gateway.Host != nil {
			p.Gateway.Host = *d.Gateway.Host
		}
		if d.Gateway.Port != nil {
			p.Gateway.Port = *d.Gateway.Port
		}
	}
	if d.Realm != nil {
		p.Realm = *d.Realm
	}
	if d.TrustedCert != nil {
		p.TrustedCert = *d.TrustedCert
	}
	if d.MFA != nil {
		if d.MFA.Mode != nil {
			p.MFA.Mode = *d.MFA.Mode
		}
		if d.MFA.Digits != nil {
			p.MFA.Digits = cloneSharedPointer(d.MFA.Digits)
		}
		if d.MFA.Period != nil {
			p.MFA.Period = cloneSharedPointer(d.MFA.Period)
		}
		if d.MFA.Algorithm != nil {
			p.MFA.Algorithm = cloneSharedPointer(d.MFA.Algorithm)
		}
	}
	if d.Routes != nil {
		if d.Routes.Mode != nil {
			p.Routes.Mode = *d.Routes.Mode
		}
		if d.Routes.Include != nil {
			p.Routes.Include = slices.Clone(*d.Routes.Include)
			for i, text := range p.Routes.Include {
				p.Routes.Include[i] = normalizeSharedPrefix(text)
			}
		}
		if d.Routes.PreserveLAN != nil {
			p.Routes.PreserveLAN = cloneSharedPointer(d.Routes.PreserveLAN)
		}
	}
	if d.DNS != nil {
		if d.DNS.Mode != nil {
			p.DNS.Mode = *d.DNS.Mode
		}
		if d.DNS.Domains != nil {
			p.DNS.Domains = slices.Clone(*d.DNS.Domains)
			for i, domain := range p.DNS.Domains {
				p.DNS.Domains[i] = NormalizeDomain(domain)
			}
		}
	}
	return p
}

// Complete overlays d onto a zero profile, fills standard defaults and schema version 1,
// and sets non-empty username and id arguments before validating the result. A supplied id
// overrides the shared id. Explicit invalid draft values are never replaced by defaults.
// It returns a zero Profile on validation failure and never changes d or stores credentials.
func Complete(d Draft, username string, id string) (Profile, error) {
	p := d.Apply(Profile{SchemaVersion: 1})
	p.ApplyDefaults()
	// Reapply presence after defaulting: explicit zero ports and empty modes must stay invalid.
	p = d.Apply(p)
	if username != "" {
		p.Username = username
	}
	if id != "" {
		p.ID = id
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// validate reuses full-profile rules but retains errors only for fields present in d.
// Missing modes use compatible temporary modes for independent parameter/list validation;
// those temporary choices do not become draft fields or Complete defaults.
func (d Draft) validate() error {
	p := d.Apply(Profile{SchemaVersion: 1})
	if d.MFA != nil && d.MFA.Mode == nil && (d.MFA.Digits != nil || d.MFA.Period != nil || d.MFA.Algorithm != nil) {
		p.MFA.Mode = "totp"
	}
	if d.Routes != nil && d.Routes.Mode == nil && d.Routes.Include != nil {
		p.Routes.Mode = "custom"
	}
	if d.DNS != nil && d.DNS.Mode == nil && d.DNS.Domains != nil {
		p.DNS.Mode = "split"
	}
	p.ApplyDefaults()
	p = d.Apply(p)
	return d.presentErrors(p.Validate())
}

// presentErrors filters the joined validation tree by exact draft field presence.
// It preserves each ValidationError and its existing full-profile message unchanged.
func (d Draft) presentErrors(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var problems []error
		for _, child := range joined.Unwrap() {
			if kept := d.presentErrors(child); kept != nil {
				problems = append(problems, kept)
			}
		}
		return errors.Join(problems...)
	}
	var problem *ValidationError
	if errors.As(err, &problem) && d.hasField(problem.Field) {
		return err
	}
	return nil
}

// hasField reports optional-field presence for a validation path, including list elements.
// It ignores username because personal fields cannot be represented by a Draft.
func (d Draft) hasField(field string) bool {
	switch field {
	case "schema_version":
		return d.SchemaVersion != nil
	case "id":
		return d.ID != nil
	case "name":
		return d.Name != nil
	case "backend":
		return d.Backend != nil
	case "gateway.host":
		return d.Gateway != nil && d.Gateway.Host != nil
	case "gateway.port":
		return d.Gateway != nil && d.Gateway.Port != nil
	case "realm":
		return d.Realm != nil
	case "trusted_cert":
		return d.TrustedCert != nil
	case "mfa.mode":
		return d.MFA != nil && d.MFA.Mode != nil
	case "mfa.digits":
		return d.MFA != nil && d.MFA.Digits != nil
	case "mfa.period":
		return d.MFA != nil && d.MFA.Period != nil
	case "mfa.algorithm":
		return d.MFA != nil && d.MFA.Algorithm != nil
	case "routes.mode":
		return d.Routes != nil && d.Routes.Mode != nil
	case "dns.mode":
		return d.DNS != nil && d.DNS.Mode != nil
	}
	if field == "routes.include" || strings.HasPrefix(field, "routes.include[") {
		return d.Routes != nil && d.Routes.Include != nil
	}
	if field == "dns.domains" || strings.HasPrefix(field, "dns.domains[") {
		return d.DNS != nil && d.DNS.Domains != nil
	}
	return false
}

// normalize canonicalizes present lists and valid certificate pins without filling omissions.
// Invalid values remain available for the existing field-level validator to reject.
func (d *Draft) normalize() {
	if d.Routes != nil && d.Routes.Include != nil {
		for i, text := range *d.Routes.Include {
			(*d.Routes.Include)[i] = normalizeSharedPrefix(text)
		}
	}
	if d.DNS != nil && d.DNS.Domains != nil {
		for i, domain := range *d.DNS.Domains {
			(*d.DNS.Domains)[i] = NormalizeDomain(domain)
		}
	}
	if d.TrustedCert != nil {
		pin := strings.ToLower(strings.ReplaceAll(*d.TrustedCert, ":", ""))
		if certPattern.MatchString(pin) {
			d.TrustedCert = new(pin)
		}
	}
}

// normalizeSharedPrefix trims surrounding whitespace and masks valid prefix host bits.
// It leaves malformed CIDRs invalid and does not relax IPv4 or minimum-prefix-length rules.
func normalizeSharedPrefix(text string) string {
	text = strings.TrimSpace(text)
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked().String()
	}
	return text
}

// cloneSharedPointer copies an optional scalar so callers can change results independently.
// A nil pointer remains nil rather than introducing a supplied value.
func cloneSharedPointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	return new(*value)
}

// cloneSharedProfile copies mutable fields without changing any values in the base.
// It retains nil versus explicitly empty lists and never changes the source profile.
func cloneSharedProfile(p Profile) Profile {
	p.MFA.Digits = cloneSharedPointer(p.MFA.Digits)
	p.MFA.Period = cloneSharedPointer(p.MFA.Period)
	p.MFA.Algorithm = cloneSharedPointer(p.MFA.Algorithm)
	p.Routes.PreserveLAN = cloneSharedPointer(p.Routes.PreserveLAN)
	p.Routes.Include = slices.Clone(p.Routes.Include)
	p.DNS.Domains = slices.Clone(p.DNS.Domains)
	return p
}

// draftFromProfile converts validated configuration to a draft without any personal fields.
// Optional empty scalars and nil lists stay omitted, matching Profile's JSON field semantics.
func draftFromProfile(p Profile) Draft {
	d := Draft{SchemaVersion: new(p.SchemaVersion), ID: new(p.ID), Name: new(p.Name),
		Gateway: &DraftGateway{Host: new(p.Gateway.Host), Port: new(p.Gateway.Port)},
		MFA:     &DraftMFA{Mode: new(p.MFA.Mode), Digits: p.MFA.Digits, Period: p.MFA.Period, Algorithm: p.MFA.Algorithm},
		Routes:  &DraftRoutes{Mode: new(p.Routes.Mode), PreserveLAN: p.Routes.PreserveLAN},
		DNS:     &DraftDNS{Mode: new(p.DNS.Mode)}}
	if p.Backend != "" {
		d.Backend = new(p.Backend)
	}
	if p.Realm != "" {
		d.Realm = new(p.Realm)
	}
	if p.TrustedCert != "" {
		d.TrustedCert = new(p.TrustedCert)
	}
	if p.Routes.Include != nil {
		d.Routes.Include = new(p.Routes.Include)
	}
	if p.DNS.Domains != nil {
		d.DNS.Domains = new(p.DNS.Domains)
	}
	return d
}

// scanSharedJSON inspects raw JSON tokens before any typed decoding, including unknown objects.
// Secret keys take precedence over remembered duplicate/null errors, so overwritten objects
// cannot hide credentials. Trailing data and malformed input return fixed, value-free errors.
func scanSharedJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var problem error
	if err := scanSharedValue(decoder, &problem); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return &ShareError{Kind: "json", Field: "$", Message: "trailing data after document"}
	}
	return problem
}

// scanSharedValue consumes one raw value and recursively checks keys in objects and arrays.
// It remembers structural ambiguity while searching all values for forbidden secret keys.
func scanSharedValue(decoder *json.Decoder, problem *error) error {
	token, err := decoder.Token()
	if err != nil {
		return &ShareError{Kind: "json", Field: "$", Message: "invalid JSON"}
	}
	if token == nil && *problem == nil {
		*problem = &ShareError{Kind: "field", Field: "$", Message: "null is not allowed"}
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return &ShareError{Kind: "json", Field: "$", Message: "invalid JSON"}
			}
			key, ok := keyToken.(string)
			if !ok {
				return &ShareError{Kind: "json", Field: "$", Message: "expected object key"}
			}
			lower := strings.ToLower(key)
			switch lower {
			case "password", "passwd", "credential", "credentials", "secret", "token", "otp", "cookie", "svpncookie":
				return &ShareError{Kind: "secret", Field: lower, Message: "secret fields are forbidden"}
			}
			if seen[key] && *problem == nil {
				*problem = &ShareError{Kind: "duplicate_key", Field: "$", Message: "duplicate object key"}
			}
			seen[key] = true
			if err := scanSharedValue(decoder, problem); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return &ShareError{Kind: "json", Field: "$", Message: "invalid JSON"}
		}
	case json.Delim('['):
		for decoder.More() {
			if err := scanSharedValue(decoder, problem); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return &ShareError{Kind: "json", Field: "$", Message: "invalid JSON"}
		}
	}
	return nil
}

// checkSharedObject enforces exact schema keys and object shapes after the raw security pass.
// Username is excluded even though it is valid in personal profiles; nested objects reuse
// the existing schema key catalog. Errors identify only known fields, never supplied values.
func checkSharedObject(data []byte, fields map[string]bool) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return &ShareError{Kind: "field", Field: "$", Message: "must be an object"}
	}
	for key, value := range object {
		if !fields[key] || key == "username" {
			return &ShareError{Kind: "field", Field: "$", Message: "unknown field in shared configuration"}
		}
		if nested, ok := objectFields["$."+key]; ok {
			if err := checkSharedObject(value, nested); err != nil {
				return err
			}
		}
	}
	return nil
}
