// Package profile decodes and validates bounded, secret-free VPN configuration.
// Invalid input returns decoding errors or joined, field-specific validation errors.
package profile

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Profile holds schema version 1 configuration, not credentials or executable options.
// Decode fills defaults; Validate reports all invalid fields without connecting to a VPN.
type Profile struct {
	SchemaVersion int     `json:"schema_version"`
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Backend       string  `json:"backend"`
	Gateway       Gateway `json:"gateway"`
	Realm         string  `json:"realm,omitempty"`
	Username      string  `json:"username"`
	TrustedCert   string  `json:"trusted_cert,omitempty"`
	MFA           MFA     `json:"mfa"`
	Routes        Routes  `json:"routes"`
	DNS           DNS     `json:"dns"`
}

// Gateway identifies a DNS host or IP literal and TLS port.
// Validate rejects addresses containing schemes, paths, ports, or invalid labels.
type Gateway struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// MFA selects a second-factor interaction without storing a seed or response.
// Pointer parameters distinguish omitted TOTP settings from explicitly invalid zero values.
type MFA struct {
	Mode      string  `json:"mode"`
	Digits    *int    `json:"digits,omitempty"`
	Period    *int    `json:"period,omitempty"`
	Algorithm *string `json:"algorithm,omitempty"`
}

// Routes specifies gateway, custom, or full routing with optional IPv4 prefixes.
// PreserveLAN uses a pointer so omission defaults to true while explicit false survives.
type Routes struct {
	Mode        string   `json:"mode"`
	Include     []string `json:"include,omitempty"`
	PreserveLAN *bool    `json:"preserve_lan"`
}

// DNS selects no managed DNS or split DNS for explicitly listed lowercase domains.
// Validate rejects invalid names, duplicates, or domains incompatible with the mode.
type DNS struct {
	Mode    string   `json:"mode"`
	Domains []string `json:"domains,omitempty"`
}

// ValidationError describes one invalid JSON field and the reason it is invalid.
// Validate joins these values so callers can inspect each failure through errors.As.
type ValidationError struct {
	Field   string
	Message string
}

// Error returns the JSON path followed by its validation message; it never fails.
func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

// Validation patterns restrict file identifiers, realms, and normalized certificate pins.
// They accept only the documented ASCII alphabets and do not perform normalization.
var (
	idPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	realmPattern = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)
	certPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ApplyDefaults fills omitted port, MFA, routing, and DNS settings in place.
// It preserves explicit false and TOTP values and never fails.
func (p *Profile) ApplyDefaults() {
	if p == nil {
		return
	}
	if p.Gateway.Port == 0 {
		p.Gateway.Port = 443
	}
	if p.MFA.Mode == "" {
		p.MFA.Mode = "none"
	}
	if p.MFA.Mode == "totp" {
		if p.MFA.Digits == nil {
			p.MFA.Digits = new(6)
		}
		if p.MFA.Period == nil {
			p.MFA.Period = new(30)
		}
		if p.MFA.Algorithm == nil {
			p.MFA.Algorithm = new("SHA1")
		}
	}
	if p.Routes.Mode == "" {
		p.Routes.Mode = "gateway"
	}
	if p.Routes.PreserveLAN == nil {
		p.Routes.PreserveLAN = new(true)
	}
	if p.DNS.Mode == "" {
		p.DNS.Mode = "none"
	}
}

// Validate checks a defaulted profile and returns every invalid field via errors.Join.
// It returns nil for valid profiles, reports nil receivers, and stores valid certificate
// pins in lowercase without colons. Other fields and invalid pins remain unchanged.
func (p *Profile) Validate() error {
	if p == nil {
		return &ValidationError{Field: "$", Message: "must be an object"}
	}
	var problems []error
	add := func(field, message string) {
		problems = append(problems, &ValidationError{Field: field, Message: message})
	}
	if p.SchemaVersion != 1 {
		add("schema_version", "must be 1")
	}
	if !idPattern.MatchString(p.ID) {
		add("id", "must match ^[a-z0-9][a-z0-9-]{0,62}$")
	}
	if !validText(p.Name, 1, 64) {
		add("name", "must be 1..64 characters with no control characters")
	}
	if p.Backend != "openfortivpn" {
		add("backend", "must be openfortivpn")
	}
	if addr, err := netip.ParseAddr(p.Gateway.Host); err != nil || addr.Zone() != "" {
		if !validDNSName(p.Gateway.Host) {
			add("gateway.host", "must be a DNS hostname or an unscoped IP literal")
		}
	}
	if p.Gateway.Port < 1 || p.Gateway.Port > 65535 {
		add("gateway.port", "must be 1..65535")
	}
	if utf8.RuneCountInString(p.Realm) > 64 || !realmPattern.MatchString(p.Realm) {
		add("realm", "must be at most 64 characters from A-Z, a-z, 0-9, dot, underscore, or hyphen")
	}
	if !validText(p.Username, 1, 256) || strings.TrimSpace(p.Username) != p.Username {
		add("username", "must be 1..256 characters without controls or whitespace at ends")
	}
	if p.TrustedCert != "" {
		normalized := strings.ToLower(strings.ReplaceAll(p.TrustedCert, ":", ""))
		if !certPattern.MatchString(normalized) {
			add("trusted_cert", "must be 64 lowercase hexadecimal characters")
		} else {
			// Normalize only valid pins so invalid separator-only input stays invalid.
			p.TrustedCert = normalized
		}
	}
	p.validateMFA(add)
	p.validateRoutes(add)
	p.validateDNS(add)
	return errors.Join(problems...)
}

// validateMFA appends each mode or parameter problem through add without mutating input.
// TOTP requires defaulted parameters; other modes forbid even explicit zero parameters.
func (p *Profile) validateMFA(add func(string, string)) {
	switch p.MFA.Mode {
	case "totp":
		if p.MFA.Digits == nil || (*p.MFA.Digits != 6 && *p.MFA.Digits != 8) {
			add("mfa.digits", "must be 6 or 8")
		}
		if p.MFA.Period == nil || *p.MFA.Period < 15 || *p.MFA.Period > 120 {
			add("mfa.period", "must be 15..120")
		}
		if p.MFA.Algorithm == nil || (*p.MFA.Algorithm != "SHA1" && *p.MFA.Algorithm != "SHA256" && *p.MFA.Algorithm != "SHA512") {
			add("mfa.algorithm", "must be SHA1, SHA256, or SHA512")
		}
	case "none", "push", "prompt", "static":
	default:
		add("mfa.mode", "must be none, push, prompt, totp, or static")
	}
	if p.MFA.Mode != "totp" {
		if p.MFA.Digits != nil {
			add("mfa.digits", "only allowed for totp")
		}
		if p.MFA.Period != nil {
			add("mfa.period", "only allowed for totp")
		}
		if p.MFA.Algorithm != nil {
			add("mfa.algorithm", "only allowed for totp")
		}
	}
}

// validateRoutes reports invalid routing modes and every malformed or conflicting prefix.
// Only canonical IPv4 prefixes of length 8..32 may be included in custom routing.
func (p *Profile) validateRoutes(add func(string, string)) {
	switch p.Routes.Mode {
	case "gateway", "full":
		if p.Routes.Include != nil {
			add("routes.include", "only allowed for custom")
		}
	case "custom":
		if len(p.Routes.Include) == 0 {
			add("routes.include", "custom requires a non-empty list")
		}
	default:
		add("routes.mode", "must be gateway, custom, or full")
	}
	prefixes := make([]netip.Prefix, 0, len(p.Routes.Include))
	for i, text := range p.Routes.Include {
		field := fmt.Sprintf("routes.include[%d]", i)
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Addr().Is4() {
			add(field, "must be an IPv4 CIDR")
			continue
		}
		if prefix != prefix.Masked() || prefix.String() != text {
			add(field, "must be a canonical masked prefix")
		}
		if prefix.Bits() < 8 {
			add(field, "prefixes /0 through /7 are too broad")
		}
		for _, previous := range prefixes {
			if prefix == previous {
				add(field, "duplicate prefix")
				break
			}
			if prefix.Overlaps(previous) {
				add(field, "overlaps another included prefix")
				break
			}
		}
		prefixes = append(prefixes, prefix)
	}
}

// validateDNS reports mode, list length, hostname, and duplicate errors through add.
// It treats domains as lowercase DNS names without trailing dots or wildcard labels.
func (p *Profile) validateDNS(add func(string, string)) {
	switch p.DNS.Mode {
	case "none":
		if p.DNS.Domains != nil {
			add("dns.domains", "only allowed for split")
		}
	case "split":
		if len(p.DNS.Domains) < 1 || len(p.DNS.Domains) > 32 {
			add("dns.domains", "split requires 1..32 domains")
		}
	default:
		add("dns.mode", "must be none or split")
	}
	seen := make(map[string]bool, len(p.DNS.Domains))
	for i, domain := range p.DNS.Domains {
		field := fmt.Sprintf("dns.domains[%d]", i)
		if !validDNSName(domain) || strings.ToLower(domain) != domain {
			add(field, "must be a lowercase DNS name without trailing dot or wildcard")
		}
		if seen[domain] {
			add(field, "duplicate domain")
		}
		seen[domain] = true
	}
}

// validText accepts valid UTF-8 with min..max Unicode characters and no control runes.
// It returns false for malformed encoding, out-of-range lengths, or controls.
func validText(text string, min, max int) bool {
	count := utf8.RuneCountInString(text)
	return utf8.ValidString(text) && count >= min && count <= max && !strings.ContainsFunc(text, unicode.IsControl)
}

// validDNSName checks an ASCII DNS name's total length and LDH label boundaries.
// It returns false for schemes, ports, paths, empty labels, trailing dots, or wildcards.
func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}
