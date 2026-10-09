package openfortivpn

import (
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

// Parser bounds limit structured line parsing and accumulated certificate metadata.
// Larger or malformed lines remain Unknown rather than changing connection state.
const (
	maxOutputLine = 64 * 1024
	maxCertText   = 16 * 1024
	certStart     = "Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:"
	authFailure   = "Could not authenticate to gateway. Please check the password, client certificate, etc."
	tunnelDenied  = "Could not authenticate to the gateway. Please make sure tunnel mode is allowed by the gateway, check the realm, etc."
)

// addressLine matches the exact bracket layout emitted for IPv4 and gateway DNS.
// Gateway suffix text is unvalidated and ends at the final bracket, even with brackets
// or controls inside it. Invalid suffixes must not discard otherwise usable addresses.
var addressLine = regexp.MustCompile(`^Got addresses: \[([^\[\]]+)\], ns \[([^\[\]]*)\](?:, ns_suffix \[((?s:.*))\])?$`)

// Parser retains only a bounded certificate block between Parse calls.
// Its zero value is ready for one output stream; streams and attempts need separate parsers.
type Parser struct {
	cert    *CertRejected
	section string
}

// Parse classifies one stdout or stderr line, emitting zero or more typed observations.
// It accepts an optional LF or CRLF terminator. Exact severity spacing is required.
// Certificate lines accumulate until the final digest or a block boundary; unknown
// lines are preserved. It does no I/O and reports malformed data as Unknown.
func (p *Parser) Parse(line string) []Event {
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	level, text := splitPrefix(line)
	var events []Event
	if p.cert != nil {
		if level == "ERROR" && len(line) <= maxOutputLine && p.collectCertificate(text) {
			if p.section == "done" {
				return p.Flush()
			}
			return nil
		}
		// Do not swallow the first normal line following a truncated certificate block.
		events = p.Flush()
	}
	if len(line) > maxOutputLine {
		return append(events, Unknown{Line: line})
	}
	if level == "ERROR" && text == certStart {
		p.cert = &CertRejected{}
		p.section = "preamble"
		return events
	}
	return append(events, classify(level, text, line))
}

// Flush emits an unfinished certificate rejection and clears its bounded state.
// Call it at stream EOF. It returns nil if no block is pending and cannot fail.
func (p *Parser) Flush() []Event {
	if p.cert == nil {
		return nil
	}
	cert := *p.cert
	p.cert, p.section = nil, ""
	return []Event{cert}
}

// splitPrefix recognizes only the exact INFO, WARN, ERROR, and DEBUG prefixes.
// It returns empty level and the original line for malformed or absent prefixes.
func splitPrefix(line string) (level, text string) {
	for _, prefix := range []string{"INFO:   ", "WARN:   ", "ERROR:  ", "DEBUG:  "} {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSuffix(strings.TrimSpace(prefix), ":"), strings.TrimPrefix(line, prefix)
		}
	}
	return "", line
}

// classify returns one observation for an already split output line.
// Known route-tool errors can be unprefixed; other milestones require their severity.
func classify(level, text, line string) Event {
	if rejection, ok := routeRejection(level, text); ok {
		return rejection
	}
	if level == "INFO" {
		switch text {
		case "Connected to gateway.":
			return ConnectedToGateway{}
		case "Authenticated.":
			return Authenticated{}
		case "Remote gateway has allocated a VPN.":
			return VPNAllocated{}
		case "Negotiation complete.":
			return NegotiationComplete{}
		case "Tunnel is up and running.":
			return TunnelUp{}
		case "Logged out.":
			return LoggedOut{}
		case "Closed connection to gateway.", "Terminated pppd.", "Terminated ppp.":
			return Teardown{Message: text}
		}
		if name, ok := strings.CutPrefix(text, "Interface "); ok {
			if name, ok = strings.CutSuffix(name, " is UP."); ok && validInterface(name) {
				return InterfaceUp{Name: name}
			}
		}
		if addresses, ok := parseAddresses(text); ok {
			return addresses
		}
	}
	if level == "ERROR" {
		switch text {
		case authFailure:
			return AuthFailed{}
		case tunnelDenied:
			return TunnelModeDenied{}
		}
		if strings.HasPrefix(text, "pppd: ") || strings.HasPrefix(text, "ppp: ") {
			return PPPFailure{Message: text}
		}
	}
	return Unknown{Line: line}
}

// routeRejection recognizes installation diagnostics and route-tool failures.
// Successful adds, protection-route diagnostics, and deletions remain unknown.
// macOS split-route failures are attributable only through their add-net output;
// routing-socket diagnostics also accompany harmless protection-route collisions.
// level is the parsed severity, or empty for route-tool output. A missing destination
// stays an invalid Prefix rather than guessing a route from another stream's log.
func routeRejection(level, text string) (RouteRejected, bool) {
	if text == "Route to vpn server exists already." || strings.HasPrefix(text, "Could not set route to vpn server") {
		return RouteRejected{}, false
	}
	lower := strings.ToLower(text)
	known := false
	if level == "INFO" || level == "WARN" || level == "ERROR" {
		known = text == "Route to gateway exists already." || text == "Default route exists already." ||
			text == "0.0.0.0/1 route exists already." || text == "128.0.0.0/1 route exists already."
		for _, prefix := range []string{"could not set route", "could not set the new ", "could not add route", "failed to add route", "failed to set route", "route add failed"} {
			if strings.HasPrefix(lower, prefix) && strings.Contains(lower, "route") {
				known = true
			}
		}
	}
	if level == "WARN" || level == "ERROR" {
		known = known || strings.HasPrefix(lower, "/sbin/route: ")
	}
	if level == "" || level == "WARN" || level == "ERROR" {
		known = known || strings.HasPrefix(lower, "rtnetlink answers: ") || strings.HasPrefix(lower, "siocaddrt: ")
		if strings.HasPrefix(lower, "add net ") {
			// Successful route output ends at the gateway; failures append a diagnostic.
			_, diagnostic, found := strings.Cut(strings.TrimPrefix(lower, "add "), ": gateway ")
			known = known || (found && strings.Contains(diagnostic, ": "))
		}
	}
	if !known {
		return RouteRejected{}, false
	}
	rejection := RouteRejected{Reason: RouteFailed, Message: text}
	if strings.Contains(lower, "file exists") || strings.Contains(lower, "exists already") {
		rejection.Reason = RouteConflict
	}
	for word := range strings.FieldsSeq(text) {
		if prefix, err := netip.ParsePrefix(strings.Trim(word, ":,().[]")); err == nil && prefix.Addr().Is4() {
			rejection.Prefix = prefix.Masked()
			break
		}
	}
	return rejection, true
}

// parseAddresses extracts well-formed unscoped IPv4 addresses and an optional suffix.
// It rejects malformed addresses and omits 0.0.0.0 DNS placeholders. Invalid gateway
// suffixes become empty without discarding a healthy tunnel's local address.
func parseAddresses(text string) (GotAddresses, bool) {
	matches := addressLine.FindStringSubmatch(text)
	if matches == nil {
		return GotAddresses{}, false
	}
	local, err := netip.ParseAddr(matches[1])
	if err != nil || !local.Is4() || local.IsUnspecified() {
		return GotAddresses{}, false
	}
	addresses := GotAddresses{LocalIP: local, Suffix: gatewaySuffix(matches[3])}
	if matches[2] == "" {
		return addresses, true
	}
	for address := range strings.SplitSeq(matches[2], ", ") {
		dns, err := netip.ParseAddr(address)
		if err != nil || !dns.Is4() {
			return GotAddresses{}, false
		}
		if !dns.IsUnspecified() {
			addresses.DNS = append(addresses.DNS, dns)
		}
	}
	return addresses, true
}

// gatewaySuffix strips controls from an unvalidated gateway DNS suffix and returns it
// only when it is a bounded ASCII DNS name. Brackets, empty/oversized labels, and other
// non-DNS text return an empty suffix, never an error that would reject tunnel addresses.
func gatewaySuffix(suffix string) string {
	suffix = strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return -1
		}
		return c
	}, suffix)
	if len(suffix) == 0 || len(suffix) > 253 {
		return ""
	}
	for label := range strings.SplitSeq(suffix, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return ""
			}
		}
	}
	return suffix
}

// validInterface accepts a bounded ASCII link name without spaces or command syntax.
// It returns false for malformed names; actual link existence is verified elsewhere.
func validInterface(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return name[0] != '-'
}

// collectCertificate consumes the expected rejection preamble and metadata lines.
// It returns false at a block boundary or invalid line; a final valid digest marks
// completion. Digests advertised in command suggestions are never used as trust data.
func (p *Parser) collectCertificate(text string) bool {
	switch text {
	case "or add this line to your configuration file:", "Gateway certificate:":
		return p.section == "preamble"
	case "    subject:":
		if p.section != "preamble" {
			return false
		}
		p.section = "subject"
		return true
	case "    issuer:":
		if p.section != "subject" {
			return false
		}
		p.section = "issuer"
		return true
	case "    sha256 digest:":
		if p.section != "issuer" {
			return false
		}
		p.section = "digest"
		return true
	}
	if p.section == "preamble" {
		return strings.HasPrefix(text, "    --trusted-cert ") || strings.HasPrefix(text, "    trusted-cert = ")
	}
	value, ok := strings.CutPrefix(text, "        ")
	if !ok || value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	switch p.section {
	case "subject", "issuer":
		if len(p.cert.Subject)+len(p.cert.Issuer)+len(value)+1 > maxCertText {
			return false
		}
		field := &p.cert.Subject
		if p.section == "issuer" {
			field = &p.cert.Issuer
		}
		if *field != "" {
			*field += "\n"
		}
		*field += value
		return true
	case "digest":
		if len(value) != 64 {
			return false
		}
		if _, err := hex.DecodeString(value); err != nil {
			return false
		}
		p.cert.Digest = strings.ToLower(value)
		p.section = "done"
		return true
	default:
		return false
	}
}
