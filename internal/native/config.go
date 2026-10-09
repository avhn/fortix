package native

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"math/bits"
	"net/netip"
	"strings"
)

// XML limits bound memory, nesting, and the number of gateway-supplied entries.
const (
	MaxConfigBytes = 256 * 1024
	maxXMLDepth    = 32
	maxXMLElements = 8192
	maxRoutes      = 1024
	maxDNS         = 16
)

// VPNConfig contains XML fallback metadata, not authoritative PPP negotiation.
// AssignedIP may be absent; DNS and Domains support split DNS; SplitRoutes contains
// canonical IPv4 prefixes. Unrelated elements and assigned IPv6 attributes are ignored;
// explicitly IPv4 fields reject IPv6 literals.
type VPNConfig struct {
	AssignedIP  netip.Addr
	DNS         []netip.Addr
	Domains     []string
	SplitRoutes []netip.Prefix
}

// ParseConfig decodes a size-bounded XML document from reader using encoding/xml.
// It rejects malformed XML, excessive nesting or entries, invalid IPv4 fields,
// noncontiguous route masks, and invalid DNS domains without echoing gateway text.
func ParseConfig(reader io.Reader) (VPNConfig, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxConfigBytes+1))
	if err != nil {
		return VPNConfig{}, err
	}
	if len(data) > MaxConfigBytes {
		return VPNConfig{}, errors.New("gateway XML configuration is too large")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var config VPNConfig
	var stack []string
	roots, elements := 0, 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			if roots != 1 || len(stack) != 0 {
				return VPNConfig{}, errors.New("invalid gateway XML document")
			}
			return config, nil
		}
		if err != nil {
			return VPNConfig{}, errors.New("invalid gateway XML document")
		}
		switch token := token.(type) {
		case xml.StartElement:
			elements++
			if len(stack) == 0 {
				roots++
			}
			if roots > 1 || len(stack) >= maxXMLDepth || elements > maxXMLElements {
				return VPNConfig{}, errors.New("gateway XML structure exceeds limits")
			}
			parent := ""
			if len(stack) != 0 {
				parent = stack[len(stack)-1]
			}
			if err := config.element(token, parent); err != nil {
				return VPNConfig{}, err
			}
			stack = append(stack, token.Name.Local)
		case xml.EndElement:
			if len(stack) == 0 {
				return VPNConfig{}, errors.New("invalid gateway XML document")
			}
			stack = stack[:len(stack)-1]
		case xml.Directive:
			// External entities and DTDs are unnecessary for gateway metadata.
			return VPNConfig{}, errors.New("gateway XML directives are unsupported")
		case xml.ProcInst:
			if token.Target != "xml" || roots != 0 {
				return VPNConfig{}, errors.New("gateway XML processing instructions are unsupported")
			}
		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(token)) != "" {
				return VPNConfig{}, errors.New("invalid gateway XML document")
			}
		}
	}
}

// element consumes supported attribute-based IPv4 metadata. parent restricts routes
// to the split-tunnel container so unrelated addr elements cannot install routes.
func (c *VPNConfig) element(element xml.StartElement, parent string) error {
	attrs := make(map[string]string, len(element.Attr))
	for _, attr := range element.Attr {
		if _, exists := attrs[attr.Name.Local]; exists {
			return errors.New("duplicate gateway XML attribute")
		}
		attrs[attr.Name.Local] = attr.Value
	}
	switch element.Name.Local {
	case "assigned-addr":
		if text, ok := attrs["ipv4"]; ok {
			address, err := parseIPv4(text)
			if err != nil || c.AssignedIP.IsValid() && c.AssignedIP != address {
				return errors.New("invalid assigned gateway IPv4 address")
			}
			c.AssignedIP = address
		}
	case "dns":
		if text, ok := attrs["ip"]; ok {
			address, err := parseIPv4(text)
			if err != nil || len(c.DNS) >= maxDNS {
				return errors.New("invalid gateway DNS address list")
			}
			c.DNS = append(c.DNS, address)
		}
		if text, ok := attrs["domain"]; ok {
			domains := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
			if len(domains) == 0 || len(c.Domains)+len(domains) > maxDNS {
				return errors.New("invalid gateway DNS domain list")
			}
			for _, domain := range domains {
				if !validHost(domain) || isIPAddress(domain) {
					return errors.New("invalid gateway DNS domain")
				}
				c.Domains = append(c.Domains, strings.ToLower(strings.TrimSuffix(domain, ".")))
			}
		}
	case "addr":
		if parent != "split-tunnel-info" {
			return nil
		}
		prefix, err := routePrefix(attrs["ip"], attrs["mask"])
		if err != nil || len(c.SplitRoutes) >= maxRoutes {
			return errors.New("invalid gateway split route")
		}
		c.SplitRoutes = append(c.SplitRoutes, prefix)
	}
	return nil
}

// isIPAddress reports IP literals that cannot be used as DNS search domains.
func isIPAddress(text string) bool {
	_, err := netip.ParseAddr(text)
	return err == nil
}

// parseIPv4 returns a strictly parsed IPv4 address and rejects mapped IPv6 literals.
func parseIPv4(text string) (netip.Addr, error) {
	address, err := netip.ParseAddr(text)
	if err != nil || !address.Is4() {
		return netip.Addr{}, errors.New("invalid gateway IPv4 address")
	}
	return address, nil
}

// routePrefix validates a dotted IPv4 address and contiguous dotted mask, returning
// a canonical prefix. Zero and all-ones masks are valid; route policy is caller-owned.
func routePrefix(ip, mask string) (netip.Prefix, error) {
	address, err := parseIPv4(ip)
	if err != nil {
		return netip.Prefix{}, err
	}
	maskIP, err := parseIPv4(mask)
	if err != nil {
		return netip.Prefix{}, err
	}
	bytes := maskIP.As4()
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	inverse := ^value
	if inverse&(inverse+1) != 0 {
		return netip.Prefix{}, errors.New("noncontiguous gateway route mask")
	}
	return netip.PrefixFrom(address, bits.OnesCount32(value)).Masked(), nil
}
