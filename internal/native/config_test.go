package native

import (
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

// fixtureXML exercises attribute-based metadata alongside ignored IPv6 and addr data.
const fixtureXML = `<?xml version="1.0"?><sslvpn-tunnel>
<assigned-addr ipv4="10.20.30.40" ipv6="::1"/>
<dns ip="10.20.0.1"/><dns ip="10.20.0.2"/><dns domain="Office.Test;Other.Test"/>
<addr ip="192.0.2.5" mask="invalid"/>
<split-tunnel-info><addr ip="10.20.99.5" mask="255.255.0.0"/>
<addr ip="192.0.2.3" mask="255.255.255.255"/>
<addr ip="10.20.30.1" mask="0.0.0.0"/></split-tunnel-info>
</sslvpn-tunnel>`

// TestParseConfig verifies canonical IPv4 routes, DNS domains, and optional addresses.
func TestParseConfig(t *testing.T) {
	config, err := ParseConfig(strings.NewReader(fixtureXML))
	if err != nil {
		t.Fatal(err)
	}
	if config.AssignedIP.String() != "10.20.30.40" || len(config.DNS) != 2 || config.DNS[1].String() != "10.20.0.2" || strings.Join(config.Domains, ",") != "office.test,other.test" {
		t.Fatalf("unexpected metadata: %+v", config)
	}
	want := []string{"10.20.0.0/16", "192.0.2.3/32", "0.0.0.0/0"}
	if len(config.SplitRoutes) != len(want) {
		t.Fatalf("routes: %v", config.SplitRoutes)
	}
	for i, route := range config.SplitRoutes {
		if route.String() != want[i] {
			t.Fatalf("route %d: %v", i, route)
		}
	}
	config, err = ParseConfig(strings.NewReader(`<sslvpn-tunnel><assigned-addr ipv6="::1"/></sslvpn-tunnel>`))
	if err != nil || config.AssignedIP.IsValid() {
		t.Fatalf("optional IPv4: %+v %v", config, err)
	}
}

// TestConfigRejections covers XML structural bounds and hostile metadata validation.
func TestConfigRejections(t *testing.T) {
	cases := map[string]string{
		"empty": "", "text": "not XML", "unclosed": "<config>",
		"multiple-roots": "<config/><config/>", "trailing-text": "<config/>SECRET",
		"dtd":         `<!DOCTYPE c [<!ENTITY x "SECRET">]><c>&x;</c>`,
		"instruction": `<?unsafe SECRET?><c/>`, "late-declaration": `<c><?xml version="1.0"?></c>`,
		"address":             `<c><assigned-addr ipv4="SECRET"/></c>`,
		"mapped-ipv6":         `<c><dns ip="::ffff:10.0.0.1"/></c>`,
		"duplicate-ip":        `<c><assigned-addr ipv4="10.0.0.1"/><assigned-addr ipv4="10.0.0.2"/></c>`,
		"duplicate-attribute": `<c><dns ip="10.0.0.1" ip="10.0.0.2"/></c>`,
		"domain":              `<c><dns domain="SECRET/invalid"/></c>`, "empty-domain": `<c><dns domain=""/></c>`,
		"ip-domain":    `<c><dns domain="10.0.0.1"/></c>`,
		"route-mask":   `<c><split-tunnel-info><addr ip="10.0.0.1" mask="255.0.255.0"/></split-tunnel-info></c>`,
		"route-ip":     `<c><split-tunnel-info><addr ip="SECRET" mask="255.255.0.0"/></split-tunnel-info></c>`,
		"missing-mask": `<c><split-tunnel-info><addr ip="10.0.0.1"/></split-tunnel-info></c>`,
		"oversize":     strings.Repeat(" ", MaxConfigBytes+1),
		"depth":        strings.Repeat("<c>", maxXMLDepth+1) + strings.Repeat("</c>", maxXMLDepth+1),
		"elements":     "<c>" + strings.Repeat("<x/>", maxXMLElements) + "</c>",
		"dns-count":    "<c>" + strings.Repeat(`<dns ip="10.0.0.1"/>`, maxDNS+1) + "</c>",
		"domain-count": "<c>" + strings.Repeat(`<dns domain="office.test"/>`, maxDNS+1) + "</c>",
		"route-count":  "<c><split-tunnel-info>" + strings.Repeat(`<addr ip="10.0.0.1" mask="255.0.0.0"/>`, maxRoutes+1) + "</split-tunnel-info></c>",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig(strings.NewReader(input))
			if err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("expected sanitized rejection, got %v", err)
			}
		})
	}
	if _, err := ParseConfig(errorReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reader error: %v", err)
	}
}

// errorReader supplies a deterministic input failure for the XML decoder.
type errorReader struct{}

// Read returns an unexpected EOF without input bytes.
func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// FuzzConfig checks XML parsing bounds and canonical output invariants.
func FuzzConfig(f *testing.F) {
	f.Add(fixtureXML)
	f.Add(`<c><split-tunnel-info><addr ip="10.0.0.1" mask="255.0.255.0"/></split-tunnel-info></c>`)
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		config, err := ParseConfig(strings.NewReader(input))
		if err != nil {
			return
		}
		if len(config.DNS) > maxDNS || len(config.Domains) > maxDNS || len(config.SplitRoutes) > maxRoutes {
			t.Fatal("unbounded configuration entries")
		}
		for _, address := range append(config.DNS, config.AssignedIP) {
			if address.IsValid() && !address.Is4() {
				t.Fatal("non-IPv4 metadata")
			}
		}
		for _, route := range config.SplitRoutes {
			if !route.IsValid() || !route.Addr().Is4() || route != route.Masked() || route.Bits() > netip.IPv4Unspecified().BitLen() {
				t.Fatal("noncanonical IPv4 route")
			}
		}
	})
}
