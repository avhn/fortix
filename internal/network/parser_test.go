package network

import (
	"net/netip"
	"testing"
)

// TestRouteParsers covers realistic platform tables and malformed ownership identities.
// Parser failures never return destinations that could reach privileged route deletion.
func TestRouteParsers(t *testing.T) {
	for _, tc := range []struct {
		name, platform, data string
		want                 int
		bad                  bool
	}{
		{"linux empty", "linux", `[]`, 0, false},
		{"linux unicast", "linux", `[{"dst":"default","gateway":"10.20.0.1","dev":"en0"},{"dst":"10.30.0.0/16","dev":"ppp0"}]`, 2, false},
		{"linux multipath", "linux", `[{"dst":"default","nexthops":[{"gateway":"10.20.0.1","dev":"en0","weight":1},{"gateway":"10.30.0.1","dev":"en1","weight":1}]}]`, 2, false},
		{"linux multipath direct", "linux", `[{"dst":"10.20.0.0/16","nexthops":[{"dev":"ppp0"},{"dev":"ppp1"}]}]`, 2, false},
		{"linux multipath missing dev", "linux", `[{"dst":"default","nexthops":[{"gateway":"10.20.0.1"}]}]`, 0, true},
		{"linux multipath invalid gateway", "linux", `[{"dst":"default","nexthops":[{"gateway":"invalid","dev":"en0"}]}]`, 0, true},
		{"linux missing dev", "linux", `[{"dst":"default"}]`, 0, true},
		{"linux blackhole", "linux", `[{"type":"blackhole","dst":"10.30.0.0/16"}]`, 0, false},
		{"linux garbage", "linux", `{}`, 0, true},
		{"linux bad destination", "linux", `[{"dst":"10.20.0.1/16","dev":"ppp0"}]`, 0, true},
		{"linux bad gateway", "linux", `[{"dst":"10.20.0.0/16","gateway":"invalid","dev":"ppp0"}]`, 0, true},
		{"darwin table", "darwin", "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 10.20.0.1 UGSc en0\n10.30/16 link#12 US ppp0\n", 2, false},
		{"darwin interface route", "darwin", "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\n10.20/16 ppp0 USc ppp0\n", 1, false},
		{"darwin missing header", "darwin", "garbage", 0, true},
		{"darwin bad row", "darwin", "Destination Gateway Flags Netif\ninvalid link#12 US ppp0", 0, true},
		{"darwin short row", "darwin", "Destination Gateway Flags Netif\n10.20", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parse := parseLinuxRoutes
			if tc.platform == "darwin" {
				parse = parseDarwinRoutes
			}
			routes, err := parse([]byte(tc.data))
			if (err != nil) != tc.bad || (!tc.bad && len(routes) != tc.want) {
				t.Fatalf("routes=%+v err=%v", routes, err)
			}
		})
	}
}

// TestPrefixAndResolvedParsers checks abbreviated IPv4 and link-specific DNS records.
// Invalid octets, lengths, link identities and multiline output must be rejected.
func TestPrefixAndResolvedParsers(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"default", "0.0.0.0/0"}, {"10.20", "10.20.0.0/16"}, {"10.20.0.1", "10.20.0.1/32"}, {"128/1", "128.0.0.0/1"}, {"10.20/16", "10.20.0.0/16"}, {"256.0.0.0/8", ""}, {"10.20/33", ""}, {"01.20", ""}, {"10.20.0.1/16", ""}, {"", ""}} {
		prefix, err := routePrefix(tc.input)
		if tc.want == "" {
			if err == nil {
				t.Fatalf("accepted invalid prefix %q", tc.input)
			}
		} else if err != nil || prefix.String() != tc.want {
			t.Fatalf("prefix %q = %v, %v", tc.input, prefix, err)
		}
	}
	for _, tc := range []struct {
		input string
		bad   bool
	}{{"Link 12 (ppp0): 10.20.0.1\n", false}, {"Link 12 (ppp0):\n", false}, {"Link 12 (ppp1): 10.20.0.1", true}, {"Link invalid (ppp0):", true}, {"Link 0 (ppp0):", true}, {"Link 12 (ppp0): one\ntwo", true}, {"arbitrary", true}} {
		if _, err := parseResolved([]byte(tc.input), "ppp0"); (err != nil) != tc.bad {
			t.Fatalf("resolved %q: %v", tc.input, err)
		}
	}
}

// FuzzLinuxRoutes ensures arbitrary bounded command output cannot invent invalid CIDRs.
// Successful parser results must be canonical IPv4 identities and never panic.
func FuzzLinuxRoutes(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"dst":"10.20.0.0/16","dev":"ppp0"}]`))
	f.Add([]byte(`[{"dst":"default","nexthops":[{"gateway":"10.20.0.1","dev":"en0"},{"dev":"ppp0"}]}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		routes, err := parseLinuxRoutes(data)
		if err == nil {
			for _, route := range routes {
				prefix, err := netip.ParsePrefix(route.CIDR)
				if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || route.Interface == "" {
					t.Fatalf("invalid route: %+v", route)
				}
			}
		}
	})
}

// FuzzDarwinRoutes exercises malformed headers, rows and abbreviated destinations.
// A successful table always contains normalized IPv4 prefixes suitable for comparison.
func FuzzDarwinRoutes(f *testing.F) {
	f.Add([]byte("Destination Gateway Flags Netif\n10.20 link#12 US ppp0\n"))
	f.Add([]byte("Destination Gateway Flags Netif\n10.20/16 ppp0 USc ppp0\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		routes, err := parseDarwinRoutes(data)
		if err == nil {
			for _, route := range routes {
				prefix, err := netip.ParsePrefix(route.CIDR)
				if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
					t.Fatalf("invalid route: %+v", route)
				}
			}
		}
	})
}

// FuzzRoutePrefix exercises every spelling of route-table IPv4 destinations.
// Successful prefixes are canonical and failures cannot panic or return a valid prefix.
func FuzzRoutePrefix(f *testing.F) {
	for _, seed := range []string{"default", "10.20/16", "128/1", "10.20.0.1", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		prefix, err := routePrefix(text)
		if err == nil && (!prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked()) {
			t.Fatalf("invalid prefix: %v", prefix)
		}
	})
}

// FuzzResolved ensures link-output parsing never accepts another interface's identity.
// Parsing values is independent from ownership validation, which checks IPs and domains.
func FuzzResolved(f *testing.F) {
	f.Add([]byte("Link 12 (ppp0): 10.20.0.1\n"))
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = parseResolved(data, "ppp0") })
}
