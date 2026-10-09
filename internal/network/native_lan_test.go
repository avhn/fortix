package network

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// prefixes parses canonical test prefixes.
func prefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

// TestCarveLocalNetworks covers splitting, dropping, tunnel exemption, default
// halves and the deterministic order revalidation relies on.
func TestCarveLocalNetworks(t *testing.T) {
	lan := []InterfaceSubnet{{"en0", netip.MustParsePrefix("198.18.1.23/24")}, {"utun4", netip.MustParsePrefix("10.20.5.0/24")}}
	for _, tc := range []struct {
		name   string
		pushed []netip.Prefix
		want   []netip.Prefix
	}{
		{"split around LAN", prefixes("198.18.0.0/22"), prefixes("198.18.0.0/24", "198.18.2.0/23")},
		{"route inside LAN dropped", prefixes("198.18.1.128/25", "10.30.3.0/24"), prefixes("10.30.3.0/24")},
		{"LAN equal dropped", prefixes("198.18.1.0/24"), prefixes()},
		{"disjoint unchanged", prefixes("10.30.4.0/24", "10.30.3.0/24"), prefixes("10.30.3.0/24", "10.30.4.0/24")},
		{"tunnel networks stay", prefixes("10.20.0.0/16"), prefixes("10.20.0.0/16")},
		{"default halves stay", prefixes("0.0.0.0/1", "128.0.0.0/1"), prefixes("0.0.0.0/1", "128.0.0.0/1")},
		{"deep split", prefixes("198.0.0.0/8"), prefixes("198.0.0.0/12", "198.16.0.0/15", "198.18.0.0/24", "198.18.2.0/23", "198.18.4.0/22", "198.18.8.0/21", "198.18.16.0/20", "198.18.32.0/19", "198.18.64.0/18", "198.18.128.0/17", "198.19.0.0/16", "198.20.0.0/14", "198.24.0.0/13", "198.32.0.0/11", "198.64.0.0/10", "198.128.0.0/9")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := carveLocalNetworks(tc.pushed, lan)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("carved %v, want %v (%v)", got, tc.want, err)
			}
			reversed := slices.Clone(lan)
			slices.Reverse(reversed)
			again, err := carveLocalNetworks(tc.pushed, reversed)
			if err != nil || !slices.Equal(again, got) {
				t.Fatalf("order depends on interfaces: %v vs %v", again, got)
			}
		})
	}
}

// TestCarveLocalNetworksBound refuses a push that would expand past the route cap.
func TestCarveLocalNetworksBound(t *testing.T) {
	subnets := make([]InterfaceSubnet, 0, 64)
	for i := range 64 {
		subnets = append(subnets, InterfaceSubnet{"en0", netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i * 4), 0, 0}), 32)})
	}
	if _, err := carveLocalNetworks(prefixes("10.0.0.0/8"), subnets); err == nil {
		t.Fatal("unbounded carve accepted")
	}
}

// TestNativeGatewayKeepsLAN connects gateway and full routing (with a pushed default)
// whose list overlaps the Wi-Fi network: the LAN stays local, the rest is installed,
// and an explicit opt-out still refuses with the route and interface named.
func TestNativeGatewayKeepsLAN(t *testing.T) {
	for _, mode := range []string{"gateway", "full", "opt-out"} {
		t.Run(mode, func(t *testing.T) {
			m, r := nativeManager(t, "linux")
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: mode}
			if mode == "opt-out" {
				p.Routes = profile.Routes{Mode: "gateway", PreserveLAN: new(false)}
			}
			e, j := configuredNative(t, m, p, 0)
			// en0 is 192.0.2.0/24 in the fixture host.
			e.PushedPrefixes = prefixes("10.20.0.0/16", "192.0.2.0/23", "192.0.2.128/25")
			if mode == "full" {
				// Full mode adds the /1 halves only when the gateway pushes a default.
				e.PushedPrefixes = append(e.PushedPrefixes, netip.MustParsePrefix("0.0.0.0/0"))
				j.GatewayIP = "203.0.113.10"
			}
			err := m.Apply(context.Background(), p, e, &j, ignoreJournal)
			if mode == "opt-out" {
				var conflict *ConflictError
				if !errors.As(err, &conflict) || !strings.Contains(conflict.Detail, "192.0.2.0/23") || !strings.Contains(conflict.Detail, "en0") || len(j.Routes) != 0 {
					t.Fatalf("opt-out accepted or unnamed: %v %+v", err, j.Routes)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var installed []string
			for _, route := range j.Routes {
				if route.Interface == e.Interface {
					installed = append(installed, route.CIDR)
				}
			}
			want := []string{"10.20.0.0/16", "192.0.3.0/24"}
			if mode == "full" {
				want = []string{"0.0.0.0/1", "10.20.0.0/16", "128.0.0.0/1", "192.0.3.0/24"}
			}
			slices.Sort(installed)
			if !slices.Equal(installed, want) {
				t.Fatalf("installed %v, want %v", installed, want)
			}
			for _, route := range r.base.routes {
				// The /1 halves cover everything; the connected LAN route is more specific.
				if prefix := netip.MustParsePrefix(route.CIDR); route.Interface == e.Interface && prefix.Bits() > 1 && prefix.Overlaps(netip.MustParsePrefix("192.0.2.0/24")) {
					t.Fatalf("LAN routed into the tunnel: %+v", route)
				}
			}
		})
	}
}
