package network

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// TestNativeGatewayExceptionPolicy acquires a host exception only when selected
// routes cover the recorded TLS peer. Unrelated routes work even when the peer's
// original path uses another tunnel. Revalidation and cleanup preserve exact ownership.
func TestNativeGatewayExceptionPolicy(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, mode := range []string{"gateway", "custom", "full"} {
			for _, overlaps := range []bool{false, true} {
				name := platform + "/" + mode + "/unrelated"
				if overlaps {
					name = platform + "/" + mode + "/covers peer"
				}
				t.Run(name, func(t *testing.T) {
					m, r := nativeManager(t, platform)
					if !overlaps {
						// A separate VPN supplies the only original path to the TLS peer.
						r.base.routes[0].Interface = "utun9"
					}
					cidr := "10.40.0.0/16"
					if overlaps {
						cidr = "203.0.113.0/24"
					}
					p := nativeProfile("work")
					p.Routes = profile.Routes{Mode: mode}
					if mode == "custom" {
						p.Routes.Include = []string{cidr}
					}
					e, j := configuredNative(t, m, p, 0)
					e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix(cidr)}
					j.GatewayIP = "203.0.113.5"
					baseline := slices.Clone(r.base.routes)
					for range 2 {
						if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
							t.Fatal(err)
						}
						if (j.GatewayException != nil) != overlaps || len(j.Routes) != 1 {
							t.Fatalf("unexpected gateway ownership: %+v", j)
						}
					}
					if err := m.Teardown(context.Background(), j); err != nil || !slices.Equal(r.base.routes, baseline) || len(m.gateways) != 0 {
						t.Fatalf("gateway policy cleanup: %v %+v", err, r.base.routes)
					}
				})
			}
		}
	}
}

// TestUnrelatedSplitDoesNotShareGateway verifies a split tunnel has no lease on a
// full tunnel's exception when none of its routes cover the TLS peer. Stopping the
// full tunnel releases that host route while the unrelated split remains active.
// Both links configure distinct endpoints before the full tunnel installs routes.
func TestUnrelatedSplitDoesNotShareGateway(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, r := nativeManager(t, platform)
			full := nativeProfile("work")
			full.Routes = profile.Routes{Mode: "full"}
			e, first := configuredNative(t, m, full, 0)
			other := nativeProfile("other")
			other.Routes = profile.Routes{Mode: "gateway"}
			secondEffect, second := configuredNative(t, m, other, 1)
			first.GatewayIP = "203.0.113.5"
			if err := m.Apply(context.Background(), full, e, &first, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			secondEffect.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}
			second.GatewayIP = first.GatewayIP
			if err := m.Apply(context.Background(), other, secondEffect, &second, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			if second.GatewayException != nil || len(m.gateways["203.0.113.5/32"].owners) != 1 {
				t.Fatal("unrelated split retained an unnecessary gateway lease")
			}
			if err := m.Teardown(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			if len(m.gateways) != 0 || slices.ContainsFunc(r.base.routes, func(route JournalRoute) bool { return route.CIDR == "203.0.113.5/32" }) || !slices.Contains(r.base.routes, second.Routes[0]) {
				t.Fatalf("full stop leaked exception or removed split route: %+v", r.base.routes)
			}
			if err := m.Teardown(context.Background(), second); err != nil {
				t.Fatal(err)
			}
		})
	}
}
