package network

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// TestNativeEndpointConflicts rejects each untrusted endpoint's LAN, TLS gateway,
// reservation, address, peer and live-route collisions on both supported platforms.
// Refusals leave durable intent, active reservations and the fake host unchanged.
func TestNativeEndpointConflicts(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, endpoint := range []string{"local", "peer"} {
			for _, scenario := range []string{"LAN", "gateway", "configured reservation", "negotiated reservation", "other address", "other peer", "live subnet", "live host", "same link host", "split default", "equal endpoints"} {
				t.Run(platform+"/"+endpoint+"/"+scenario, func(t *testing.T) {
					m, r := nativeManager(t, platform)
					p := nativeProfile("work")
					e, j := nativeAttempt(t, m, p, 0)
					candidate := netip.MustParseAddr("10.88.0.1")
					switch scenario {
					case "LAN":
						candidate = netip.MustParseAddr("192.0.2.1")
					case "gateway":
						j.GatewayIP = candidate.String()
					case "configured reservation", "negotiated reservation", "other address", "other peer":
						other := nativeProfile("other")
						other.Routes = profile.Routes{Mode: "gateway"}
						if scenario == "configured reservation" {
							other.Routes = profile.Routes{Mode: "custom", Include: []string{"10.88.0.0/16"}}
						}
						if err := m.CheckUp(context.Background(), other); err != nil {
							t.Fatal(err)
						}
						reserved := m.active[other.ID]
						switch scenario {
						case "negotiated reservation":
							reserved.prefixes = []netip.Prefix{netip.MustParsePrefix("10.88.0.0/16")}
							reserved.negotiated = true
						case "other address":
							reserved.localIP = candidate
						case "other peer":
							reserved.peerIP, reserved.configured = candidate, true
						}
						m.active[other.ID] = reserved
					case "live subnet":
						r.base.routes = append(r.base.routes, JournalRoute{CIDR: "10.88.0.0/16", Interface: "en0"})
					case "live host":
						r.base.routes = append(r.base.routes, JournalRoute{CIDR: "10.88.0.1/32", Gateway: "192.0.2.1", Interface: "en0"})
					case "same link host":
						r.base.routes = append(r.base.routes, JournalRoute{CIDR: "10.88.0.1/32", Interface: e.Interface})
					case "split default":
						r.base.routes = append(r.base.routes, JournalRoute{CIDR: "0.0.0.0/1", Interface: "ppp0"})
					case "equal endpoints":
						if endpoint == "peer" {
							candidate = e.LocalIP
						} else {
							candidate = e.PeerIP
						}
					}
					if endpoint == "peer" {
						e.PeerIP = candidate
					} else {
						e.LocalIP = candidate
					}
					before := journalSnapshot(t, j)
					reserved := m.active[p.ID]
					calls, writes := len(r.base.calls), 0
					var conflict *ConflictError
					err := m.ConfigureNative(context.Background(), e, &j, func(Journal) error { writes++; return nil })
					if !errors.As(err, &conflict) || writes != 0 || !reflect.DeepEqual(j, before) || !reflect.DeepEqual(m.active[p.ID], reserved) {
						t.Fatalf("endpoint conflict changed intent: err=%v writes=%d journal=%+v", err, writes, j)
					}
					for _, call := range r.base.calls[calls:] {
						if slices.Contains(call, "/sbin/ifconfig") || slices.Contains(call, "addr") || slices.Contains(call, "link") {
							t.Fatalf("endpoint conflict mutated host: %v", call)
						}
					}
				})
			}
		}
	}
}

// TestNativeEndpointRetry accepts unrouted private endpoints and an identical retry
// despite its connected peer /32, without another journal write or address mutation.
// The ordinary physical default is retained and never considered an endpoint conflict.
func TestNativeEndpointRetry(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, peer := range []string{"10.99.0.1", "10.88.0.1"} {
			t.Run(platform+"/"+peer, func(t *testing.T) {
				m, r := nativeManager(t, platform)
				e, j := nativeAttempt(t, m, nativeProfile("work"), 0)
				e.PeerIP = netip.MustParseAddr(peer)
				writes := 0
				persist := func(Journal) error { writes++; return nil }
				if err := m.ConfigureNative(context.Background(), e, &j, persist); err != nil || writes != 1 {
					t.Fatalf("unrouted endpoints rejected: err=%v writes=%d", err, writes)
				}
				calls := len(r.base.calls)
				if err := m.ConfigureNative(context.Background(), e, &j, persist); err != nil || writes != 1 {
					t.Fatalf("identical retry rejected: err=%v writes=%d", err, writes)
				}
				for _, call := range r.base.calls[calls:] {
					if slices.Contains(call, "/sbin/ifconfig") || slices.Contains(call, "addr") || slices.Contains(call, "link") {
						t.Fatalf("identical retry reconfigured host: %v", call)
					}
				}
			})
		}
	}
}

// TestNativeEndpointRetryConflicts rechecks identical retries against late competing
// routes, with no exemption for another link, a routed next hop or a wider destination.
// Discovery failures also refuse configuration without persistence or host mutation.
func TestNativeEndpointRetryConflicts(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, scenario := range []string{"other link", "foreign gateway", "wider route", "subnet discovery", "route discovery"} {
			t.Run(platform+"/"+scenario, func(t *testing.T) {
				m, r := nativeManager(t, platform)
				e, j := configuredNative(t, m, nativeProfile("work"), 0)
				foreign := JournalRoute{CIDR: netip.PrefixFrom(e.PeerIP, 32).String(), Interface: e.Interface}
				switch scenario {
				case "other link":
					foreign.Interface = "en0"
				case "foreign gateway":
					foreign.Gateway = "192.0.2.99"
				case "wider route":
					foreign.CIDR = "10.99.0.0/24"
				case "subnet discovery":
					m.subnets = func() ([]InterfaceSubnet, error) { return nil, errors.New("discovery failed") }
				case "route discovery":
					r.base.fail = "route"
					if platform == "darwin" {
						r.base.fail = "-rn"
					}
				}
				if scenario != "subnet discovery" && scenario != "route discovery" {
					r.base.routes = append(r.base.routes, foreign)
				}
				before := journalSnapshot(t, j)
				calls, writes := len(r.base.calls), 0
				err := m.ConfigureNative(context.Background(), e, &j, func(Journal) error { writes++; return nil })
				var conflict *ConflictError
				if err == nil || (scenario != "subnet discovery" && scenario != "route discovery" && !errors.As(err, &conflict)) || writes != 0 || !reflect.DeepEqual(j, before) {
					t.Fatalf("unsafe retry accepted: err=%v writes=%d journal=%+v", err, writes, j)
				}
				for _, call := range r.base.calls[calls:] {
					if slices.Contains(call, "/sbin/ifconfig") || slices.Contains(call, "addr") || slices.Contains(call, "link") {
						t.Fatalf("unsafe retry mutated host: %v", call)
					}
				}
			})
		}
	}
}
