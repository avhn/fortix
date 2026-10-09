//go:build darwin || linux

package network

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// TestNativeInitialLocalRoute applies a broader split despite Darwin's local /32.
// Linux has no connected host route in the main table. Revalidation is inert and
// teardown leaves the physical path and any kernel-connected route intact.
func TestNativeInitialLocalRoute(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			m, r := nativeManager(t, platform)
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: "gateway"}
			e, j := configuredNative(t, m, p, 0)
			e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
			baseline := slices.Clone(r.base.routes)
			wantRoutes := 1
			if platform == "darwin" {
				wantRoutes++
				if baseline[1].CIDR != netip.PrefixFrom(e.LocalIP, 32).String() {
					t.Fatalf("initial kernel local route missing: %+v", baseline)
				}
			}
			if len(baseline) != wantRoutes || m.active[p.ID].negotiated {
				t.Fatalf("unexpected initial route state: %+v", baseline)
			}
			if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			if len(j.Routes) != 1 || j.Routes[0].CIDR != "10.0.0.0/8" || len(r.base.routes) != len(baseline)+1 {
				t.Fatalf("connected peer claimed or replaced: %+v table=%+v", j, r.base.routes)
			}
			calls := len(r.base.calls)
			if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			for _, call := range r.base.calls[calls:] {
				if slices.Contains(call, "add") {
					t.Fatalf("revalidation added a route: %v", call)
				}
			}
			if err := m.Teardown(context.Background(), j); err != nil || !slices.Equal(r.base.routes, baseline) {
				t.Fatalf("connected route removed by teardown: %v %+v", err, r.base.routes)
			}
		})
	}
}

// TestNativeDarwinLocalRouteShapes accepts an absent local host route or the kernel's
// direct-device and local-gateway spellings. None is required or helper-owned, and
// configuration retries and broader policy remain valid without claiming the route.
func TestNativeDarwinLocalRouteShapes(t *testing.T) {
	for _, shape := range []string{"absent", "direct", "local gateway", "interface gateway", "link gateway"} {
		t.Run(shape, func(t *testing.T) {
			m, r := nativeManager(t, "darwin")
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: "gateway"}
			e, j := configuredNative(t, m, p, 0)
			r.base.routes = slices.DeleteFunc(r.base.routes, func(route JournalRoute) bool { return route.Interface == e.Interface })
			localRoute := JournalRoute{CIDR: netip.PrefixFrom(e.LocalIP, 32).String(), Interface: e.Interface}
			switch shape {
			case "local gateway":
				localRoute.Gateway = e.LocalIP.String()
			case "interface gateway":
				localRoute.Gateway = e.Interface
			case "link gateway":
				localRoute.Gateway = "link#12"
			}
			if shape != "absent" {
				r.base.routes = append(r.base.routes, localRoute)
			}
			baseline := slices.Clone(r.base.routes)
			if err := m.ConfigureNative(context.Background(), e, &j, ignoreJournal); err != nil {
				t.Fatal(err)
			}
			e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
			if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); err != nil || len(j.Routes) != 1 || j.Routes[0].CIDR != "10.0.0.0/8" {
				t.Fatalf("local route shape affected policy: %v %+v", err, j)
			}
			if err := m.Teardown(context.Background(), j); err != nil || !slices.Equal(r.base.routes, baseline) {
				t.Fatalf("kernel route claimed or removed: %v %+v", err, r.base.routes)
			}
		})
	}
}

// TestNativeLocalRouteConflicts limits Darwin's exemption to the configured local IP.
// Linux has no main-table exemption. Exact local destinations, foreign next hops,
// other links and unrelated host routes cannot enter the route journal.
func TestNativeLocalRouteConflicts(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, scenario := range []string{"exact local", "other link", "foreign gateway", "unrelated host", "forged peer", "reused index", "unconfigured"} {
			t.Run(platform+"/"+scenario, func(t *testing.T) {
				m, r := nativeManager(t, platform)
				p := nativeProfile("work")
				p.Routes = profile.Routes{Mode: "gateway"}
				e, j := configuredNative(t, m, p, 0)
				e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
				foreign := JournalRoute{CIDR: netip.PrefixFrom(e.LocalIP, 32).String(), Interface: e.Interface}
				switch scenario {
				case "exact local":
					e.PushedPrefixes = []netip.Prefix{netip.PrefixFrom(e.LocalIP, 32)}
				case "other link":
					foreign.Interface = "en0"
				case "foreign gateway":
					foreign.Gateway = "192.0.2.99"
				case "unrelated host":
					foreign.CIDR = "10.98.0.1/32"
				case "forged peer":
					e.PeerIP = netip.MustParseAddr("10.98.0.1")
					foreign.CIDR = netip.PrefixFrom(e.PeerIP, 32).String()
				case "reused index":
					r.links[e.Interface].index++
				case "unconfigured":
					current := m.active[p.ID]
					current.configured = false
					m.active[p.ID] = current
				}
				if scenario == "exact local" && platform == "linux" {
					r.base.routes = append(r.base.routes, foreign)
				}
				if scenario != "exact local" && scenario != "reused index" && scenario != "unconfigured" {
					r.base.routes = append(r.base.routes, foreign)
				}
				baseline := slices.Clone(r.base.routes)
				err := m.ReserveNegotiated(context.Background(), p, e)
				var conflict *ConflictError
				var identity *InterfaceError
				if !errors.As(err, &conflict) && !errors.As(err, &identity) {
					t.Fatalf("untrusted peer route accepted: %v", err)
				}
				if len(j.Routes) != 0 || m.active[p.ID].negotiated || !slices.Equal(r.base.routes, baseline) {
					t.Fatalf("peer conflict claimed or changed routes: %+v table=%+v", j, r.base.routes)
				}
			})
		}
	}
}

// TestNativeRunnerLocalCancellation keeps native and gateway add intent when an injected
// runner installs the expected route before returning its own cancellation or deadline.
// The parent context stays active. Both live teardown and restarted recovery remove
// only the intended route, preserving the physical default and kernel-connected peer.
func TestNativeRunnerLocalCancellation(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, resource := range []string{"native", "gateway"} {
			for _, failure := range []error{context.DeadlineExceeded, context.Canceled} {
				for _, cleanup := range []string{"teardown", "recovery"} {
					t.Run(platform+"/"+resource+"/"+failure.Error()+"/"+cleanup, func(t *testing.T) {
						m, r := nativeManager(t, platform)
						p := nativeProfile("work")
						e, j := configuredNative(t, m, p, 0)
						baseline := slices.Clone(r.base.routes)
						ctx := context.Background()
						route := JournalRoute{CIDR: "10.20.0.0/16", Interface: e.Interface}
						if platform == "darwin" {
							route.Gateway = e.Interface
						}
						if resource == "gateway" {
							j.GatewayIP = "203.0.113.5"
							route = JournalRoute{CIDR: "203.0.113.5/32", Gateway: "192.0.2.1", Interface: "en0"}
						}
						r.rejectCIDR, r.racingRoute = route.CIDR, route
						r.rejectErr = errors.Join(failure, &CommandError{})
						durable := journalSnapshot(t, j)
						persist := func(updated Journal) error { durable = journalSnapshot(t, updated); return nil }
						var err error
						if resource == "gateway" {
							err = m.acquireGateway(ctx, &j, persist)
						} else {
							err = m.addOwnedRoute(ctx, JournalRoute{CIDR: route.CIDR, Interface: route.Interface}, &j, persist)
						}
						var conflict *ConflictError
						if !errors.Is(err, failure) || errors.As(err, &conflict) || ctx.Err() != nil || !slices.Contains(r.base.routes, route) {
							t.Fatalf("local cancellation misclassified: %v table=%+v", err, r.base.routes)
						}
						if resource == "gateway" {
							if j.GatewayException == nil || durable.GatewayException == nil || m.gateways[route.CIDR] == nil {
								t.Fatalf("gateway add intent discarded: %+v durable=%+v", j, durable)
							}
						} else if len(j.Routes) != 1 || len(durable.Routes) != 1 {
							t.Fatalf("native add intent discarded: %+v durable=%+v", j, durable)
						}
						if cleanup == "recovery" {
							err = freshNativeManager(t, m).RecoverAll(ctx, []Journal{durable})
						} else {
							err = m.Teardown(ctx, j)
						}
						if err != nil || !slices.Equal(r.base.routes, baseline) {
							t.Fatalf("ambiguous add leaked after %s: %v table=%+v", cleanup, err, r.base.routes)
						}
					})
				}
			}
		}
	}
}

// TestNativeLocalCancellationConflict preserves collision safety even when a runner
// also returns a local deadline. Explicit EEXIST on the same identity and a distinct
// competing path both clear intent, return ConflictError, and leave the route untouched.
func TestNativeLocalCancellationConflict(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, resource := range []string{"native", "gateway"} {
			for _, collision := range []string{"exists", "competing identity"} {
				t.Run(platform+"/"+resource+"/"+collision, func(t *testing.T) {
					m, r := nativeManager(t, platform)
					p := nativeProfile("work")
					e, j := configuredNative(t, m, p, 0)
					route := JournalRoute{CIDR: "10.20.0.0/16", Interface: e.Interface}
					if platform == "darwin" {
						route.Gateway = e.Interface
					}
					if resource == "gateway" {
						j.GatewayIP = "203.0.113.5"
						route = JournalRoute{CIDR: "203.0.113.5/32", Gateway: "192.0.2.1", Interface: "en0"}
					}
					r.rejectErr = errors.Join(context.DeadlineExceeded, &CommandError{Stderr: "File exists"})
					if collision == "competing identity" {
						r.rejectErr = context.DeadlineExceeded
						route.Interface, route.Gateway = "en0", "192.0.2.99"
					}
					r.rejectCIDR, r.racingRoute = route.CIDR, route
					durable := journalSnapshot(t, j)
					persist := func(updated Journal) error { durable = journalSnapshot(t, updated); return nil }
					var err error
					if resource == "gateway" {
						err = m.acquireGateway(context.Background(), &j, persist)
					} else {
						err = m.addOwnedRoute(context.Background(), JournalRoute{CIDR: route.CIDR, Interface: e.Interface}, &j, persist)
					}
					var conflict *ConflictError
					if !errors.As(err, &conflict) || len(j.Routes) != 0 || len(durable.Routes) != 0 || j.GatewayException != nil || durable.GatewayException != nil || len(m.gateways) != 0 {
						t.Fatalf("local deadline claimed a competing route: %v journal=%+v durable=%+v", err, j, durable)
					}
					baseline := slices.Clone(r.base.routes)
					if !slices.Contains(baseline, route) {
						t.Fatal("competing route was not modeled")
					}
					if err := m.Teardown(context.Background(), j); err != nil || !slices.Equal(r.base.routes, baseline) {
						t.Fatalf("cleanup removed competing route: %v table=%+v", err, r.base.routes)
					}
				})
			}
		}
	}
}

// TestNativeLocalDeadlineRollback verifies Apply rolls back a successful add that returns
// a runner-local deadline. Gateway exceptions use a split route covering the TLS peer.
// A failed rollback must preserve durable intent for recovery.
func TestNativeLocalDeadlineRollback(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, resource := range []string{"native", "gateway"} {
			for _, failCleanup := range []bool{false, true} {
				t.Run(platform+"/"+resource+"/"+map[bool]string{false: "rollback", true: "recovery"}[failCleanup], func(t *testing.T) {
					m, r := nativeManager(t, platform)
					p := nativeProfile("work")
					p.Routes = profile.Routes{Mode: "gateway"}
					e, j := configuredNative(t, m, p, 0)
					e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
					route := JournalRoute{CIDR: "10.20.0.0/16", Interface: e.Interface}
					if platform == "darwin" {
						route.Gateway = e.Interface
					}
					if resource == "gateway" {
						j.GatewayIP = "203.0.113.5"
						e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
						route = JournalRoute{CIDR: "203.0.113.5/32", Gateway: "192.0.2.1", Interface: "en0"}
					}
					baseline := slices.Clone(r.base.routes)
					r.rejectCIDR, r.racingRoute, r.rejectErr = route.CIDR, route, context.DeadlineExceeded
					if failCleanup {
						r.base.fail = "delete"
					}
					durable := journalSnapshot(t, j)
					ctx := context.Background()
					err := m.Apply(ctx, p, e, &j, func(updated Journal) error { durable = journalSnapshot(t, updated); return nil })
					var conflict *ConflictError
					if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &conflict) || ctx.Err() != nil {
						t.Fatalf("runner-local deadline misclassified: %v", err)
					}
					if failCleanup {
						if !slices.Contains(r.base.routes, route) || (resource == "gateway" && durable.GatewayException == nil) || (resource == "native" && len(durable.Routes) != 1) {
							t.Fatalf("failed rollback discarded intent: %+v table=%+v", durable, r.base.routes)
						}
						r.base.fail = ""
						if err := freshNativeManager(t, m).RecoverAll(ctx, []Journal{durable}); err != nil {
							t.Fatal(err)
						}
					} else if len(durable.Routes) != 0 || durable.GatewayException != nil {
						t.Fatalf("successful rollback retained intent: %+v", durable)
					}
					if !slices.Equal(r.base.routes, baseline) {
						t.Fatalf("local deadline leaked route: %+v", r.base.routes)
					}
				})
			}
		}
	}
}
