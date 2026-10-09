//go:build darwin || linux

package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// policyRunner injects a Linux policy route into read-only table replies.
// Every non-query invocation delegates to the fully injected native host.
type policyRunner struct {
	base *nativeRunner
	kind string
}

// Run supplies a non-unicast destination alongside the original physical default.
// Policy entries deliberately have no device, so they cannot grant route ownership.
func (r policyRunner) Run(ctx context.Context, candidates []string, args ...string) ([]byte, error) {
	if args[0] == "-j" {
		return []byte(fmt.Sprintf(`[{"dst":"default","dev":"en0","gateway":"192.0.2.1"},{"dst":"10.20.0.0/16","type":%q}]`, r.kind)), nil
	}
	return r.base.Run(ctx, candidates, args...)
}

// TestNativePolicyRouteConflicts refuses Linux reject/throw routes before adding any
// negotiated prefix. The process-backend parser retains its unicast-only semantics.
func TestNativePolicyRouteConflicts(t *testing.T) {
	for _, kind := range []string{"blackhole", "throw", "prohibit", "unreachable"} {
		t.Run(kind, func(t *testing.T) {
			m, r := nativeManager(t, "linux")
			p := nativeProfile("work")
			p.Routes = profile.Routes{Mode: "gateway"}
			e, j := configuredNative(t, m, p, 0)
			e.PushedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
			m.runner = policyRunner{base: r, kind: kind}
			calls := len(r.base.calls)
			var conflict *ConflictError
			if err := m.Apply(context.Background(), p, e, &j, ignoreJournal); !errors.As(err, &conflict) || len(j.Routes) != 0 {
				t.Fatalf("policy route conflict accepted: %v", err)
			}
			for _, call := range r.base.calls[calls:] {
				if slices.Contains(call, "add") || slices.Contains(call, "delete") {
					t.Fatalf("policy conflict caused mutation: %v", call)
				}
			}
		})
	}
}
