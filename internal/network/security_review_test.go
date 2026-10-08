package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// TestKernelInterfaceVerification checks both the real non-privileged kernel read
// and an injected mismatch, which must fail before journalling or host mutations.
func TestKernelInterfaceVerification(t *testing.T) {
	if verifyInterface("fortix-missing", netip.MustParseAddr("192.0.2.1")) == nil {
		t.Fatal("missing interface accepted")
	}
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	verified := false
	for _, link := range links {
		addresses, err := link.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			if err := verifyInterface(link.Name, prefix.Addr()); err != nil {
				t.Fatal("actual kernel address refused")
			}
			if verifyInterface(link.Name, netip.Addr{}) == nil {
				t.Fatal("unassigned address accepted")
			}
			verified = true
			break
		}
	}
	if !verified {
		t.Fatal("host has no interface IPv4 address for verification")
	}
	m, f := testManager(t, "linux")
	p := testProfile("work")
	if err := m.CheckUp(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	calls := len(f.calls)
	m.verifyInterface = func(string, netip.Addr) error { return errors.New("kernel mismatch") }
	j := Journal{Profile: p.ID, Attempt: 1}
	e := session.Effect{Profile: p.ID, Attempt: 1, Interface: "ppp0", LocalIP: netip.MustParseAddr("10.99.0.2")}
	persisted := false
	err = m.Apply(t.Context(), p, e, &j, func(Journal) error { persisted = true; return nil })
	var mismatch *InterfaceError
	if !errors.As(err, &mismatch) || persisted || len(f.calls) != calls || len(j.Routes) != 0 {
		t.Fatal("unverified interface authorized network changes")
	}
}

// TestGatewayModeRejectsOwnDefaults differentiates gateway mode from full mode
// for ordinary and split-default routes on the attempt's own tunnel interface.
func TestGatewayModeRejectsOwnDefaults(t *testing.T) {
	for _, mode := range []string{"gateway", "full"} {
		for _, destination := range []string{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "10.20.0.0/16"} {
			t.Run(mode+"/"+destination, func(t *testing.T) {
				m, f := testManager(t, "linux")
				p := testProfile("work")
				p.Routes, p.DNS = profile.Routes{Mode: mode}, profile.DNS{Mode: "none"}
				if err := m.CheckUp(context.Background(), p); err != nil {
					t.Fatal(err)
				}
				f.routes = []JournalRoute{{CIDR: destination, Interface: "ppp0"}}
				j := Journal{Profile: p.ID, Attempt: 1}
				e := session.Effect{Profile: p.ID, Attempt: 1, Interface: "ppp0", LocalIP: netip.MustParseAddr("10.99.0.2")}
				err := m.Apply(t.Context(), p, e, &j, func(Journal) error { return nil })
				var conflict *ConflictError
				want := mode == "gateway" && netip.MustParsePrefix(destination).Bits() <= 1
				if errors.As(err, &conflict) != want || (!want && err != nil) {
					t.Fatalf("default policy: %v", err)
				}
			})
		}
	}
}
