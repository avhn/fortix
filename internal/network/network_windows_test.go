package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
	"github.com/avhn/fortix/internal/tun"
)

// SDK layout assertions are compile-time gates on both Windows amd64 and arm64.
// Paired bounds reject either growth or shrinkage without executing a Windows binary.
var (
	_ [104 - unsafe.Sizeof(windows.MibIpForwardRow2{})]byte
	_ [unsafe.Sizeof(windows.MibIpForwardRow2{}) - 104]byte
	_ [80 - unsafe.Sizeof(windows.MibUnicastIpAddressRow{})]byte
	_ [unsafe.Sizeof(windows.MibUnicastIpAddressRow{}) - 80]byte
	_ [1352 - unsafe.Sizeof(windows.MibIfRow2{})]byte
	_ [unsafe.Sizeof(windows.MibIfRow2{}) - 1352]byte
	_ [168 - unsafe.Sizeof(ipInterfaceRow{})]byte
	_ [unsafe.Sizeof(ipInterfaceRow{}) - 168]byte
	_ [84 - unsafe.Offsetof(windows.MibIpForwardRow2{}.Metric)]byte
	_ [unsafe.Offsetof(windows.MibIpForwardRow2{}.Metric) - 84]byte
	_ [32 - unsafe.Offsetof(windows.MibUnicastIpAddressRow{}.InterfaceLuid)]byte
	_ [unsafe.Offsetof(windows.MibUnicastIpAddressRow{}.InterfaceLuid) - 32]byte
	_ [1152 - unsafe.Offsetof(windows.MibIfRow2{}.InterfaceAndOperStatusFlags)]byte
	_ [unsafe.Offsetof(windows.MibIfRow2{}.InterfaceAndOperStatusFlags) - 1152]byte
	_ [166 - unsafe.Offsetof(ipInterfaceRow{}.DisableDefaultRoutes)]byte
	_ [unsafe.Offsetof(ipInterfaceRow{}.DisableDefaultRoutes) - 166]byte
)

// memoryState emulates atomic replacement and injects failure at individual durable boundaries.
type memoryState struct {
	files          map[string][]byte
	writes, failAt int
	events         *[]string
}

// write leaves previous bytes intact on the selected failed atomic publication.
func (s *memoryState) write(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.writes++
	if s.writes == s.failAt {
		return errors.New("injected journal write failure")
	}
	s.files[name] = slices.Clone(data)
	if s.events != nil {
		*s.events = append(*s.events, "write:"+name)
	}
	return nil
}

// read returns a detached snapshot, matching an opened immutable file handle.
func (s *memoryState) read(name string) ([]byte, error) {
	data, ok := s.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return slices.Clone(data), nil
}

// remove records cleanup order and treats already absent metadata as success.
func (s *memoryState) remove(name string) error {
	delete(s.files, name)
	if s.events != nil {
		*s.events = append(*s.events, "remove:"+name)
	}
	return nil
}

// names enumerates a stable snapshot of protected basenames.
func (s *memoryState) names() ([]string, error) {
	var names []string
	for name := range s.files {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

// fakeIPHelper models route/address identities without opening adapters or requiring elevation.
type fakeIPHelper struct {
	links         []adapter
	table         []JournalRoute
	addresses     map[uint64]windows.MibUnicastIpAddressRow
	interfaces    map[uint64]ipInterfaceRow
	events        []string
	createError   error
	beforeCreate  func(JournalRoute)
	verifyFailure string
}

// adapters returns detached kernel metadata snapshots.
func (f *fakeIPHelper) adapters() ([]adapter, error) { return slices.Clone(f.links), nil }

// routes returns a copy so mutation code cannot alter the fake kernel by aliasing slices.
func (f *fakeIPHelper) routes() ([]JournalRoute, error) {
	if f.verifyFailure == "route" {
		for i := len(f.events) - 1; i >= 0; i-- {
			if strings.HasPrefix(f.events[i], "write:") {
				continue
			}
			if strings.HasPrefix(f.events[i], "create-route:") {
				return nil, errors.New("injected verification failure")
			}
			break
		}
	}
	return slices.Clone(f.table), nil
}

// createRoute emulates the native already-exists rejection before any successful creation.
func (f *fakeIPHelper) createRoute(route JournalRoute) error {
	if f.beforeCreate != nil {
		f.beforeCreate(route)
	}
	f.events = append(f.events, "create-route:"+route.CIDR)
	if f.createError != nil {
		return f.createError
	}
	for _, row := range f.table {
		if row.CIDR == route.CIDR && row.LUID == route.LUID && row.Gateway == route.Gateway {
			return windows.ERROR_OBJECT_ALREADY_EXISTS
		}
	}
	f.table = append(f.table, route)
	return nil
}

// deleteRoute records exactly which concrete identity was removed.
func (f *fakeIPHelper) deleteRoute(route JournalRoute) error {
	f.events = append(f.events, "delete-route:"+route.CIDR)
	f.table = slices.DeleteFunc(f.table, func(row JournalRoute) bool { return sameRoute(row, route) })
	return nil
}

// bestRoute selects longest prefix then metric to emulate the original peer lookup.
func (f *fakeIPHelper) bestRoute(peer netip.Addr) (JournalRoute, error) {
	var best JournalRoute
	bits := -1
	for _, row := range f.table {
		prefix := netip.MustParsePrefix(row.CIDR)
		if prefix.Contains(peer) && (prefix.Bits() > bits || prefix.Bits() == bits && row.Metric < best.Metric) {
			best, bits = row, prefix.Bits()
		}
	}
	if bits < 0 {
		return best, windows.ERROR_NOT_FOUND
	}
	return best, nil
}

// address emulates acknowledged manual address creation, reads and deletion.
func (f *fakeIPHelper) address(row *windows.MibUnicastIpAddressRow, operation string) error {
	actual, exists := f.addresses[row.InterfaceLuid]
	switch operation {
	case "get":
		if exists && f.verifyFailure == "address" {
			return errors.New("injected verification failure")
		}
		if !exists {
			return windows.ERROR_NOT_FOUND
		}
		*row = actual
	case "create":
		f.events = append(f.events, "create-address")
		if exists {
			return windows.ERROR_OBJECT_ALREADY_EXISTS
		}
		f.addresses[row.InterfaceLuid] = *row
	case "delete":
		f.events = append(f.events, "delete-address")
		delete(f.addresses, row.InterfaceLuid)
	default:
		return errors.New("unexpected fake operation")
	}
	return nil
}

// ipInterface preserves all unrelated fields while recording settings mutations.
func (f *fakeIPHelper) ipInterface(row *ipInterfaceRow, set bool) error {
	if set {
		f.events = append(f.events, "set-interface")
		f.interfaces[row.LUID] = *row
		return nil
	}
	actual, ok := f.interfaces[row.LUID]
	if !ok {
		return windows.ERROR_NOT_FOUND
	}
	if f.verifyFailure == "settings" && actual.MTU == 1400 {
		return errors.New("injected verification failure")
	}
	*row = actual
	return nil
}

// removeAdapter records the final destructive step and removes only its matching GUID.
func (f *fakeIPHelper) removeAdapter(guid windows.GUID) error {
	f.events = append(f.events, "remove-adapter")
	for _, a := range f.links {
		if a.row.InterfaceGuid == guid {
			f.table = slices.DeleteFunc(f.table, func(row JournalRoute) bool { return row.LUID == a.row.InterfaceLuid })
			delete(f.addresses, a.row.InterfaceLuid)
			delete(f.interfaces, a.row.InterfaceLuid)
		}
	}
	f.links = slices.DeleteFunc(f.links, func(a adapter) bool { return a.row.InterfaceGuid == guid })
	return nil
}

// testAdapter creates SDK-shaped metadata with a deliberately uninformative display alias.
func testAdapter(name string, index uint32, luid uint64, guid windows.GUID, physical bool) adapter {
	a := adapter{row: windows.MibIfRow2{InterfaceIndex: index, InterfaceLuid: luid, InterfaceGuid: guid, OperStatus: windows.IfOperStatusUp, Type: windows.IF_TYPE_ETHERNET_CSMACD}}
	text, _ := windows.UTF16FromString(name)
	copy(a.row.Alias[:], text)
	if physical {
		a.row.InterfaceAndOperStatusFlags = 1
		a.row.PhysicalMediumType = 14
	}
	return a
}

// windowsFixture provides a protected allocation and one independent physical default path.
func windowsFixture(t *testing.T) (*Manager, *fakeIPHelper, *memoryState, Journal) {
	t.Helper()
	m, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	m.installation = "{00000001-0000-0000-0000-000000000001}"
	a := tun.Allocation{GUID: windows.GUID{Data1: 2}, Name: "fortix-0000000000000000", Nonce: strings.Repeat("0", 32), LUID: 22}
	link := backend.LinkIdentity{Interface: a.Name, Index: 22}
	j := Journal{Version: journalVersion, Installation: m.installation, Profile: "first", Attempt: 1, Backend: "native", Interface: a.Name, Link: &link, Allocation: &a, Index: 22, GatewayIP: "203.0.113.10"}
	f := &fakeIPHelper{
		links:     []adapter{testAdapter(a.Name, 22, 22, a.GUID, false), testAdapter("Untrusted friendly name", 3, 3, windows.GUID{Data1: 3}, true)},
		table:     []JournalRoute{{CIDR: "0.0.0.0/0", Gateway: "192.0.2.1", LUID: 3, Index: 3, Metric: 20, Protocol: windows.MIB_IPPROTO_NETMGMT}},
		addresses: make(map[uint64]windows.MibUnicastIpAddressRow), interfaces: map[uint64]ipInterfaceRow{22: {Family: windows.AF_INET, LUID: 22, Index: 22, MTU: 1500, Metric: 25, AutomaticMetric: 1}},
	}
	f.seedLAN("192.168.1.10/24")
	s := &memoryState{files: make(map[string][]byte), events: &f.events}
	m.api, m.store = f, s
	data, _ := json.Marshal(allocationRecord{journalVersion, m.installation, a, 22})
	s.files[allocationName(a)] = data
	if err := m.save(context.Background(), &j, nil); err != nil {
		t.Fatal(err)
	}
	s.writes = 0
	f.events = nil
	return m, f, s, j
}

// windowsProfile creates valid policy without secrets or machine-specific fixture values.
func windowsProfile() *profile.Profile {
	p := &profile.Profile{SchemaVersion: 1, ID: "first", Name: "First VPN", Username: "example", Gateway: profile.Gateway{Host: "example.com", Port: 443}, Backend: "native"}
	p.ApplyDefaults()
	return p
}

// bindFixture reserves and registers a pre-created fake allocation through the public API.
func bindFixture(t *testing.T, m *Manager, j *Journal) (*profile.Profile, session.Effect) {
	t.Helper()
	p := windowsProfile()
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterLink(context.Background(), p.ID, j.Attempt, *j.Link, j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return p, session.Effect{Profile: p.ID, Attempt: j.Attempt, Interface: j.Interface, Link: *j.Link, LocalIP: netip.MustParseAddr("198.51.100.10"), MTU: 1400}
}

// TestWindowsSDKOffsets catches important ABI offsets in addition to compile-time size gates.
func TestWindowsSDKOffsets(t *testing.T) {
	checks := map[string]struct{ got, want uintptr }{
		"route prefix":      {unsafe.Offsetof(windows.MibIpForwardRow2{}.DestinationPrefix), 12},
		"route next hop":    {unsafe.Offsetof(windows.MibIpForwardRow2{}.NextHop), 44},
		"route protocol":    {unsafe.Offsetof(windows.MibIpForwardRow2{}.Protocol), 88},
		"address prefix":    {unsafe.Offsetof(windows.MibUnicastIpAddressRow{}.OnLinkPrefixLength), 60},
		"interface metric":  {unsafe.Offsetof(ipInterfaceRow{}.Metric), 148},
		"interface mtu":     {unsafe.Offsetof(ipInterfaceRow{}.MTU), 152},
		"interface offload": {unsafe.Offsetof(ipInterfaceRow{}.TransmitOffload), 164},
	}
	for name, check := range checks {
		if check.got != check.want {
			t.Errorf("%s offset = %d, want %d", name, check.got, check.want)
		}
	}
}

// TestWindowsRouteCollision proves an existing route is never adopted or later deleted.
func TestWindowsRouteCollision(t *testing.T) {
	m, f, _, j := windowsFixture(t)
	baseline := len(f.table)
	route := JournalRoute{CIDR: "198.51.100.0/24", Interface: j.Interface, LUID: 22, Index: 22, Protocol: windows.MIB_IPPROTO_NETMGMT}
	f.table = append(f.table, route)
	f.createError = windows.ERROR_OBJECT_ALREADY_EXISTS
	err := m.addOwnedRoute(context.Background(), route, &j, func(Journal) error { return nil })
	var conflict *ConflictError
	if !errors.As(err, &conflict) || j.Routes[0].State != mutationRejected {
		t.Fatalf("collision: %v, %v", err, j.Routes)
	}
	if err := m.removeRoute(context.Background(), j.Routes[0]); err != nil {
		t.Fatal(err)
	}
	if len(f.table) != baseline+1 {
		t.Fatal("foreign row was deleted")
	}
}

// TestWindowsDeleteIdentity checks every ownership field and pending/rejected states.
func TestWindowsDeleteIdentity(t *testing.T) {
	for _, field := range []string{"prefix", "hop", "luid", "index", "metric", "protocol", "pending", "rejected", "exact"} {
		t.Run(field, func(t *testing.T) {
			m, f, _, _ := windowsFixture(t)
			owned := JournalRoute{CIDR: "198.51.100.0/24", LUID: 22, Index: 22, Metric: 5, Protocol: 3, State: mutationApplied}
			actual := owned
			switch field {
			case "prefix":
				actual.CIDR = "192.0.2.0/24"
			case "hop":
				actual.Gateway = "192.0.2.1"
			case "luid":
				actual.LUID++
			case "index":
				actual.Index++
			case "metric":
				actual.Metric++
			case "protocol":
				actual.Protocol++
			case "pending":
				owned.State = mutationIntent
			case "rejected":
				owned.State = mutationRejected
			}
			f.table = []JournalRoute{actual}
			err := m.removeRoute(context.Background(), owned)
			if field == "pending" && err == nil {
				t.Fatal("ambiguous ownership accepted")
			}
			if field == "exact" && len(f.table) != 0 {
				t.Fatal("owned route remains")
			}
			if field != "exact" && len(f.table) != 1 {
				t.Fatal("changed or unowned route deleted")
			}
		})
	}
}

// TestWindowsPhysicalClassification refuses virtual Ethernet and misleading friendly names.
func TestWindowsPhysicalClassification(t *testing.T) {
	m, f, _, _ := windowsFixture(t)
	physical := f.links[1]
	for _, tc := range []struct {
		name   string
		mutate func(*windows.MibIfRow2)
		want   bool
	}{
		{"hardware", func(*windows.MibIfRow2) {}, true},
		{"virtual ethernet", func(r *windows.MibIfRow2) { r.InterfaceAndOperStatusFlags = 0 }, false},
		{"filter", func(r *windows.MibIfRow2) { r.InterfaceAndOperStatusFlags |= 2 }, false},
		{"endpoint", func(r *windows.MibIfRow2) { r.InterfaceAndOperStatusFlags |= 128 }, false},
		{"unknown medium", func(r *windows.MibIfRow2) { r.PhysicalMediumType = 12 }, false},
		{"wifi", func(r *windows.MibIfRow2) {
			r.Type = windows.IF_TYPE_IEEE80211
			r.MediaType = 16
			r.PhysicalMediumType = 9
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := physical.row
			tc.mutate(&row)
			if isPhysical(row) != tc.want {
				t.Fatalf("classification=%v", isPhysical(row))
			}
		})
	}
	f.links[0].prefixes = prefixes("198.51.100.0/24")
	_, subnets, err := m.discover()
	if err != nil {
		t.Fatal(err)
	}
	input := prefixes("198.51.0.0/16")
	got, err := carveLocalNetworks(input, subnets)
	if err != nil || !slices.Equal(got, input) {
		t.Fatalf("virtual adapter carved: %v %v", got, err)
	}
	f.links[1].prefixes = prefixes("198.50.0.0/15")
	_, subnets, err = m.discover()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := carveLocalNetworks(input, subnets); err == nil {
		t.Fatal("broad physical LAN accepted")
	}
}

// TestWindowsGatewayLeases distinguishes borrowed, owned and shared host exceptions.
func TestWindowsGatewayLeases(t *testing.T) {
	for _, borrow := range []bool{false, true} {
		t.Run(fmt.Sprintf("borrow-%v", borrow), func(t *testing.T) {
			m, f, _, j := windowsFixture(t)
			baseline := len(f.table)
			if borrow {
				row := f.table[0]
				row.CIDR = j.GatewayIP + "/32"
				f.table = append(f.table, row)
			}
			if err := m.acquireGateway(context.Background(), &j, nil); err != nil {
				t.Fatal(err)
			}
			if j.GatewayException.Owned == borrow {
				t.Fatal("wrong lease ownership")
			}
			second := j
			second.Profile = "second"
			second.GatewayException = nil
			if err := m.acquireGateway(context.Background(), &second, nil); err != nil {
				t.Fatal(err)
			}
			if err := m.releaseGateway(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			if len(f.table) != baseline+1 {
				t.Fatal("shared route released early")
			}
			if err := m.releaseGateway(context.Background(), second); err != nil {
				t.Fatal(err)
			}
			want := baseline
			if borrow {
				want = baseline + 1
			}
			if len(f.table) != want {
				t.Fatalf("routes=%v", f.table)
			}
		})
	}
}

// TestWindowsRouteWriteBoundaries keeps every failed publication safe to inspect and retry.
func TestWindowsRouteWriteBoundaries(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			m, f, s, j := windowsFixture(t)
			baseline := len(f.table)
			s.failAt = failAt
			route := JournalRoute{CIDR: "198.51.100.0/24", Interface: j.Interface, LUID: 22, Index: 22, Protocol: 3}
			if err := m.addOwnedRoute(context.Background(), route, &j, nil); err == nil {
				t.Fatal("write failure hidden")
			}
			stored, err := m.loadJournal(j.Profile, j.Attempt)
			if err != nil {
				t.Fatal(err)
			}
			if failAt == 1 {
				if len(stored.Routes) != 0 || len(f.table) != baseline {
					t.Fatal("mutation preceded durable intent")
				}
			} else {
				if len(stored.Routes) != 1 || stored.Routes[0].State != mutationIntent || len(f.table) != baseline+1 {
					t.Fatal("ambiguous create lost its intent")
				}
				if err := m.removeRoute(context.Background(), stored.Routes[0]); err == nil {
					t.Fatal("unacknowledged ownership deleted")
				}
			}
			assertBoundaryRecovery(t, m, f, s, j, false)
		})
	}
}

// TestWindowsConfigureWriteBoundaries covers settings and address intent/result publications.
func TestWindowsConfigureWriteBoundaries(t *testing.T) {
	for boundary := 1; boundary <= 4; boundary++ {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			m, f, s, j := windowsFixture(t)
			_, effect := bindFixture(t, m, &j)
			s.failAt = s.writes + boundary
			if err := m.ConfigureNative(context.Background(), effect, &j, func(Journal) error { return nil }); err == nil {
				t.Fatal("write failure hidden")
			}
			stored, err := m.loadJournal(j.Profile, j.Attempt)
			if err != nil {
				t.Fatal(err)
			}
			if boundary == 1 && interfaceSettings(f.interfaces[22]).MTU != 1500 {
				t.Fatal("settings changed before intent")
			}
			if boundary == 2 && (stored.Settings == nil || stored.Settings.State != mutationIntent) {
				t.Fatal("settings intent lost")
			}
			if boundary == 3 && len(f.addresses) != 0 {
				t.Fatal("address changed before intent")
			}
			if boundary == 4 && (stored.Address == nil || stored.Address.State != mutationIntent) {
				t.Fatal("address intent lost")
			}
			assertBoundaryRecovery(t, m, f, s, j, false)
		})
	}
}

// TestWindowsGatewayWriteBoundaries retains safe intent around host-route publication.
func TestWindowsGatewayWriteBoundaries(t *testing.T) {
	for boundary := 1; boundary <= 2; boundary++ {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			m, f, s, j := windowsFixture(t)
			baseline := len(f.table)
			s.failAt = boundary
			if err := m.acquireGateway(context.Background(), &j, nil); err == nil {
				t.Fatal("write failure hidden")
			}
			stored, err := m.loadJournal(j.Profile, j.Attempt)
			if err != nil {
				t.Fatal(err)
			}
			if boundary == 1 && (stored.GatewayException != nil || len(f.table) != baseline) {
				t.Fatal("gateway changed before intent")
			}
			if boundary == 2 && (stored.GatewayException == nil || stored.GatewayException.Route.State != mutationIntent || len(f.table) != baseline+1) {
				t.Fatal("gateway intent lost")
			}
			if err := m.Teardown(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			if len(f.table) != baseline {
				t.Fatal("acknowledged gateway survived teardown")
			}
			assertBoundaryRecovery(t, m, f, s, j, false)
		})
	}
}

// TestWindowsFullTunnelLifecycle exercises the public surface with a fake native kernel.
func TestWindowsFullTunnelLifecycle(t *testing.T) {
	for _, lan := range []string{"192.168.1.10/24", "10.1.2.10/24"} {
		for _, pushed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/pushed-%v", lan, pushed), func(t *testing.T) {
				m, f, _, j := windowsFixture(t)
				f.seedLAN(lan)
				baseline := len(f.table)
				p := windowsProfile()
				p.Routes.Mode = "full"
				if p.Routes.PreserveLAN != nil && !*p.Routes.PreserveLAN {
					t.Fatal("fixture disabled default LAN preservation")
				}
				if err := m.CheckUp(context.Background(), p); err != nil {
					t.Fatal(err)
				}
				if err := m.RegisterLink(context.Background(), p.ID, j.Attempt, *j.Link, &j, func(Journal) error { return nil }); err != nil {
					t.Fatal(err)
				}
				effect := session.Effect{Profile: p.ID, Attempt: j.Attempt, Interface: j.Interface, Link: *j.Link, LocalIP: netip.MustParseAddr("198.51.100.10"), MTU: 1400}
				if pushed {
					effect.PushedPrefixes = prefixes("0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2")
				}
				if err := m.ConfigureNative(context.Background(), effect, &j, func(Journal) error { return nil }); err != nil {
					t.Fatal(err)
				}
				if err := m.Apply(context.Background(), p, effect, &j, func(Journal) error { return nil }); err != nil {
					t.Fatal(err)
				}
				gateway := slices.Index(f.events, "create-route:203.0.113.10/32")
				if gateway < 0 || (pushed && len(j.Routes) <= 4) || (!pushed && len(j.Routes) != 2) || len(f.table) != baseline+len(j.Routes)+1 {
					t.Fatalf("application order: %v", f.events)
				}
				for _, route := range j.Routes {
					if slices.Index(f.events, "create-route:"+route.CIDR) <= gateway || pushed && netip.MustParsePrefix(route.CIDR).Overlaps(netip.MustParsePrefix(lan).Masked()) {
						t.Fatalf("gateway ordering or LAN carving failed: %v", route)
					}
				}
				if err := m.Teardown(context.Background(), j); err != nil {
					t.Fatal(err)
				}
				if len(f.table) != baseline || len(f.addresses) != 0 || f.interfaces[22].MTU != 1500 {
					t.Fatalf("resources leaked: %v", f.events)
				}
				if err := m.FinalizeRelease(context.Background(), j); err != nil {
					t.Fatal(err)
				}
				if len(m.active) != 0 {
					t.Fatal("reservation leaked")
				}
			})
		}
	}
}

// TestWindowsGatewayExcludes uses shared exclusion policy before route installation.
func TestWindowsGatewayExcludes(t *testing.T) {
	m, _, _, j := windowsFixture(t)
	p := windowsProfile()
	p.Routes.Exclude = []string{"198.51.100.0/24"}
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterLink(context.Background(), p.ID, j.Attempt, *j.Link, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	effect := session.Effect{Profile: p.ID, Attempt: j.Attempt, Interface: j.Interface, Link: *j.Link, LocalIP: netip.MustParseAddr("192.0.2.10"), MTU: 1400, PushedPrefixes: prefixes("198.51.100.0/24", "203.0.113.128/25")}
	if err := m.ConfigureNative(context.Background(), effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background(), p, effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(j.Routes) != 1 || j.Routes[0].CIDR != "203.0.113.128/25" {
		t.Fatalf("excluded route installed: %v", j.Routes)
	}
}

// TestWindowsRecoveryOrder validates all records before mutations and removes adapters last.
func TestWindowsRecoveryOrder(t *testing.T) {
	m, f, s, j := windowsFixture(t)
	p, effect := bindFixture(t, m, &j)
	if err := m.ConfigureNative(context.Background(), effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	effect.PushedPrefixes = prefixes("203.0.113.0/24")
	if err := m.Apply(context.Background(), p, effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	m.active = make(map[string]tunnel)
	f.events = nil
	s.files["network-attempt-broken-1.json"] = []byte(`{"version":999}`)
	if err := m.RecoverAll(context.Background(), nil); err == nil || len(f.events) != 0 {
		t.Fatalf("invalid batch mutated: %v %v", err, f.events)
	}
	delete(s.files, "network-attempt-broken-1.json")
	if err := m.RecoverAll(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	route := slices.Index(f.events, "delete-route:203.0.113.0/24")
	address := slices.Index(f.events, "delete-address")
	gateway := slices.Index(f.events, "delete-route:203.0.113.10/32")
	device := slices.Index(f.events, "remove-adapter")
	if route < 0 || address < route || gateway < address || device < gateway {
		t.Fatalf("recovery order: %v", f.events)
	}
	if _, exists := s.files[journalName(j)]; exists {
		t.Fatal("recovered journal retained")
	}
}

// TestWindowsSplitDNSRefusal rejects a conflicting namespace before link or route mutation.
func TestWindowsSplitDNSRefusal(t *testing.T) {
	m, f, s, _ := windowsFixture(t)
	m.resolver = fakeResolver(&fakeNRPTRunner{policies: []nrptRule{{Namespaces: []string{".example.com"}}}})
	p := windowsProfile()
	p.DNS.Mode = "split"
	p.DNS.Domains = []string{"example.com"}
	err := m.CheckUp(context.Background(), p)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || len(f.events) != 0 || s.writes != 0 {
		t.Fatalf("split DNS refusal: %v %v", err, f.events)
	}
}

// recordingResolver makes DNS recovery order observable without implementing namespace mutations.
type recordingResolver struct{ events *[]string }

// Apply acknowledges only the no-DNS test seam.
func (r recordingResolver) Apply(context.Context, *resolverIntent, func() error) error { return nil }

// Remove records resolver removal before any adapter-dependent operation.
func (r recordingResolver) Remove(context.Context, *resolverIntent) error {
	*r.events = append(*r.events, "resolver-remove")
	return nil
}

// Recover records the independent recovery phase, including cache flushing responsibility.
func (r recordingResolver) Recover(context.Context, *resolverIntent) error {
	*r.events = append(*r.events, "resolver-recover")
	return nil
}

// TestWindowsSharedLeaseRecovery rebuilds references from distinct allocation journals.
func TestWindowsSharedLeaseRecovery(t *testing.T) {
	m, f, s, first := windowsFixture(t)
	baseline := len(f.table)
	if err := m.acquireGateway(context.Background(), &first, nil); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Profile = "second"
	second.GatewayException = nil
	allocation := *first.Allocation
	allocation.GUID, allocation.LUID = windows.GUID{Data1: 4}, 44
	allocation.Nonce, allocation.Name = strings.Repeat("1", 32), "fortix-1111111111111111"
	link := backend.LinkIdentity{Interface: allocation.Name, Index: 44}
	second.Allocation, second.Link, second.Index, second.Interface = &allocation, &link, 44, allocation.Name
	f.links = append(f.links, testAdapter(allocation.Name, 44, 44, allocation.GUID, false))
	data, _ := json.Marshal(allocationRecord{journalVersion, m.installation, allocation, 44})
	s.files[allocationName(allocation)] = data
	if err := m.acquireGateway(context.Background(), &second, nil); err != nil {
		t.Fatal(err)
	}
	// Simulate a new helper process with no memory of lease owners.
	m.gateways = make(map[string]*gatewayLease)
	f.events = nil
	m.resolver = recordingResolver{&f.events}
	if err := m.RecoverAll(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range f.events {
		if event == "delete-route:203.0.113.10/32" {
			count++
		}
	}
	if count != 1 || len(f.table) != baseline-2 {
		t.Fatalf("shared exception cleanup: %v", f.events)
	}
	if len(f.events) < 3 || f.events[0] != "resolver-recover" || f.events[1] != "resolver-recover" {
		t.Fatalf("resolver recovery order: %v", f.events)
	}
	if slices.Index(f.events, "remove-adapter") < slices.Index(f.events, "delete-route:203.0.113.10/32") {
		t.Fatalf("adapter removed before last lease: %v", f.events)
	}
}

// TestWindowsAllocationHookBoundaries keeps the pre-create ledger when identity publication fails.
func TestWindowsAllocationHookBoundaries(t *testing.T) {
	for boundary := 1; boundary <= 2; boundary++ {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			m, _, s, j := windowsFixture(t)
			delete(s.files, allocationName(*j.Allocation))
			a := *j.Allocation
			a.LUID = 0
			s.failAt = boundary
			err := m.AllocationHook(a)
			if boundary == 1 {
				if err == nil {
					t.Fatal("pre-create failure hidden")
				}
				if _, exists := s.files[allocationName(a)]; exists {
					t.Fatal("failed intent published")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			a.LUID = j.Allocation.LUID
			if err := m.AllocationHook(a); err == nil {
				t.Fatal("identity write failure hidden")
			}
			data, err := s.read(allocationName(a))
			if err != nil {
				t.Fatal(err)
			}
			var record allocationRecord
			if err := decodeRecord(data, &record); err != nil {
				t.Fatal(err)
			}
			if record.Allocation.LUID != 0 || record.Index != 0 {
				t.Fatal("failed identity publication replaced pre-create intent")
			}
		})
	}
}

// TestWindowsVirtualReservationConflict refuses unknown virtual overlaps rather than carving them.
func TestWindowsVirtualReservationConflict(t *testing.T) {
	m, f, _, j := windowsFixture(t)
	p, effect := bindFixture(t, m, &j)
	if err := m.ConfigureNative(context.Background(), effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	other := testAdapter("Ethernet", 50, 50, windows.GUID{Data1: 50}, false)
	other.prefixes = prefixes("203.0.113.0/24")
	f.links = append(f.links, other)
	effect.PushedPrefixes = prefixes("203.0.0.0/16")
	err := m.ReserveNegotiated(context.Background(), p, effect)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || !strings.Contains(err.Error(), "overlaps your local network") {
		t.Fatalf("virtual overlap was carved: %v", err)
	}
}

// TestWindowsForeignAddressSurvives checks that changed address identity also prevents adapter removal.
func TestWindowsForeignAddressSurvives(t *testing.T) {
	m, f, _, j := windowsFixture(t)
	_, effect := bindFixture(t, m, &j)
	if err := m.ConfigureNative(context.Background(), effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	row := f.addresses[22]
	row.OnLinkPrefixLength = 24
	f.addresses[22] = row
	if err := m.Teardown(context.Background(), j); err == nil {
		t.Fatal("changed address ownership accepted")
	}
	if len(f.addresses) != 1 || slices.Contains(f.events, "remove-adapter") {
		t.Fatal("foreign address or adapter deleted")
	}
}

// TestWindowsUnboundAttemptRecovery accepts failures before native link registration.
func TestWindowsUnboundAttemptRecovery(t *testing.T) {
	m, f, s, j := windowsFixture(t)
	delete(s.files, journalName(j))
	initial := Journal{Profile: j.Profile, Attempt: j.Attempt, Backend: "native"}
	if err := m.Teardown(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	if len(f.events) != 0 {
		t.Fatal("unbound teardown touched a possibly live allocation")
	}
	if err := m.RecoverAll(context.Background(), []Journal{initial}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.events, "remove-adapter") {
		t.Fatal("orphan allocation was not recovered")
	}
}

// TestWindowsResolverIntentWithoutAdapter retains changed DNS ownership independently of links.
func TestWindowsResolverIntentWithoutAdapter(t *testing.T) {
	m, f, _, j := windowsFixture(t)
	j.Resolver = nrptFixtureIntent(j, true)
	if err := m.save(context.Background(), &j, nil); err != nil {
		t.Fatal(err)
	}
	rule := intentRule(j.Resolver)
	rule.Comment = "changed by another administrator"
	m.resolver = fakeResolver(&fakeNRPTRunner{rules: []nrptRule{rule}})
	f.links = f.links[1:]
	f.events = nil
	if err := m.RecoverAll(context.Background(), nil); err == nil {
		t.Fatal("changed DNS ownership discarded")
	}
	if len(f.events) != 0 {
		t.Fatalf("mutated before resolver recovery: %v", f.events)
	}
}

// seedLAN models connected, loopback, multicast and broadcast rows on a Windows host.
func (f *fakeIPHelper) seedLAN(lan string) {
	connected := netip.MustParsePrefix(lan)
	f.links[1].prefixes = []netip.Prefix{connected}
	loopback := testAdapter("Loopback", 1, 1, windows.GUID{Data1: 1}, false)
	loopback.row.Type = windows.IF_TYPE_SOFTWARE_LOOPBACK
	loopback.prefixes = prefixes("127.0.0.1/8")
	f.links = slices.DeleteFunc(f.links, func(a adapter) bool { return a.row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK })
	f.links = append(f.links, loopback)
	f.table = f.table[:1]
	broadcast := connected.Masked().Addr().As4()
	for bit := connected.Bits(); bit < 32; bit++ {
		broadcast[bit/8] |= 1 << (7 - bit%8)
	}
	for _, cidr := range []string{connected.Masked().String(), netip.PrefixFrom(connected.Addr(), 32).String(), netip.PrefixFrom(netip.AddrFrom4(broadcast), 32).String()} {
		f.table = append(f.table, JournalRoute{CIDR: cidr, LUID: 3, Index: 3, Protocol: windows.MIB_IPPROTO_LOCAL})
	}
	for _, cidr := range []string{"127.0.0.0/8", "127.0.0.1/32", "127.255.255.255/32"} {
		f.table = append(f.table, JournalRoute{CIDR: cidr, LUID: 1, Index: 1, Protocol: windows.MIB_IPPROTO_LOCAL})
	}
	for _, a := range f.links {
		for _, cidr := range []string{"224.0.0.0/4", "255.255.255.255/32"} {
			f.table = append(f.table, JournalRoute{CIDR: cidr, LUID: a.row.InterfaceLuid, Index: a.row.InterfaceIndex, Protocol: windows.MIB_IPPROTO_LOCAL})
		}
	}
}

// recoveryNeighbor persists an unrelated allocation, optionally without a bound journal.
func recoveryNeighbor(t *testing.T, m *Manager, f *fakeIPHelper, s *memoryState, id uint32, orphan bool) Journal {
	t.Helper()
	a := tun.Allocation{GUID: windows.GUID{Data1: id}, LUID: uint64(id), Nonce: strings.Repeat(fmt.Sprint(id%10), 32)}
	a.Name = "fortix-" + a.Nonce[:16]
	link := backend.LinkIdentity{Interface: a.Name, Index: int(id)}
	j := Journal{Version: journalVersion, Installation: m.installation, Profile: fmt.Sprintf("neighbor%d", id), Attempt: 1, Backend: "native", Interface: a.Name, Link: &link, Allocation: &a, Index: id}
	f.links = append(f.links, testAdapter(a.Name, id, uint64(id), a.GUID, false))
	data, err := json.Marshal(allocationRecord{journalVersion, m.installation, a, id})
	if err != nil {
		t.Fatal(err)
	}
	s.files[allocationName(a)] = data
	if !orphan {
		if err := m.save(context.Background(), &j, nil); err != nil {
			t.Fatal(err)
		}
	}
	return j
}

// assertBoundaryRecovery proves ambiguous physical ownership cannot strand owned adapters or peers.
func assertBoundaryRecovery(t *testing.T, m *Manager, f *fakeIPHelper, s *memoryState, j Journal, retain bool) {
	t.Helper()
	s.failAt, f.verifyFailure = 0, ""
	neighbor := recoveryNeighbor(t, m, f, s, 44, false)
	orphan := recoveryNeighbor(t, m, f, s, 55, true)
	m.active = make(map[string]tunnel)
	m.gateways = make(map[string]*gatewayLease)
	for pass := 0; pass < 2; pass++ {
		err := m.RecoverAll(context.Background(), []Journal{j, neighbor})
		if (err != nil) != retain {
			t.Fatalf("recovery pass %d: %v, retained=%v", pass, err, retain)
		}
		for _, record := range []Journal{j, neighbor, orphan} {
			if slices.ContainsFunc(f.links, func(a adapter) bool { return a.row.InterfaceGuid == record.Allocation.GUID }) {
				t.Fatalf("allocation remains for %s", record.Profile)
			}
			_, journalExists := s.files[journalName(record)]
			_, ledgerExists := s.files[allocationName(*record.Allocation)]
			wantRetained := retain && record.Profile == j.Profile
			if journalExists != wantRetained || ledgerExists != wantRetained {
				t.Fatalf("metadata for %s: journal=%v ledger=%v", record.Profile, journalExists, ledgerExists)
			}
		}
		if slices.ContainsFunc(f.table, func(row JournalRoute) bool { return row.LUID == j.Allocation.LUID }) || len(f.addresses) != 0 {
			t.Fatal("owned adapter routes or address remain")
		}
		gatewayPresent := slices.ContainsFunc(f.table, func(row JournalRoute) bool { return row.CIDR == j.GatewayIP+"/32" && row.LUID == 3 })
		if gatewayPresent != retain {
			t.Fatalf("physical gateway present=%v, retained=%v", gatewayPresent, retain)
		}
	}
}

// TestWindowsVerificationRecovery covers successful native writes whose verification read fails.
func TestWindowsVerificationRecovery(t *testing.T) {
	for _, operation := range []string{"route", "address", "settings", "gateway"} {
		t.Run(operation, func(t *testing.T) {
			m, f, s, j := windowsFixture(t)
			j.LocalIP, j.PeerIP, j.MTU = "198.51.100.10", "198.51.100.10", 1400
			f.verifyFailure = operation
			var err error
			switch operation {
			case "route":
				err = m.addOwnedRoute(context.Background(), JournalRoute{CIDR: "0.0.0.0/1", Interface: j.Interface, LUID: 22, Index: 22, Protocol: windows.MIB_IPPROTO_NETMGMT}, &j, nil)
			case "address":
				err = m.configureAddress(context.Background(), &j, nil)
			case "settings":
				err = m.configureInterface(context.Background(), &j, nil)
			case "gateway":
				f.verifyFailure = "route"
				err = m.acquireGateway(context.Background(), &j, nil)
			}
			if err == nil || !strings.Contains(err.Error(), "injected verification failure") {
				t.Fatalf("verification failure hidden: %v", err)
			}
			assertBoundaryRecovery(t, m, f, s, j, false)
		})
	}
}

// TestWindowsGatewayUnpublishedLease refuses sharing after an acknowledgement write fails.
func TestWindowsGatewayUnpublishedLease(t *testing.T) {
	m, f, s, first := windowsFixture(t)
	s.failAt = 2
	if err := m.acquireGateway(context.Background(), &first, nil); err == nil {
		t.Fatal("write failure hidden")
	}
	second := recoveryNeighbor(t, m, f, s, 44, false)
	second.GatewayIP = first.GatewayIP
	var conflict *ConflictError
	if err := m.acquireGateway(context.Background(), &second, nil); !errors.As(err, &conflict) {
		t.Fatalf("unpublished lease was shared: %v", err)
	}
	if err := m.Teardown(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	assertBoundaryRecovery(t, m, f, s, first, false)
}

// TestWindowsMixedGatewayRecovery accepts legacy intent/applied sharers in either load order.
func TestWindowsMixedGatewayRecovery(t *testing.T) {
	for _, appliedFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(appliedFirst), func(t *testing.T) {
			m, f, s, first := windowsFixture(t)
			s.failAt = 2
			if err := m.acquireGateway(context.Background(), &first, nil); err == nil {
				t.Fatal("write failure hidden")
			}
			second := recoveryNeighbor(t, m, f, s, 44, false)
			second.GatewayIP = first.GatewayIP
			resource := *first.GatewayException
			second.GatewayException = &resource
			// Older code allowed a sharer to persist applied while its creator retained intent.
			if err := m.save(context.Background(), &second, nil); err != nil {
				t.Fatal(err)
			}
			if appliedFirst {
				if err := m.save(context.Background(), &first, nil); err != nil {
					t.Fatal(err)
				}
				second.GatewayException.Route.State = mutationIntent
				if err := m.save(context.Background(), &second, nil); err != nil {
					t.Fatal(err)
				}
			}
			m.gateways = make(map[string]*gatewayLease)
			s.failAt = s.writes + 1
			if err := m.RecoverAll(context.Background(), nil); err == nil {
				t.Fatal("ownership promotion write failure hidden")
			}
			if slices.Contains(f.events, "delete-route:203.0.113.10/32") || slices.Contains(f.events, "remove-adapter") {
				t.Fatal("cleanup preceded durable ownership promotion")
			}
			s.failAt = 0
			for pass := 0; pass < 2; pass++ {
				if err := m.RecoverAll(context.Background(), nil); err != nil {
					t.Fatal(err)
				}
			}
			count := 0
			for _, event := range f.events {
				if event == "delete-route:203.0.113.10/32" {
					count++
				}
			}
			if count != 1 || len(s.files) != 0 {
				t.Fatalf("mixed-state cleanup: deletes=%d metadata=%d", count, len(s.files))
			}
		})
	}
}

// TestWindowsGatewayCrashIntent retains a row without a durable or live create acknowledgement.
func TestWindowsGatewayCrashIntent(t *testing.T) {
	m, f, s, j := windowsFixture(t)
	s.failAt = 2
	if err := m.acquireGateway(context.Background(), &j, nil); err == nil {
		t.Fatal("write failure hidden")
	}
	// Discarding live ownership models interruption before acknowledgement reached disk.
	assertBoundaryRecovery(t, m, f, s, j, true)
}

// TestWindowsResolverTeardown clears successfully removed DNS intent before completing cleanup.
func TestWindowsResolverTeardown(t *testing.T) {
	m, f, _, j := windowsFixture(t)
	j.Resolver = nrptFixtureIntent(j, true)
	if err := m.save(context.Background(), &j, nil); err != nil {
		t.Fatal(err)
	}
	m.resolver = recordingResolver{&f.events}
	if err := m.Teardown(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	stored, err := m.loadJournal(j.Profile, j.Attempt)
	if err != nil || !stored.CleanupComplete || stored.Resolver != nil {
		t.Fatalf("resolver cleanup not persisted: %+v, %v", stored, err)
	}
	if err := m.FinalizeRelease(context.Background(), j); err != nil {
		t.Fatal(err)
	}
}

// TestWindowsStaleHelperJournal accepts the crash window after final network metadata deletion.
func TestWindowsStaleHelperJournal(t *testing.T) {
	m, _, s, j := windowsFixture(t)
	if err := m.Teardown(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if err := m.FinalizeRelease(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if err := m.Teardown(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if err := m.RecoverAll(context.Background(), []Journal{j}); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(allocationRecord{journalVersion, m.installation, *j.Allocation, j.Index})
	s.files[allocationName(*j.Allocation)] = data
	if err := m.Teardown(context.Background(), j); err == nil {
		t.Fatal("missing journal with retained ledger accepted by teardown")
	}
	if err := m.RecoverAll(context.Background(), []Journal{j}); err == nil {
		t.Fatal("missing journal with retained ledger accepted by recovery")
	}
}

// TestWindowsRejectedGatewayWriteFailure releases the reservation without claiming a foreign row.
func TestWindowsRejectedGatewayWriteFailure(t *testing.T) {
	m, f, s, j := windowsFixture(t)
	_, _ = bindFixture(t, m, &j)
	s.failAt = s.writes + 2
	f.createError = windows.ERROR_OBJECT_ALREADY_EXISTS
	f.beforeCreate = func(route JournalRoute) { f.table = append(f.table, route) }
	if err := m.acquireGateway(context.Background(), &j, nil); err == nil {
		t.Fatal("rejected create and failed result write hidden")
	}
	if err := m.Teardown(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if err := m.FinalizeRelease(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if len(m.active) != 0 || len(m.gateways) != 0 {
		t.Fatal("rejected create retained a reservation")
	}
	if !slices.ContainsFunc(f.table, func(row JournalRoute) bool { return row.CIDR == j.GatewayIP+"/32" }) {
		t.Fatal("foreign physical row was deleted")
	}
}

// TestWindowsSystemRoutePolicy filters only kernel rows and keeps real connected conflicts.
func TestWindowsSystemRoutePolicy(t *testing.T) {
	m, f, _, _ := windowsFixture(t)
	for _, row := range f.table[1:] {
		if !systemRoute(row, f.links) {
			t.Fatalf("system row remains: %v", row)
		}
	}
	for _, row := range []JournalRoute{
		{CIDR: "192.168.1.0/24", LUID: 3, Index: 3, Protocol: windows.MIB_IPPROTO_NETMGMT},
		{CIDR: "192.168.1.0/24", LUID: 99, Index: 99, Protocol: windows.MIB_IPPROTO_LOCAL},
		{CIDR: "203.0.113.0/24", LUID: 3, Index: 3, Protocol: windows.MIB_IPPROTO_LOCAL},
	} {
		if systemRoute(row, f.links) {
			t.Fatalf("competing row filtered: %v", row)
		}
	}
	p := windowsProfile()
	p.Routes.Mode, p.Routes.Include = "custom", []string{"127.0.0.0/8"}
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatalf("loopback system rows blocked custom include: %v", err)
	}
	m.Release(p.ID)
	p.Routes.Include = []string{"192.168.1.0/24"}
	var conflict *ConflictError
	if err := m.CheckUp(context.Background(), p); !errors.As(err, &conflict) {
		t.Fatalf("connected subnet conflict lost: %v", err)
	}
}

// TestWindowsIntentCleanupRequiresAllocationIdentity refuses an adapter whose identity changed.
func TestWindowsIntentCleanupRequiresAllocationIdentity(t *testing.T) {
	m, f, s, j := windowsFixture(t)
	s.failAt = 2
	if err := m.addOwnedRoute(context.Background(), JournalRoute{CIDR: "0.0.0.0/1", Interface: j.Interface, LUID: 22, Index: 22, Protocol: windows.MIB_IPPROTO_NETMGMT}, &j, nil); err == nil {
		t.Fatal("result publication failure hidden")
	}
	f.links[0].row.InterfaceLuid++
	if err := m.Teardown(context.Background(), j); err == nil {
		t.Fatal("changed allocation accepted during intent cleanup")
	}
	neighbor := recoveryNeighbor(t, m, f, s, 44, false)
	if err := m.RecoverAll(context.Background(), nil); err == nil {
		t.Fatal("changed allocation accepted during recovery")
	}
	if _, exists := s.files[journalName(j)]; !exists {
		t.Fatal("uncertain allocation journal discarded")
	}
	if _, exists := s.files[journalName(neighbor)]; exists {
		t.Fatal("unrelated recovery was blocked")
	}
	if !slices.ContainsFunc(f.links, func(a adapter) bool { return a.row.InterfaceGuid == j.Allocation.GUID }) {
		t.Fatal("changed allocation removed")
	}
}

// TestWindowsIntentTeardown defers unacknowledged tunnel resources to verified adapter removal.
func TestWindowsIntentTeardown(t *testing.T) {
	for _, operation := range []string{"route", "address", "settings"} {
		t.Run(operation, func(t *testing.T) {
			m, f, s, j := windowsFixture(t)
			j.LocalIP, j.PeerIP, j.MTU = "198.51.100.10", "198.51.100.10", 1400
			s.failAt = 2
			var err error
			switch operation {
			case "route":
				err = m.addOwnedRoute(context.Background(), JournalRoute{CIDR: "0.0.0.0/1", Interface: j.Interface, LUID: 22, Index: 22, Protocol: windows.MIB_IPPROTO_NETMGMT}, &j, nil)
			case "address":
				err = m.configureAddress(context.Background(), &j, nil)
			case "settings":
				err = m.configureInterface(context.Background(), &j, nil)
			}
			if err == nil {
				t.Fatal("result publication failure hidden")
			}
			if err := m.Teardown(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			if err := m.FinalizeRelease(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			if slices.ContainsFunc(f.links, func(a adapter) bool { return a.row.InterfaceGuid == j.Allocation.GUID }) || len(f.addresses) != 0 || slices.ContainsFunc(f.table, func(row JournalRoute) bool { return row.LUID == j.Allocation.LUID }) {
				t.Fatal("intent resource stranded on owned adapter")
			}
		})
	}
}
