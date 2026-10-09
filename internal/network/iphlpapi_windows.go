package network

import (
	"errors"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ipInterfaceRow mirrors the SDK layout, whose offload bitfields are single bytes.
// Keeping this narrow layout avoids treating the final BOOLEAN as part of a ULONG.
type ipInterfaceRow struct {
	Family                                                                                           uint16
	LUID                                                                                             uint64
	Index                                                                                            uint32
	MaxReassemblySize                                                                                uint32
	InterfaceIdentifier                                                                              uint64
	MinRouterAdvertisementInterval, MaxRouterAdvertisementInterval                                   uint32
	AdvertisingEnabled, ForwardingEnabled, WeakHostSend, WeakHostReceive                             uint8
	AutomaticMetric, UseNeighborUnreachabilityDetection                                              uint8
	ManagedAddressConfigurationSupported, OtherStatefulConfigurationSupported, AdvertiseDefaultRoute uint8
	RouterDiscoveryBehavior, DadTransmits, BaseReachableTime, RetransmitTime                         uint32
	PathMtuDiscoveryTimeout, LinkLocalAddressBehavior, LinkLocalAddressTimeout                       uint32
	ZoneIndices                                                                                      [16]uint32
	SitePrefixLength, Metric, MTU                                                                    uint32
	Connected, SupportsWakeUpPatterns, SupportsNeighborDiscovery, SupportsRouterDiscovery            uint8
	ReachableTime                                                                                    uint32
	TransmitOffload, ReceiveOffload, DisableDefaultRoutes                                            uint8
}

// networkBinding isolates IP Helper operations so tests never mutate host networking.
type networkBinding interface {
	adapters() ([]adapter, error)
	routes() ([]JournalRoute, error)
	createRoute(JournalRoute) error
	deleteRoute(JournalRoute) error
	bestRoute(netip.Addr) (JournalRoute, error)
	address(*windows.MibUnicastIpAddressRow, string) error
	ipInterface(*ipInterfaceRow, bool) error
	removeAdapter(windows.GUID) error
}

// ipHelper implements only the native calls used by owned network transactions.
type ipHelper struct{}

var ipHelperDLL = windows.NewLazySystemDLL("iphlpapi.dll")

// ipCall checks export availability and preserves the API's returned status code.
func ipCall(name string, args ...uintptr) error {
	proc := ipHelperDLL.NewProc(name)
	if err := proc.Find(); err != nil {
		return err
	}
	code, _, _ := proc.Call(args...)
	if code != 0 {
		return windows.Errno(code)
	}
	return nil
}

// inet4 creates an IPv4 SOCKADDR_INET without a port or scope identifier.
func inet4(ip netip.Addr) windows.RawSockaddrInet {
	var out windows.RawSockaddrInet
	row := (*windows.RawSockaddrInet4)(unsafe.Pointer(&out))
	row.Family, row.Addr = windows.AF_INET, ip.As4()
	return out
}

// fromInet4 refuses unexpected families instead of interpreting IPv6 bytes as IPv4.
func fromInet4(raw windows.RawSockaddrInet) (netip.Addr, error) {
	row := (*windows.RawSockaddrInet4)(unsafe.Pointer(&raw))
	if row.Family != windows.AF_INET {
		return netip.Addr{}, errors.New("non-IPv4 route")
	}
	return netip.AddrFrom4(row.Addr), nil
}

// routeRow reconstructs the complete mutable route identity, not a destination-only key.
func routeRow(route JournalRoute) (windows.MibIpForwardRow2, error) {
	var row windows.MibIpForwardRow2
	if err := validateRoute(route); err != nil {
		return row, err
	}
	prefix := netip.MustParsePrefix(route.CIDR)
	hop := netip.IPv4Unspecified()
	if route.Gateway != "" {
		hop = netip.MustParseAddr(route.Gateway)
	}
	row.InterfaceLuid, row.InterfaceIndex = route.LUID, route.Index
	row.DestinationPrefix = windows.IpAddressPrefix{Prefix: inet4(prefix.Addr()), PrefixLength: uint8(prefix.Bits())}
	row.NextHop = inet4(hop)
	row.ValidLifetime, row.PreferredLifetime = ^uint32(0), ^uint32(0)
	row.Metric, row.Protocol = route.Metric, route.Protocol
	return row, nil
}

// routeIdentity copies stable SDK fields while ignoring counters and changing lifetimes.
func routeIdentity(row windows.MibIpForwardRow2) (JournalRoute, error) {
	ip, err := fromInet4(row.DestinationPrefix.Prefix)
	if err != nil || row.DestinationPrefix.PrefixLength > 32 {
		return JournalRoute{}, errors.New("invalid route prefix")
	}
	hop, err := fromInet4(row.NextHop)
	if err != nil {
		return JournalRoute{}, err
	}
	r := JournalRoute{CIDR: netip.PrefixFrom(ip, int(row.DestinationPrefix.PrefixLength)).Masked().String(), LUID: row.InterfaceLuid, Index: row.InterfaceIndex, Metric: row.Metric, Protocol: row.Protocol}
	if !hop.IsUnspecified() {
		r.Gateway = hop.String()
	}
	return r, nil
}

// routes copies the bounded IPv4 table before freeing its native allocation.
func (ipHelper) routes() ([]JournalRoute, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, errors.New("missing route table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return nil, errors.New("route table exceeds limit")
	}
	out := make([]JournalRoute, 0, table.NumEntries)
	for _, row := range table.Rows() {
		route, err := routeIdentity(row)
		if err != nil {
			return nil, err
		}
		out = append(out, route)
	}
	return out, nil
}

// createRoute never converts an existing-row error into successful ownership.
func (ipHelper) createRoute(route JournalRoute) error {
	row, err := routeRow(route)
	if err != nil {
		return err
	}
	return ipCall("CreateIpForwardEntry2", uintptr(unsafe.Pointer(&row)))
}

// deleteRoute uses the full key after the manager checks the current metric and protocol.
func (ipHelper) deleteRoute(route JournalRoute) error {
	row, err := routeRow(route)
	if err != nil {
		return err
	}
	return ipCall("DeleteIpForwardEntry2", uintptr(unsafe.Pointer(&row)))
}

// bestRoute asks the kernel for the actual peer's path before covering routes exist.
func (ipHelper) bestRoute(peer netip.Addr) (JournalRoute, error) {
	destination := inet4(peer)
	var row windows.MibIpForwardRow2
	var source windows.RawSockaddrInet
	err := ipCall("GetBestRoute2", 0, 0, 0, uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&source)))
	if err != nil {
		return JournalRoute{}, err
	}
	return routeIdentity(row)
}

// address performs a fixed unicast operation; callers supply only validated rows.
func (ipHelper) address(row *windows.MibUnicastIpAddressRow, operation string) error {
	switch operation {
	case "get":
		return windows.GetUnicastIpAddressEntry(row)
	case "create":
		return ipCall("CreateUnicastIpAddressEntry", uintptr(unsafe.Pointer(row)))
	case "delete":
		return ipCall("DeleteUnicastIpAddressEntry", uintptr(unsafe.Pointer(row)))
	default:
		return errors.New("invalid address operation")
	}
}

// ipInterface reads the complete row before changing only MTU and metric fields.
func (ipHelper) ipInterface(row *ipInterfaceRow, set bool) error {
	name := "GetIpInterfaceEntry"
	if set {
		name = "SetIpInterfaceEntry"
	}
	return ipCall(name, uintptr(unsafe.Pointer(row)))
}
