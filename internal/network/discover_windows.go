package network

import (
	"errors"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// InterfaceSubnet carries the canonical prefix and display alias used by shared policy.
type InterfaceSubnet struct {
	Interface string
	Prefix    netip.Prefix
}

// adapter pairs addresses with kernel metadata; aliases never determine link class.
type adapter struct {
	row      windows.MibIfRow2
	prefixes []netip.Prefix
}

// physicalSnapshot serves the shared policy's name-only classification seam.
// Each successful discovery replaces the whole snapshot; missing aliases fail closed.
var physicalSnapshot = struct {
	sync.RWMutex
	names map[string]bool
}{names: make(map[string]bool)}

// isPhysical requires hardware Ethernet or Wi-Fi metadata, excluding filters/endpoints.
func isPhysical(row windows.MibIfRow2) bool {
	flags := row.InterfaceAndOperStatusFlags
	if flags&1 == 0 || flags&(2|128) != 0 || row.TunnelType != 0 {
		return false
	}
	switch row.Type {
	case windows.IF_TYPE_ETHERNET_CSMACD:
		return row.MediaType == 0 && (row.PhysicalMediumType == 0 || row.PhysicalMediumType == 14)
	case windows.IF_TYPE_IEEE80211:
		return (row.MediaType == 0 || row.MediaType == 16) && (row.PhysicalMediumType == 1 || row.PhysicalMediumType == 9)
	}
	return false
}

// physicalInterface consults only kernel-derived metadata, never alias conventions.
func physicalInterface(name string) bool {
	physicalSnapshot.RLock()
	defer physicalSnapshot.RUnlock()
	return physicalSnapshot.names[name]
}

// publishAdapters makes one complete trusted snapshot available to shared carving.
func publishAdapters(adapters []adapter) {
	names := make(map[string]bool, len(adapters))
	for _, a := range adapters {
		names[windows.UTF16ToString(a.row.Alias[:])] = isPhysical(a.row)
	}
	physicalSnapshot.Lock()
	physicalSnapshot.names = names
	physicalSnapshot.Unlock()
}

// adapters enumerates bounded address data and independently reads hardware metadata.
func (ipHelper) adapters() ([]adapter, error) {
	size := uint32(16384)
	for attempt := 0; attempt < 4; attempt++ {
		if size > 4<<20 {
			return nil, errors.New("adapter table exceeds limit")
		}
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_PREFIX|windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var out []adapter
		for current := first; current != nil; current = current.Next {
			if len(out) >= 4096 {
				return nil, errors.New("too many adapters")
			}
			a := adapter{row: windows.MibIfRow2{InterfaceLuid: current.Luid, InterfaceIndex: current.IfIndex}}
			if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &a.row); err != nil {
				return nil, err
			}
			for address := current.FirstUnicastAddress; address != nil; address = address.Next {
				if len(a.prefixes) >= 4096 {
					return nil, errors.New("too many adapter addresses")
				}
				ip, ok := netip.AddrFromSlice(address.Address.IP())
				if !ok || !ip.Unmap().Is4() {
					continue
				}
				if address.OnLinkPrefixLength > 32 {
					return nil, errors.New("invalid adapter prefix")
				}
				a.prefixes = append(a.prefixes, netip.PrefixFrom(ip.Unmap(), int(address.OnLinkPrefixLength)))
			}
			out = append(out, a)
		}
		return out, nil
	}
	return nil, errors.New("adapter table changed repeatedly")
}

// discover refreshes classification and includes virtual networks as conflict candidates.
func (m *Manager) discover() ([]adapter, []InterfaceSubnet, error) {
	adapters, err := m.api.adapters()
	if err != nil {
		return nil, nil, err
	}
	publishAdapters(adapters)
	var subnets []InterfaceSubnet
	for _, a := range adapters {
		if a.row.OperStatus != windows.IfOperStatusUp || a.row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		for _, prefix := range a.prefixes {
			subnets = append(subnets, InterfaceSubnet{windows.UTF16ToString(a.row.Alias[:]), prefix.Masked()})
		}
	}
	if m.subnets != nil {
		subnets, err = m.subnets()
	}
	return adapters, subnets, err
}

// ConnectedSubnets exposes discovery without permitting any host mutation.
func ConnectedSubnets() ([]InterfaceSubnet, error) {
	m := Manager{api: ipHelper{}}
	_, subnets, err := m.discover()
	return subnets, err
}

// InterfaceExists includes down and addressless adapters and propagates discovery failures.
func InterfaceExists(name string) (bool, error) {
	adapters, err := (ipHelper{}).adapters()
	if err != nil {
		return false, err
	}
	for _, a := range adapters {
		if windows.UTF16ToString(a.row.Alias[:]) == name {
			return true, nil
		}
	}
	return false, nil
}

// adapterIdentity verifies all recorded identifiers before any adapter-scoped mutation.
func (m *Manager) adapterIdentity(j Journal) (adapter, bool, error) {
	adapters, err := m.api.adapters()
	if err != nil {
		return adapter{}, false, err
	}
	if j.Allocation == nil {
		return adapter{}, false, &InterfaceError{}
	}
	for _, a := range adapters {
		if a.row.InterfaceGuid == j.Allocation.GUID {
			if a.row.InterfaceLuid != j.Allocation.LUID || a.row.InterfaceIndex != j.Index || windows.UTF16ToString(a.row.Alias[:]) != j.Allocation.Name {
				return adapter{}, false, &InterfaceError{}
			}
			return a, true, nil
		}
		if a.row.InterfaceLuid == j.Allocation.LUID || a.row.InterfaceIndex == j.Index {
			return adapter{}, false, &InterfaceError{}
		}
	}
	return adapter{}, false, nil
}
