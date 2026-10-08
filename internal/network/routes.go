package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// InterfaceSubnet is a connected link's canonical address prefix used for conflict checks.
// Point-to-point VPN links are included; down interfaces are excluded by discovery.
type InterfaceSubnet struct {
	Interface string
	Prefix    netip.Prefix
}

// ConnectedSubnets discovers IPv4 prefixes on up interfaces without changing the host.
// Interface/address enumeration errors propagate so conflicts never fail open.
func ConnectedSubnets() ([]InterfaceSubnet, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []InterfaceSubnet
	for _, link := range interfaces {
		if link.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := link.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() {
				result = append(result, InterfaceSubnet{link.Name, prefix.Masked()})
			}
		}
	}
	return result, nil
}

// validInterface accepts only the PPP interface names emitted by the VPN parser.
// It prevents whitespace, flags, paths and other devices from reaching privileged argv.
func validInterface(name string) bool {
	if !strings.HasPrefix(name, "ppp") || len(name) < 4 || len(name) > 16 {
		return false
	}
	for _, c := range name[3:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// routes reads the IPv4 main routing table using fixed system command candidates.
// Unsupported or malformed command output fails closed instead of inventing ownership.
func (m *Manager) routes(ctx context.Context) ([]JournalRoute, error) {
	if m.os == "linux" {
		data, err := m.runner.Run(ctx, []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip"}, "-j", "-4", "route", "show", "table", "main")
		if err != nil {
			return nil, err
		}
		return parseLinuxRoutes(data)
	}
	data, err := m.runner.Run(ctx, []string{"/usr/sbin/netstat", "/usr/bin/netstat"}, "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	return parseDarwinRoutes(data)
}

// parseLinuxRoutes decodes bounded iproute2 JSON into unicast IPv4 route identities.
// Empty tables are accepted; malformed destinations, gateways or oversized input fail.
func parseLinuxRoutes(data []byte) ([]JournalRoute, error) {
	if len(data) > 1<<20 || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		return nil, errors.New("invalid route table")
	}
	// Each multipath hop has its own ownership identity on the common destination.
	var entries []struct {
		Destination string `json:"dst"`
		Gateway     string `json:"gateway"`
		Interface   string `json:"dev"`
		Type        string `json:"type"`
		NextHops    []struct {
			Gateway   string `json:"gateway"`
			Interface string `json:"dev"`
		} `json:"nexthops"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, errors.New("invalid route table")
	}
	result := make([]JournalRoute, 0, len(entries))
	for _, entry := range entries {
		if entry.Type != "" && entry.Type != "unicast" {
			continue
		}
		prefix, err := routePrefix(entry.Destination)
		if err != nil {
			return nil, errors.New("invalid route identity")
		}
		if len(entry.NextHops) > 0 {
			for _, hop := range entry.NextHops {
				route, err := linuxRoute(prefix, hop.Gateway, hop.Interface)
				if err != nil {
					return nil, err
				}
				result = append(result, route)
			}
			continue
		}
		route, err := linuxRoute(prefix, entry.Gateway, entry.Interface)
		if err != nil {
			return nil, err
		}
		result = append(result, route)
	}
	return result, nil
}

// linuxRoute returns one unicast route identity for prefix and its direct or routed hop.
// Missing interfaces and invalid IPv4 gateways fail rather than granting ownership.
func linuxRoute(prefix netip.Prefix, gateway, link string) (JournalRoute, error) {
	if link == "" {
		return JournalRoute{}, errors.New("invalid route identity")
	}
	if gateway != "" {
		ip, err := netip.ParseAddr(gateway)
		if err != nil || !ip.Is4() {
			return JournalRoute{}, errors.New("invalid route gateway")
		}
	}
	return JournalRoute{prefix.String(), gateway, link}, nil
}

// parseDarwinRoutes reads netstat's IPv4 table, locating Netif from its header.
// Abbreviated destinations are normalized; unrelated headers are ignored, bad rows fail.
func parseDarwinRoutes(data []byte) ([]JournalRoute, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("invalid route table")
	}
	var result []JournalRoute
	column := -1
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Destination" {
			for i, field := range fields {
				if field == "Netif" {
					column = i
				}
			}
			if column < 3 {
				return nil, errors.New("invalid route header")
			}
			continue
		}
		if column < 0 {
			continue
		}
		if len(fields) <= column {
			return nil, errors.New("invalid route row")
		}
		prefix, err := routePrefix(fields[0])
		if err != nil {
			return nil, err
		}
		// Neighbor-cache entries are not routes installed by the helper.
		if strings.Contains(fields[2], "W") || strings.Contains(fields[2], "L") {
			continue
		}
		result = append(result, JournalRoute{prefix.String(), fields[1], fields[column]})
	}
	if column < 0 {
		return nil, errors.New("missing route table header")
	}
	return result, nil
}

// routePrefix normalizes default, host and abbreviated IPv4 netstat destinations.
// Invalid octets, prefix lengths, scoped addresses and noncanonical network bits fail.
func routePrefix(text string) (netip.Prefix, error) {
	if text == "default" {
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}
	address, length, hasLength := strings.Cut(text, "/")
	parts := strings.Split(address, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Prefix{}, errors.New("invalid route destination")
	}
	bits := len(parts) * 8
	if hasLength {
		var err error
		bits, err = strconv.Atoi(length)
		if err != nil || bits < 0 || bits > 32 {
			return netip.Prefix{}, errors.New("invalid route prefix length")
		}
	}
	var octets [4]byte
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 8)
		if err != nil || strconv.FormatUint(n, 10) != part {
			return netip.Prefix{}, errors.New("invalid route destination")
		}
		octets[i] = byte(n)
	}
	prefix := netip.PrefixFrom(netip.AddrFrom4(octets), bits)
	if prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("unmasked route destination")
	}
	return prefix, nil
}

// changeRoute adds or deletes one validated direct PPP route without invoking a shell.
// Command errors propagate; callers check route ownership before requesting deletion.
func (m *Manager) changeRoute(ctx context.Context, route JournalRoute, add bool) error {
	prefix, err := netip.ParsePrefix(route.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || !validInterface(route.Interface) {
		return errors.New("invalid owned route")
	}
	op := "delete"
	if add {
		op = "add"
	}
	if m.os == "darwin" {
		_, err = m.runner.Run(ctx, []string{"/sbin/route"}, "-n", op, "-net", prefix.String(), "-interface", route.Interface)
	} else {
		args := []string{"route", op, prefix.String(), "dev", route.Interface}
		_, err = m.runner.Run(ctx, []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip"}, args...)
	}
	return err
}

// sameRoute compares destination, interface and gateway, accepting Darwin interface-name
// and link gateways as direct routes only for an empty write-ahead gateway intent.
// Concrete recorded gateways require exact equality so replacement routes survive.
func sameRoute(owned, actual JournalRoute) bool {
	return owned.CIDR == actual.CIDR && owned.Interface == actual.Interface &&
		(owned.Gateway == actual.Gateway || (owned.Gateway == "" && (actual.Gateway == owned.Interface || strings.HasPrefix(actual.Gateway, "link#"))))
}

// InterfaceExists checks whether name is still present, including down/addressless
// links. Enumeration errors propagate; false means per-link resolved state is gone.
func InterfaceExists(name string) (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, link := range interfaces {
		if link.Name == name {
			return true, nil
		}
	}
	return false, nil
}
