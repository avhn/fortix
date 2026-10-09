package network

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// negotiatedPrefixes returns the native destinations selected by validated route mode.
// Untrusted pushed prefixes are bounded and canonical. Gateway mode rejects ordinary
// and split defaults; full mode without splits deliberately uses two IPv4 /1 routes.
func negotiatedPrefixes(p *profile.Profile, effect session.Effect) ([]netip.Prefix, error) {
	if len(effect.PushedPrefixes) > 256 {
		return nil, errors.New("too many negotiated routes")
	}
	for _, prefix := range effect.PushedPrefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return nil, errors.New("invalid negotiated route")
		}
		if p.Routes.Mode == "gateway" && prefix.Bits() <= 1 {
			return nil, &ConflictError{"gateway mode rejects default and split-default routes; use full mode"}
		}
	}
	if p.Routes.Mode == "custom" {
		prefixes := make([]netip.Prefix, 0, len(p.Routes.Include))
		for _, cidr := range p.Routes.Include {
			prefixes = append(prefixes, netip.MustParsePrefix(cidr))
		}
		return prefixes, nil
	}
	if usesNativeDefaults(p, effect) {
		prefixes := make([]netip.Prefix, 0, len(effect.PushedPrefixes)+2)
		prefixes = append(prefixes, netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"))
		for _, prefix := range effect.PushedPrefixes {
			if prefix.Bits() > 1 {
				prefixes = append(prefixes, prefix)
			}
		}
		return excludeRoutes(prefixes, p.Routes.Exclude)
	}
	return excludeRoutes(slices.Clone(effect.PushedPrefixes), p.Routes.Exclude)
}

// excludeRoutes removes the profile's excluded ranges from gateway-selected routes,
// so a range another VPN owns stays with that VPN. A pushed route inside an excluded
// range is dropped and a broader one is split around it. Default halves are left
// alone: the other VPN's narrower route already wins over them.
func excludeRoutes(prefixes []netip.Prefix, exclude []string) ([]netip.Prefix, error) {
	if len(exclude) == 0 {
		return prefixes, nil
	}
	result := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		parts := []netip.Prefix{prefix}
		if prefix.Bits() > 1 {
			for _, text := range exclude {
				excluded := netip.MustParsePrefix(text)
				next := make([]netip.Prefix, 0, len(parts)+1)
				for _, part := range parts {
					next = append(next, subtractPrefix(part, excluded)...)
				}
				parts = next
			}
		}
		result = append(result, parts...)
		if len(result) > maxCarvedRoutes {
			return nil, errors.New("too many routes after applying excluded ranges")
		}
	}
	return result, nil
}

// profileLabel names a profile in user-facing messages, preferring its display name.
func profileLabel(p profile.Profile) string {
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}

// preserveLAN reports the profile's LAN policy; omission keeps the documented default.
func preserveLAN(p *profile.Profile) bool {
	return p.Routes.PreserveLAN == nil || *p.Routes.PreserveLAN
}

// minCarvedLANBits is the broadest local network that may be carved. A network can
// hand out any subnet over DHCP; accepting a broad one would let it pull company
// routes out of the tunnel, so broader overlaps keep refusing the attempt.
const minCarvedLANBits = 16

// maxCarvedRoutes bounds the routes produced by carving, so a hostile push of many
// broad prefixes cannot expand into an unbounded number of kernel routes.
const maxCarvedRoutes = 1024

// carveLocalNetworks removes the networks of physical interfaces (Wi-Fi, Ethernet,
// local bridges) from gateway-selected routes, so the gateway cannot claim the LAN
// the client sits on. A broader route is split into the smallest prefixes that
// cover the rest. Carving fails closed: a local network broader than /16, or one
// that covers a whole pushed route, refuses the attempt instead of moving company
// traffic onto the local network. Default halves are left alone because the
// connected LAN route is already more specific. Tunnel interfaces are not carved:
// a clash with another VPN stays a conflict.
func carveLocalNetworks(prefixes []netip.Prefix, subnets []InterfaceSubnet) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		parts := []netip.Prefix{prefix}
		if prefix.Bits() > 1 {
			for _, subnet := range subnets {
				if !physicalInterface(subnet.Interface) || !subnet.Prefix.IsValid() || !subnet.Prefix.Addr().Is4() {
					continue
				}
				local := subnet.Prefix.Masked()
				if prefix.Overlaps(local) && (local.Bits() < minCarvedLANBits || local.Bits() <= prefix.Bits()) {
					return nil, &ConflictError{lanConflict(prefix, local, subnet.Interface)}
				}
				next := make([]netip.Prefix, 0, len(parts)+1)
				for _, part := range parts {
					next = append(next, subtractPrefix(part, local)...)
				}
				parts = next
			}
		}
		for _, part := range parts {
			if !slices.Contains(result, part) {
				result = append(result, part)
			}
		}
		if len(result) > maxCarvedRoutes {
			return nil, errors.New("too many routes after excluding local networks")
		}
	}
	// Interface enumeration order can differ between checks; a stable order keeps
	// revalidation within one attempt comparing equal lists.
	slices.SortFunc(result, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return result, nil
}

// subtractPrefix returns prefix minus local as disjoint prefixes, largest first.
// Disjoint inputs return prefix unchanged and a covering local returns nothing.
func subtractPrefix(prefix, local netip.Prefix) []netip.Prefix {
	if !prefix.Overlaps(local) {
		return []netip.Prefix{prefix}
	}
	if local.Bits() <= prefix.Bits() {
		return nil
	}
	var result []netip.Prefix
	// Walk down from prefix toward local, keeping the sibling half at each level.
	current := prefix
	for current.Bits() < local.Bits() {
		bits := current.Bits() + 1
		lower := netip.PrefixFrom(current.Addr(), bits)
		upper := netip.PrefixFrom(nextAddr(lower), bits)
		if lower.Contains(local.Addr()) {
			result, current = append(result, upper), lower
		} else {
			result, current = append(result, lower), upper
		}
	}
	return result
}

// nextAddr returns the first IPv4 address after prefix's range.
func nextAddr(prefix netip.Prefix) netip.Addr {
	a := prefix.Addr().As4()
	value := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	value += uint32(1) << (32 - prefix.Bits())
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// usesNativeDefaults identifies full routing with absent splits or pushed defaults.
// Defaults are normalized to two owned /1 routes rather than replacing the LAN default.
func usesNativeDefaults(p *profile.Profile, effect session.Effect) bool {
	return p.Routes.Mode == "full" && (len(effect.PushedPrefixes) == 0 || slices.ContainsFunc(effect.PushedPrefixes, func(prefix netip.Prefix) bool { return prefix.Bits() <= 1 }))
}

// reservationPrefixes returns both configured and negotiated destinations under m.mu.
// Copies prevent mutation of another attempt's policy or aliasing caller-owned slices.
func reservationPrefixes(t tunnel) []netip.Prefix {
	prefixes := slices.Clone(t.prefixes)
	for _, cidr := range t.profile.Routes.Include {
		prefixes = append(prefixes, netip.MustParsePrefix(cidr))
	}
	return prefixes
}

// nativeOverlap checks concrete prefixes while treating defaults as separate policy.
// More-specific physical/LAN routes continue to preserve local access under full mode.
func nativeOverlap(candidate, existing netip.Prefix) bool {
	if candidate.Bits() <= 1 || existing.Bits() <= 1 {
		return candidate.Bits() <= 1 && existing.Bits() <= 1 && candidate.Overlaps(existing)
	}
	return candidate.Overlaps(existing)
}

// ConflictError describes a safe, specific refusal rather than a command diagnostic.
// Helpers map this type to CONFLICT and never automatically retry the attempt.
type ConflictError struct{ Detail string }

// Error returns the non-secret explanation of the refused network configuration.
func (e *ConflictError) Error() string { return e.Detail }

// profileConflict tells the user which connected profile holds a range and what to do.
func profileConflict(other, p profile.Profile, prefix netip.Prefix) string {
	if prefix.Bits() <= 1 {
		return fullTunnelConflict(other, p)
	}
	return fmt.Sprintf("%s is already using %s. Disconnect %s to connect %s, or exclude %s in %s.",
		profileLabel(other), prefix, profileLabel(other), profileLabel(p), prefix, profileLabel(p))
}

// fullTunnelConflict explains that only one profile may carry all traffic at a time.
func fullTunnelConflict(other, p profile.Profile) string {
	return fmt.Sprintf("%s is already sending all traffic through its tunnel. Disconnect %s to connect %s.",
		profileLabel(other), profileLabel(other), profileLabel(p))
}

// lanConflict explains a route that would take over the network the computer is on.
func lanConflict(prefix, local netip.Prefix, iface string) string {
	return fmt.Sprintf("The VPN route %s overlaps your local network %s on %s. Connect from another network, or exclude that range in the profile.",
		prefix, local, iface)
}

// tunnel reserves configured prefixes and full mode while an attempt is in flight.
// Addresses and observed pushed routes are added as negotiation makes them available.
// Only the configured local address can identify a native connected route, so
// caller-supplied peers cannot exempt unrelated destinations from conflict checks.
type tunnel struct {
	profile    profile.Profile
	localIP    netip.Addr
	link       string
	attempt    uint64
	identity   backend.LinkIdentity
	prefixes   []netip.Prefix
	negotiated bool
	configured bool
}

// InterfaceError refuses network changes when the kernel cannot prove the tunnel link.
// Its fixed diagnostic can be shown to clients without exposing host command output.
type InterfaceError struct{}

// Error returns the public explanation of the refused interface binding.
func (*InterfaceError) Error() string {
	return "tunnel interface missing or does not carry the negotiated local IP"
}

// carrierNAT is the RFC 6598 shared address space, used for internal resolvers
// alongside the RFC 1918 ranges that netip.Addr.IsPrivate covers.
var carrierNAT = netip.MustParsePrefix("100.64.0.0/10")

// internalNameservers keeps only private nameservers when the gateway pushes a
// mix. Gateways often append a public resolver such as 8.8.8.8; resolvers query
// every listed server, so its fast NXDOMAIN for internal names would win and be
// cached. If no private server was negotiated, the list is returned unchanged.
func internalNameservers(servers []netip.Addr) []netip.Addr {
	var internal []netip.Addr
	for _, server := range servers {
		if server.IsPrivate() || carrierNAT.Contains(server) {
			internal = append(internal, server)
		}
	}
	if len(internal) == 0 {
		return servers
	}
	return internal
}
