package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

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

// reservationRoutes includes Linux policy routes in conflict discovery without giving
// them an ownership identity. Blackhole, throw, prohibit and unreachable destinations
// can reject an add just like unicast routes; none may be selected for deletion.
// Process routing retains its historical unicast table view through routes.
func (m *Manager) reservationRoutes(ctx context.Context) ([]JournalRoute, error) {
	if m.os != "linux" {
		return m.routes(ctx)
	}
	data, err := m.runner.Run(ctx, []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip"}, "-j", "-4", "route", "show", "table", "main")
	if err != nil {
		return nil, err
	}
	routes, err := parseLinuxRoutes(data)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Destination string `json:"dst"`
		Type        string `json:"type"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, errors.New("invalid reservation route table")
	}
	for _, entry := range entries {
		if entry.Type == "" || entry.Type == "unicast" {
			continue
		}
		prefix, err := routePrefix(entry.Destination)
		if err != nil {
			return nil, errors.New("invalid policy route destination")
		}
		routes = append(routes, JournalRoute{CIDR: prefix.String()})
	}
	return routes, nil
}

// connectedNativeRoute recognizes Darwin's optional kernel local /32 after configuring
// an unnumbered point-to-point link with identical endpoints. Linux assigns no peer and
// gets no main-table host-route exemption; its local address route is in the local table.
// The caller must first verify the registered attempt, kernel index and local address.
// Direct-device spellings and Darwin's local-address gateway are accepted; routed next
// hops and unrelated destinations remain competitors. The route is never required,
// claimed, journaled or deleted by recognition.
func (m *Manager) connectedNativeRoute(current tunnel, route JournalRoute) bool {
	if m.os != "darwin" || !current.configured || !tunnelAddress(current.localIP) {
		return false
	}
	expected := JournalRoute{CIDR: netip.PrefixFrom(current.localIP, 32).String(), Interface: current.identity.Interface}
	return sameRoute(expected, route) || (route.CIDR == expected.CIDR && route.Interface == expected.Interface && route.Gateway == current.localIP.String())
}

// ReserveNegotiated checks native route policy against reservations, connected networks
// and the live table before recording any negotiated destinations. effect must name a
// registered attempt and carry its verified kernel local IPv4 address. No host mutation
// occurs here. Full defaults may cover narrower physical/LAN routes, but cannot compete
// with another tunnel's default or an existing identical /1 route. A broader route may
// cover Darwin's verified local /32 without claiming the kernel-connected route.
// Reservations remain until successful teardown, including later transaction failures.
func (m *Manager) ReserveNegotiated(ctx context.Context, p *profile.Profile, effect session.Effect) error {
	_, err := m.reserveNegotiated(ctx, p, effect, netip.Addr{})
	return err
}

// reserveNegotiated applies reservation checks with an optional recorded TLS peer and
// returns the reserved destinations, which are the only ones Apply may install.
// Only Apply supplies that verified journal address under the transaction gate. A
// broader route may cover its physical host exception without claiming it; acquisition
// separately validates that path before mutation. Unknown peers grant no exemption.
func (m *Manager) reserveNegotiated(ctx context.Context, p *profile.Profile, effect session.Effect, gateway netip.Addr) ([]netip.Prefix, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil || p.Validate() != nil || p.Backend != "native" || effect.Profile != p.ID {
		return nil, errors.New("invalid native route reservation")
	}
	m.mu.Lock()
	current := m.active[p.ID]
	m.mu.Unlock()
	if !current.configured {
		return nil, &InterfaceError{}
	}
	if current.profile.Backend != p.Backend || current.profile.Routes.Mode != p.Routes.Mode ||
		!slices.Equal(current.profile.Routes.Include, p.Routes.Include) || !slices.Equal(current.profile.Routes.Exclude, p.Routes.Exclude) ||
		current.profile.DNS.Mode != p.DNS.Mode ||
		!slices.Equal(current.profile.DNS.Domains, p.DNS.Domains) {
		return nil, errors.New("native network policy changed within an attempt")
	}
	j := Journal{Profile: p.ID, Attempt: current.attempt, Backend: "native", Interface: current.link, Link: &current.identity, LocalIP: current.localIP.String()}
	if err := m.registeredLink(effect, j, true); err != nil {
		return nil, err
	}
	prefixes, err := negotiatedPrefixes(p, effect)
	if err != nil {
		return nil, err
	}
	subnets, err := m.subnets()
	if err != nil {
		return nil, errors.New("connected interface discovery failed")
	}
	if p.Routes.Mode != "custom" && preserveLAN(p) {
		if prefixes, err = carveLocalNetworks(prefixes, subnets); err != nil {
			return nil, err
		}
	}
	routes, err := m.reservationRoutes(ctx)
	if err != nil {
		return nil, err
	}
	for _, prefix := range prefixes {
		for _, subnet := range subnets {
			if subnet.Interface != effect.Interface && prefix.Bits() > 1 && prefix.Overlaps(subnet.Prefix) {
				return nil, &ConflictError{lanConflict(prefix, subnet.Prefix, subnet.Interface)}
			}
		}
		for _, route := range routes {
			other := netip.MustParsePrefix(route.CIDR)
			// Darwin may create a local host route before the first reservation.
			// Only broader policy may cover it; an exact destination remains unowned.
			if prefix.Bits() < other.Bits() && prefix.Contains(other.Addr()) && m.connectedNativeRoute(current, route) {
				continue
			}
			// A protected TLS host path must remain more specific than the tunnel route.
			if other.Bits() == 32 && other.Addr() == gateway && prefix.Bits() < 32 && physicalInterface(route.Interface) {
				continue
			}
			// An owned identical route is acceptable only for an idempotent revalidation.
			if route.Interface == effect.Interface && current.negotiated && slices.Contains(current.prefixes, other) {
				continue
			}
			if other.Bits() == 0 {
				if validInterface(route.Interface) && prefix.Bits() <= 1 {
					return nil, &ConflictError{"another tunnel default route is active"}
				}
				continue
			}
			if nativeOverlap(prefix, other) || prefix == other {
				return nil, &ConflictError{fmt.Sprintf("negotiated route %s overlaps existing route %s", prefix, other)}
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	latest := m.active[p.ID]
	if latest.attempt != effect.Attempt || latest.identity != effect.Link {
		return nil, &InterfaceError{}
	}
	for id, other := range m.active {
		if id == p.ID {
			continue
		}
		if p.Routes.Mode == "full" && other.profile.Routes.Mode == "full" {
			return nil, &ConflictError{fullTunnelConflict(other.profile, *p)}
		}
		for _, prefix := range prefixes {
			for _, reserved := range reservationPrefixes(other) {
				if nativeOverlap(prefix, reserved) {
					return nil, &ConflictError{profileConflict(other.profile, *p, reserved)}
				}
			}
		}
	}
	if latest.negotiated && !slices.Equal(latest.prefixes, prefixes) {
		return nil, errors.New("negotiated routes changed within an attempt")
	}
	latest.prefixes, latest.negotiated = slices.Clone(prefixes), true
	m.active[p.ID] = latest
	return slices.Clone(prefixes), nil
}

// addOwnedRoute journals an add intent and then verifies its concrete kernel identity.
// A definite rejection clears intent. Existing-route failures return a typed conflict,
// never ownership of a competing route, even if the table changed during the command.
// Caller or command-local cancellation retains ambiguous intent only when no competing
// destination is proven, allowing rollback or recovery to remove a completed add.
func (m *Manager) addOwnedRoute(ctx context.Context, route JournalRoute, j *Journal, persist func(Journal) error) error {
	j.Routes = append(j.Routes, route)
	if err := persist(*j); err != nil {
		j.Routes = j.Routes[:len(j.Routes)-1]
		return err
	}
	if err := m.changeRoute(ctx, route, true); err != nil {
		// The runner may reach its own deadline after the kernel accepted the add.
		canceled := ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
		conflict := routeExistsError(err)
		inspectCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		actual, inspectErr := m.routes(inspectCtx)
		cancel()
		for _, existing := range actual {
			if existing.CIDR == route.CIDR && (!canceled || !sameRoute(route, existing)) {
				conflict = true
			}
		}
		if !canceled || conflict {
			j.Routes = j.Routes[:len(j.Routes)-1]
			if conflict {
				err = &ConflictError{"route destination already exists and was not claimed"}
			}
			return errors.Join(err, persist(*j))
		}
		return errors.Join(err, inspectErr)
	}
	actual, err := m.routes(ctx)
	if err != nil {
		return err
	}
	var verified JournalRoute
	found := false
	for _, existing := range actual {
		if existing.CIDR == route.CIDR && !sameRoute(route, existing) {
			return &ConflictError{"added route has a competing live destination"}
		}
		if sameRoute(route, existing) {
			verified, found = existing, true
		}
	}
	if !found {
		return errors.New("added route could not be verified")
	}
	j.Routes[len(j.Routes)-1] = verified
	return persist(*j)
}

// applyNative revalidates the registered identity and route reservation immediately
// before installing native routes. Gateway exceptions are acquired only for full
// defaults or selected prefixes containing the TLS peer. Caller holds the transaction
// gate; every installed prefix has a matching pre-mutation reservation.
func (m *Manager) applyNative(ctx context.Context, p *profile.Profile, effect session.Effect, j *Journal, persist func(Journal) error) error {
	gateway, _ := netip.ParseAddr(j.GatewayIP)
	prefixes, err := m.reserveNegotiated(ctx, p, effect, gateway)
	if err != nil {
		return err
	}
	fullDefault := usesNativeDefaults(p, effect)
	if fullDefault && j.GatewayIP == "" {
		return errors.New("full tunnel requires the actual IPv4 gateway address")
	}
	if j.GatewayIP != "" {
		gateway, err := netip.ParseAddr(j.GatewayIP)
		if err != nil || !tunnelAddress(gateway) {
			return errors.New("invalid TLS gateway address")
		}
		// Unrelated split routes cannot redirect the TLS peer and need no exception.
		if fullDefault || slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(gateway) }) {
			if err := m.acquireGateway(ctx, j, persist); err != nil {
				return err
			}
		}
	}
	for _, prefix := range prefixes {
		if err := m.registeredLink(effect, *j, true); err != nil {
			return err
		}
		route := JournalRoute{CIDR: prefix.String(), Interface: effect.Interface}
		routes, err := m.routes(ctx)
		if err != nil {
			return err
		}
		owned := false
		for _, actual := range routes {
			if actual.CIDR != route.CIDR {
				continue
			}
			for _, recorded := range j.Routes {
				owned = owned || sameRoute(recorded, actual)
			}
			if !owned {
				return &ConflictError{"native route destination already exists"}
			}
		}
		if !owned {
			if err := m.addOwnedRoute(ctx, route, j, persist); err != nil {
				return err
			}
		}
	}
	return nil
}
