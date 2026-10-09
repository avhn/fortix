//go:build darwin || linux

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
