//go:build darwin || linux

package network

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

// leaseOwner identifies a gateway reference without conflating reconnect generations.
// The enclosing transaction gate protects ownership changes and gateway command I/O.
type leaseOwner struct {
	profile string
	attempt uint64
}

// gatewayLease retains one physical host exception until its last attempt releases it.
// Borrowed host routes are shared but never deleted, including during crash recovery.
type gatewayLease struct {
	resource JournalGateway
	owners   map[leaseOwner]struct{}
}

// physicalInterface accepts bounded interface names only for typed host exceptions.
// Tunnel names, command flags, paths, spaces and non-ASCII bytes are refused.
func physicalInterface(name string) bool {
	if name == "" || len(name) > 16 || validInterface(name) || name[0] == '-' {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// gatewayPath selects the most-specific original physical IPv4 path to the TLS peer.
// Tunnel routes cannot redirect the exception into a VPN; equally specific competing
// physical paths fail instead of guessing. An existing host route is borrowed as-is.
func gatewayPath(ip netip.Addr, routes []JournalRoute) (JournalRoute, bool, error) {
	best := -1
	var selected JournalRoute
	for _, route := range routes {
		prefix := netip.MustParsePrefix(route.CIDR)
		if !prefix.Contains(ip) || !physicalInterface(route.Interface) {
			continue
		}
		if prefix.Bits() < best {
			continue
		}
		best, selected = prefix.Bits(), route
	}
	if best < 0 {
		return JournalRoute{}, false, errors.New("gateway has no original physical path")
	}
	for _, route := range routes {
		prefix := netip.MustParsePrefix(route.CIDR)
		if prefix.Contains(ip) && prefix.Bits() == best && physicalInterface(route.Interface) &&
			(route.Interface != selected.Interface || route.Gateway != selected.Gateway) {
			return JournalRoute{}, false, &ConflictError{"gateway has competing physical paths"}
		}
	}
	borrowed := best == 32
	selected.CIDR = netip.PrefixFrom(ip, 32).String()
	if selected.Gateway == selected.Interface || strings.HasPrefix(selected.Gateway, "link#") {
		selected.Gateway = ""
	}
	if selected.Gateway != "" {
		gateway, err := netip.ParseAddr(selected.Gateway)
		if err != nil || !tunnelAddress(gateway) {
			return JournalRoute{}, false, errors.New("invalid physical gateway")
		}
	}
	return selected, borrowed, nil
}

// changeGateway changes only a validated typed IPv4 host exception through a physical
// link. Fixed argv includes the exact next hop and device; no generic route can use this
// path. Darwin's -ifp chooses the physical interface without creating a scoped route.
func (m *Manager) changeGateway(ctx context.Context, resource JournalGateway, add bool) error {
	if err := validateGateway(resource); err != nil {
		return err
	}
	index, err := m.interfaceIndex(resource.Route.Interface)
	if err != nil || index != resource.Index {
		return &InterfaceError{}
	}
	op := "delete"
	if add {
		op = "add"
	}
	route := resource.Route
	if m.os == "darwin" {
		ip := netip.MustParsePrefix(route.CIDR).Addr().String()
		args := []string{"-n", op, "-host", ip}
		if route.Gateway == "" || route.Gateway == route.Interface || strings.HasPrefix(route.Gateway, "link#") {
			args = append(args, "-interface", route.Interface)
		} else {
			args = append(args, route.Gateway, "-ifp", route.Interface)
		}
		_, err = m.runner.Run(ctx, []string{"/sbin/route"}, args...)
	} else {
		args := []string{"route", op, route.CIDR}
		if route.Gateway != "" {
			args = append(args, "via", route.Gateway)
		}
		args = append(args, "dev", route.Interface)
		_, err = m.runner.Run(ctx, []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip"}, args...)
	}
	return err
}

// validateGateway confines a gateway lease to an IPv4 host route and a physical index.
// Direct-link gateways are accepted for Darwin's verified concrete route spelling.
func validateGateway(resource JournalGateway) error {
	route := resource.Route
	prefix, err := netip.ParsePrefix(route.CIDR)
	if err != nil || !tunnelAddress(prefix.Addr()) || prefix.Bits() != 32 || !physicalInterface(route.Interface) || resource.Index <= 0 {
		return errors.New("invalid gateway exception identity")
	}
	if route.Gateway != "" && route.Gateway != route.Interface && !strings.HasPrefix(route.Gateway, "link#") {
		ip, err := netip.ParseAddr(route.Gateway)
		if err != nil || !tunnelAddress(ip) {
			return errors.New("invalid gateway exception next hop")
		}
	}
	return nil
}

// sameGateway compares shared lease metadata, allowing a direct write-ahead gateway
// to match its concrete Darwin link spelling. Routed replacements never match intents.
func sameGateway(a, b JournalGateway) bool {
	return a.Index == b.Index && a.Owned == b.Owned && (sameRoute(a.Route, b.Route) || sameRoute(b.Route, a.Route))
}

// acquireGateway persists a reference before borrowing or adding the physical host route.
// The actual TLS IPv4 peer comes from Journal.GatewayIP, never a DNS name or PPP peer.
// Definite add failures clear intent and never grant ownership of a racing host route.
// Caller or command-local cancellation retains ambiguous intent for rollback or recovery
// unless collision diagnostics or a competing route identity prove the add was rejected.
func (m *Manager) acquireGateway(ctx context.Context, j *Journal, persist func(Journal) error) error {
	ip, err := netip.ParseAddr(j.GatewayIP)
	if err != nil || !tunnelAddress(ip) {
		return errors.New("invalid TLS gateway address")
	}
	key := netip.PrefixFrom(ip, 32).String()
	owner := leaseOwner{j.Profile, j.Attempt}
	routes, err := m.routes(ctx)
	if err != nil {
		return err
	}
	if shared := m.gateways[key]; shared != nil {
		index, err := m.interfaceIndex(shared.resource.Route.Interface)
		if err != nil || index != shared.resource.Index || !slices.ContainsFunc(routes, func(route JournalRoute) bool { return sameRoute(shared.resource.Route, route) }) {
			return &ConflictError{"shared gateway exception changed"}
		}
		resource := shared.resource
		j.GatewayException = &resource
		if err := persist(*j); err != nil {
			j.GatewayException = nil
			return err
		}
		shared.owners[owner] = struct{}{}
		return nil
	}
	route, borrowed, err := gatewayPath(ip, routes)
	if err != nil {
		return err
	}
	for _, actual := range routes {
		if actual.CIDR == key && !sameRoute(route, actual) {
			return &ConflictError{"gateway host route has a competing path"}
		}
	}
	index, err := m.interfaceIndex(route.Interface)
	if err != nil || index <= 0 {
		return &InterfaceError{}
	}
	resource := JournalGateway{Route: route, Index: index, Owned: !borrowed}
	j.GatewayException = &resource
	if err := persist(*j); err != nil {
		j.GatewayException = nil
		return err
	}
	shared := &gatewayLease{resource: resource, owners: map[leaseOwner]struct{}{owner: {}}}
	m.gateways[key] = shared
	if !borrowed {
		if err := m.changeGateway(ctx, resource, true); err != nil {
			// The runner may time out independently after the host exception was added.
			canceled := ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
			conflict := routeExistsError(err)
			inspectCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			actual, inspectErr := m.routes(inspectCtx)
			cancel()
			for _, existing := range actual {
				if existing.CIDR == key && (!canceled || !sameRoute(resource.Route, existing)) {
					conflict = true
				}
			}
			if !canceled || conflict {
				j.GatewayException = nil
				delete(m.gateways, key)
				if conflict {
					err = &ConflictError{"gateway host route already exists and was not claimed"}
				}
				return errors.Join(err, persist(*j))
			}
			return errors.Join(err, inspectErr)
		}
	}
	actual, err := m.routes(ctx)
	if err != nil {
		return err
	}
	var verified JournalRoute
	found := false
	for _, candidate := range actual {
		if candidate.CIDR == key && !sameRoute(resource.Route, candidate) {
			return &ConflictError{"added gateway exception has a competing path"}
		}
		if sameRoute(resource.Route, candidate) {
			verified, found = candidate, true
		}
	}
	if !found {
		return errors.New("gateway exception could not be verified")
	}
	resource.Route = verified
	shared.resource = resource
	j.GatewayException = &resource
	return persist(*j)
}

// releaseGateway drops one generation's lease and deletes only the final unchanged
// helper-owned host route. Reused physical links and changed routes are left intact.
// The caller holds the transaction gate; failed deletion retains the reference for retry.
func (m *Manager) releaseGateway(ctx context.Context, j Journal) error {
	if j.GatewayException == nil {
		return nil
	}
	resource := *j.GatewayException
	key := resource.Route.CIDR
	owner := leaseOwner{j.Profile, j.Attempt}
	shared := m.gateways[key]
	if shared != nil {
		if !sameGateway(shared.resource, resource) {
			return errors.New("gateway lease journal mismatch")
		}
		if _, exists := shared.owners[owner]; !exists {
			return nil
		}
		if len(shared.owners) > 1 {
			delete(shared.owners, owner)
			return nil
		}
	}
	if resource.Owned {
		index, err := m.interfaceIndex(resource.Route.Interface)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && index == resource.Index {
			routes, err := m.routes(ctx)
			if err != nil {
				return err
			}
			for _, actual := range routes {
				if sameRoute(resource.Route, actual) {
					if err := m.changeGateway(ctx, resource, false); err != nil {
						return err
					}
					break
				}
			}
		}
	}
	delete(m.gateways, key)
	return nil
}

// RecoverAll reconstructs shared host-exception references from every startup journal
// before reconciling any of them. Callers with multiple journals must use this batch
// boundary rather than independent Recover calls, which cannot see other references.
// Invalid or inconsistent records fail before mutation; live reservations are refused.
func (m *Manager) RecoverAll(ctx context.Context, journals []Journal) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer func() { <-m.transaction }()
	m.mu.Lock()
	live := len(m.active) != 0
	m.mu.Unlock()
	if live {
		return errors.New("batch recovery requires no active attempts")
	}
	leases := make(map[string]*gatewayLease)
	for _, j := range journals {
		if err := m.validateJournal(j); err != nil {
			return err
		}
		if j.GatewayException == nil {
			continue
		}
		resource := *j.GatewayException
		key := resource.Route.CIDR
		lease := leases[key]
		if lease == nil {
			lease = &gatewayLease{resource: resource, owners: make(map[leaseOwner]struct{})}
			leases[key] = lease
		} else if !sameGateway(lease.resource, resource) {
			return errors.New("inconsistent recovered gateway exceptions")
		}
		lease.owners[leaseOwner{j.Profile, j.Attempt}] = struct{}{}
	}
	m.gateways = leases
	for _, j := range journals {
		if err := m.teardown(ctx, j); err != nil {
			return err
		}
	}
	return nil
}
