package network

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
)

// leaseOwner distinguishes reconnect generations sharing one physical host route.
type leaseOwner struct {
	profile string
	attempt uint64
}

// gatewayLease retains all acknowledged references until the last owner releases it.
type gatewayLease struct {
	resource JournalGateway
	owners   map[leaseOwner]struct{}
	created  bool // Native create succeeded, even if durable acknowledgement failed.
}

// validateGateway restricts leases to the actual TLS peer and a complete physical identity.
func validateGateway(g JournalGateway, peer string) error {
	if err := validateRoute(g.Route); err != nil {
		return err
	}
	prefix := netip.MustParsePrefix(g.Route.CIDR)
	if !validIPv4(peer) || prefix != netip.PrefixFrom(netip.MustParseAddr(peer), 32) || g.GUID == (windows.GUID{}) || g.Index != int(g.Route.Index) || !validState(g.Route.State) || (g.Owned && g.Route.Protocol != windows.MIB_IPPROTO_NETMGMT) {
		return errors.New("invalid gateway exception identity")
	}
	return nil
}

// sameGateway compares ownership as well as every concrete routing identity field.
func sameGateway(a, b JournalGateway) bool {
	return a.GUID == b.GUID && a.Owned == b.Owned && a.Index == b.Index && sameRoute(a.Route, b.Route) && a.Route.State == b.Route.State
}

// gatewayPresent rechecks physical metadata and GUID/index/LUID rather than trusting aliases.
func (m *Manager) gatewayPresent(g JournalGateway) (bool, error) {
	adapters, err := m.api.adapters()
	if err != nil {
		return false, err
	}
	for _, a := range adapters {
		if a.row.InterfaceGuid == g.GUID {
			if a.row.InterfaceLuid != g.Route.LUID || a.row.InterfaceIndex != g.Route.Index || !isPhysical(a.row) {
				return false, errors.New("gateway physical identity changed")
			}
			return true, nil
		}
		if a.row.InterfaceLuid == g.Route.LUID || a.row.InterfaceIndex == g.Route.Index {
			return false, errors.New("gateway interface identity reused")
		}
	}
	return false, nil
}

// acquireGateway borrows an exact physical /32 or creates one before covering tunnel routes.
func (m *Manager) acquireGateway(ctx context.Context, j *Journal, persist func(Journal) error) error {
	if !validIPv4(j.GatewayIP) {
		return errors.New("invalid TLS gateway address")
	}
	peer := netip.MustParseAddr(j.GatewayIP)
	key, owner := netip.PrefixFrom(peer, 32).String(), leaseOwner{j.Profile, j.Attempt}
	rows, err := m.api.routes()
	if err != nil {
		return err
	}
	if lease := m.gateways[key]; lease != nil {
		present, err := m.gatewayPresent(lease.resource)
		if err != nil {
			return err
		}
		if !present || lease.resource.Route.State != mutationApplied || !slices.ContainsFunc(rows, func(row JournalRoute) bool { return sameRoute(row, lease.resource.Route) }) {
			return &ConflictError{"shared gateway exception changed"}
		}
		resource := lease.resource
		j.GatewayException = &resource
		if err := m.save(ctx, j, persist); err != nil {
			return err
		}
		lease.owners[owner] = struct{}{}
		return nil
	}
	original, err := m.api.bestRoute(peer)
	if err != nil {
		return err
	}
	adapters, _, err := m.discover()
	if err != nil {
		return err
	}
	var physical adapter
	for _, a := range adapters {
		if a.row.InterfaceLuid == original.LUID && a.row.InterfaceIndex == original.Index && isPhysical(a.row) {
			physical = a
			break
		}
	}
	if physical.row.InterfaceLuid == 0 {
		return errors.New("gateway has no original physical path")
	}
	borrowed := original.CIDR == key
	original.CIDR, original.Interface = key, windows.UTF16ToString(physical.row.Alias[:])
	if !borrowed {
		original.Protocol = windows.MIB_IPPROTO_NETMGMT
		original.Metric = 0
	}
	for _, row := range rows {
		if row.CIDR == key && (!borrowed || !sameRoute(original, row)) {
			return &ConflictError{"gateway host route has a competing path"}
		}
	}
	original.State = mutationIntent
	if borrowed {
		original.State = mutationApplied
	}
	resource := JournalGateway{Route: original, Index: int(original.Index), Owned: !borrowed, GUID: physical.row.InterfaceGuid}
	j.GatewayException = &resource
	if err := m.save(ctx, j, persist); err != nil {
		return err
	}
	lease := &gatewayLease{resource: resource, owners: map[leaseOwner]struct{}{owner: {}}}
	m.gateways[key] = lease
	if !borrowed {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.api.createRoute(original); err != nil {
			resource.Route.State = mutationRejected
			lease.resource = resource
			j.GatewayException = &resource
			if routeExistsError(err) {
				err = &ConflictError{"gateway host route already exists and was not claimed"}
			}
			return errors.Join(err, m.save(context.WithoutCancel(ctx), j, persist))
		}
		// Successful creation proves ownership before any fallible verification read.
		lease.created = true
		resource.Route.State = mutationApplied
		if err := m.save(context.WithoutCancel(ctx), j, persist); err != nil {
			return err
		}
	}
	rows, err = m.api.routes()
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(rows, func(row JournalRoute) bool { return sameRoute(row, original) }) {
		return errors.New("gateway exception could not be verified")
	}
	// Only durable, verified ownership may be published to another profile.
	lease.resource = resource
	return nil
}

// releaseGateway deletes only the last unchanged owned row; borrowed routes always survive.
func (m *Manager) releaseGateway(ctx context.Context, j Journal) error {
	if j.GatewayException == nil {
		return nil
	}
	resource := *j.GatewayException
	key, owner := resource.Route.CIDR, leaseOwner{j.Profile, j.Attempt}
	lease := m.gateways[key]
	if lease == nil {
		if !resource.Owned || resource.Route.State == mutationRejected {
			return nil
		}
		rows, err := m.api.routes()
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(rows, func(row JournalRoute) bool { return sameRoute(row, resource.Route) }) {
			return nil
		}
		return errors.New("gateway lease references have not been reconstructed")
	}
	identity := lease.resource
	identity.Route.State = resource.Route.State
	if !sameGateway(identity, resource) {
		return errors.New("gateway lease journal mismatch")
	}
	// A rejected create is known not to own a row even if its result write failed.
	if lease.resource.Route.State == mutationRejected && (resource.Route.State == mutationIntent || resource.Route.State == mutationRejected) {
		delete(lease.owners, owner)
		if len(lease.owners) == 0 {
			delete(m.gateways, key)
		}
		return nil
	}
	if _, exists := lease.owners[owner]; !exists {
		return nil
	}
	if len(lease.owners) > 1 {
		delete(lease.owners, owner)
		return nil
	}
	// In-process create acknowledgement and durable sharers both prove ownership.
	if lease.created || lease.resource.Route.State == mutationApplied {
		resource.Route.State = mutationApplied
	}
	if resource.Owned {
		present, err := m.gatewayPresent(resource)
		if err != nil {
			return err
		}
		if present {
			if err := m.removeRoute(ctx, resource.Route); err != nil {
				return err
			}
		}
	}
	delete(m.gateways, key)
	return nil
}

// missingJournal accepts stale helper metadata only after its allocation ledger is gone.
func (m *Manager) missingJournal(j Journal) error {
	if j.Allocation == nil {
		return nil
	}
	_, err := m.store.read(allocationName(*j.Allocation))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("authoritative recovery journal missing; allocation retained")
}

// recoveryRecords reads every protected network record before authorizing any cleanup.
func (m *Manager) recoveryRecords(supplied []Journal) ([]Journal, []allocationRecord, error) {
	names, err := m.store.names()
	if err != nil {
		return nil, nil, err
	}
	records := make(map[string]Journal)
	allocations := make(map[windows.GUID]allocationRecord)
	for _, name := range names {
		if !strings.HasPrefix(name, "network-attempt-") && !strings.HasPrefix(name, "network-allocation-") {
			continue
		}
		data, err := m.store.read(name)
		if err != nil {
			return nil, nil, err
		}
		if strings.HasPrefix(name, "network-attempt-") {
			var j Journal
			if err := decodeRecord(data, &j); err != nil {
				return nil, nil, err
			}
			if err := m.validateJournal(j); err != nil {
				return nil, nil, err
			}
			if journalName(j) != name {
				return nil, nil, errors.New("journal filename identity mismatch")
			}
			records[name] = j
		} else {
			var a allocationRecord
			if err := decodeRecord(data, &a); err != nil {
				return nil, nil, err
			}
			if a.Version != journalVersion || a.Installation != m.installation || !validAllocation(a.Allocation) || allocationName(a.Allocation) != name || (a.Allocation.LUID == 0) != (a.Index == 0) {
				return nil, nil, errors.New("invalid allocation ledger")
			}
			allocations[a.Allocation.GUID] = a
		}
	}
	for _, j := range supplied {
		if !validProfileID(j.Profile) || j.Attempt == 0 {
			return nil, nil, errors.New("invalid supplied recovery identity")
		}
		if _, ok := records[journalName(j)]; !ok && j.Allocation != nil {
			if _, exists := allocations[j.Allocation.GUID]; exists {
				return nil, nil, errors.New("authoritative recovery journal missing; allocation retained")
			}
		}
	}
	var journals []Journal
	seen := make(map[windows.GUID]bool)
	for _, j := range records {
		a, ok := allocations[j.Allocation.GUID]
		if !ok || a.Allocation != *j.Allocation || a.Index != j.Index || seen[a.Allocation.GUID] {
			return nil, nil, errors.New("allocation ledger does not match journal")
		}
		seen[a.Allocation.GUID] = true
		journals = append(journals, j)
	}
	slices.SortFunc(journals, func(a, b Journal) int { return strings.Compare(journalName(a), journalName(b)) })
	var orphans []allocationRecord
	for guid, a := range allocations {
		if !seen[guid] {
			orphans = append(orphans, a)
		}
	}
	return journals, orphans, nil
}

// RecoverAll validates the complete batch, rebuilds references, then follows global cleanup order.
// The service must stop transport before entering this startup-only boundary.
func (m *Manager) RecoverAll(ctx context.Context, supplied []Journal) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	m.mu.Lock()
	live := len(m.active) != 0
	m.mu.Unlock()
	if live {
		return errors.New("batch recovery requires no active attempts")
	}
	if err := m.ensureInstallation(ctx); err != nil {
		return err
	}
	journals, orphans, err := m.recoveryRecords(supplied)
	if err != nil {
		return err
	}
	leases := make(map[string]*gatewayLease)
	for _, j := range journals {
		if j.GatewayException == nil {
			continue
		}
		resource := *j.GatewayException
		key := resource.Route.CIDR
		lease := leases[key]
		if lease == nil {
			lease = &gatewayLease{resource: resource, owners: make(map[leaseOwner]struct{})}
			leases[key] = lease
		} else {
			identity := lease.resource
			identity.Route.State = resource.Route.State
			if !sameGateway(identity, resource) {
				return errors.New("inconsistent recovered gateway exceptions")
			}
			// Any acknowledged sharer proves creation of this exact owned row.
			if resource.Route.State == mutationApplied {
				lease.resource = resource
			}
		}
		lease.owners[leaseOwner{j.Profile, j.Attempt}] = struct{}{}
	}
	// Preserve reconciled ownership if a later failure retains only an intent sharer.
	// Publish every promotion before removing any resource or its proving journal.
	for i := range journals {
		resource := journals[i].GatewayException
		if resource != nil && resource.Route.State == mutationIntent && leases[resource.Route.CIDR].resource.Route.State == mutationApplied {
			resource.Route.State = mutationApplied
			if err := m.save(ctx, &journals[i], nil); err != nil {
				return err
			}
		}
	}
	m.gateways = leases
	// Keep failures scoped to their journal while preserving global cleanup order.
	blocked := make(map[string]bool)
	retained := make(map[string]bool)
	var failures []error
	for _, j := range journals {
		if err := m.resolver.Recover(ctx, j.Resolver); err != nil {
			blocked[journalName(j)] = true
			failures = append(failures, err)
		}
	}
	for _, j := range journals {
		if blocked[journalName(j)] {
			continue
		}
		if err := m.removeOwnedNetwork(ctx, j); err != nil {
			blocked[journalName(j)] = true
			failures = append(failures, err)
		}
	}
	for _, j := range journals {
		if blocked[journalName(j)] {
			continue
		}
		if err := m.releaseGateway(ctx, j); err != nil {
			// Physical route ambiguity retains metadata, not the owned tunnel adapter.
			retained[journalName(j)] = true
			failures = append(failures, err)
		}
	}
	for _, j := range journals {
		if blocked[journalName(j)] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err := m.api.removeAdapter(j.Allocation.GUID); err != nil {
			blocked[journalName(j)] = true
			failures = append(failures, err)
		}
	}
	for _, a := range orphans {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		// The persisted random GUID is checked against the Wintun device identity.
		if err := m.api.removeAdapter(a.Allocation.GUID); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := m.store.remove(allocationName(a.Allocation)); err != nil {
			failures = append(failures, err)
		}
	}
	for _, j := range journals {
		if blocked[journalName(j)] || retained[journalName(j)] {
			continue
		}
		// Delete the journal first so interruption cannot leave it pointing to a missing ledger.
		if err := m.store.remove(journalName(j)); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := m.store.remove(allocationName(*j.Allocation)); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
