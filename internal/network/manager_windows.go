package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// Runner preserves the helper's injection surface; Windows routes never invoke generic commands.
type Runner interface {
	Run(context.Context, []string, ...string) ([]byte, error)
}

// ExecRunner refuses arbitrary command execution on the native Windows network path.
type ExecRunner struct{}

// Run fails closed; DNS uses its own bounded resolver seam rather than generic argv.
func (ExecRunner) Run(context.Context, []string, ...string) ([]byte, error) {
	return nil, errors.New("network command execution is unsupported on Windows")
}

// CommandError preserves the portable typed diagnostic without exposing command output.
type CommandError struct{ Stderr string }

// Error returns only the stable public diagnostic.
func (*CommandError) Error() string { return "network command failed" }

// Options preserves the helper's portable construction surface without enabling Unix commands.
type Options struct {
	Paths           paths.Paths
	OS              string
	Runner          Runner
	Subnets         func() ([]InterfaceSubnet, error)
	LinkExists      func(string) (bool, error)
	VerifyInterface func(string, netip.Addr) error
	InterfaceIndex  func(string) (int, error)
}

// Manager serializes durable ownership transactions and retains failed-cleanup reservations.
type Manager struct {
	mu           sync.Mutex
	transaction  chan struct{}
	active       map[string]tunnel
	gateways     map[string]*gatewayLease
	api          networkBinding
	resolver     resolverBinding
	store        stateStore
	installation string
	subnets      func() ([]InterfaceSubnet, error)
}

// New is inert; protected state and installation identity are opened on first allocation.
func New(o Options) (*Manager, error) {
	if o.OS != "" && o.OS != "windows" {
		return nil, errors.New("unsupported network platform")
	}
	return &Manager{transaction: make(chan struct{}, 1), active: make(map[string]tunnel), gateways: make(map[string]*gatewayLease), api: ipHelper{}, resolver: newNRPTResolver(), store: protectedState{o.Paths.State}, subnets: o.Subnets}, nil
}

// beginTransaction acquires one cancellable gate for mutations and policy snapshots.
func (m *Manager) beginTransaction(ctx context.Context) error {
	select {
	case m.transaction <- struct{}{}:
		if err := ctx.Err(); err != nil {
			m.endTransaction()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// endTransaction releases the gate after all durable and in-memory changes finish.
func (m *Manager) endTransaction() { <-m.transaction }

// CheckUp preflights transport, DNS namespaces and route reservations before TLS.
func (m *Manager) CheckUp(ctx context.Context, p *profile.Profile) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	if p == nil || p.Validate() != nil {
		return errors.New("invalid network profile")
	}
	if p.Backend != "native" {
		return errors.New("openfortivpn is not supported on Windows")
	}
	intent := &resolverIntent{Mode: p.DNS.Mode, Domains: slices.Clone(p.DNS.Domains)}
	m.mu.Lock()
	registered := m.active[p.ID]
	m.mu.Unlock()
	if p.DNS.Mode == "split" && registered.link != "" {
		j, err := m.loadJournal(p.ID, registered.attempt)
		if err != nil {
			return err
		}
		if j.Resolver != nil {
			intent = j.Resolver
		}
	}
	if err := m.resolver.Apply(ctx, intent, nil); err != nil {
		return err
	}
	var subnets []InterfaceSubnet
	var routes []JournalRoute
	if p.Routes.Mode == "custom" {
		_, discovered, err := m.discover()
		if err != nil {
			return err
		}
		subnets = discovered
		routes, err = m.conflictRoutes(ctx)
		if err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.active[p.ID]
	if current.link != "" {
		return nil
	}
	for id, other := range m.active {
		if id == p.ID {
			continue
		}
		if p.Routes.Mode == "full" && other.profile.Routes.Mode == "full" {
			return &ConflictError{fullTunnelConflict(other.profile, *p)}
		}
		for _, text := range p.Routes.Include {
			prefix := netip.MustParsePrefix(text)
			for _, reserved := range reservationPrefixes(other) {
				if nativeOverlap(prefix, reserved) {
					return &ConflictError{profileConflict(other.profile, *p, reserved)}
				}
			}
		}
	}
	for _, text := range p.Routes.Include {
		prefix := netip.MustParsePrefix(text)
		for _, subnet := range subnets {
			if prefix.Overlaps(subnet.Prefix) {
				return &ConflictError{fmt.Sprintf("route %s overlaps connected interface %s", text, subnet.Interface)}
			}
		}
		for _, route := range routes {
			other := netip.MustParsePrefix(route.CIDR)
			if other.Bits() > 1 && prefix.Overlaps(other) {
				return &ConflictError{fmt.Sprintf("route %s overlaps existing route %s", text, route.CIDR)}
			}
		}
	}
	copy := *p
	copy.Routes.Include, copy.Routes.Exclude, copy.DNS.Domains = slices.Clone(p.Routes.Include), slices.Clone(p.Routes.Exclude), slices.Clone(p.DNS.Domains)
	if p.Routes.PreserveLAN != nil {
		value := *p.Routes.PreserveLAN
		copy.Routes.PreserveLAN = &value
	}
	current.profile = copy
	m.active[p.ID] = current
	return ctx.Err()
}

// Release drops only unused reservations, never a live or failed-cleanup allocation.
func (m *Manager) Release(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active[id].link == "" {
		delete(m.active, id)
	}
}

// CheckAddresses reserves a usable local address without allowing duplicate active endpoints.
func (m *Manager) CheckAddresses(id string, address netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addresses(id, address)
}

// addresses updates a pending endpoint while the caller holds the state mutex.
func (m *Manager) addresses(id string, address netip.Addr) error {
	current, ok := m.active[id]
	if !ok || !tunnelAddress(address) {
		return errors.New("invalid tunnel address reservation")
	}
	if current.configured && current.localIP != address {
		return errors.New("native local address changed within an attempt")
	}
	for otherID, other := range m.active {
		if otherID != id && other.localIP == address {
			return &ConflictError{fmt.Sprintf("local IP %s is already used by active profile %s", address, otherID)}
		}
	}
	current.localIP = address
	m.active[id] = current
	return nil
}

// RegisterLink binds the transport's index to a pre-existing protected allocation ledger.
func (m *Manager) RegisterLink(ctx context.Context, id string, attempt uint64, link backend.LinkIdentity, j *Journal, persist func(Journal) error) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	if j == nil || persist == nil || j.Profile != id || j.Attempt != attempt || attempt == 0 || link.Index <= 0 || int(uint32(link.Index)) != link.Index || link.PID != 0 || link.StartTime != "" || j.PID != 0 || j.StartTime != "" {
		return errors.New("invalid native link registration")
	}
	if err := m.ensureInstallation(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	current, exists := m.active[id]
	m.mu.Unlock()
	if !exists || current.profile.Backend != "native" || (current.attempt != 0 && (current.attempt != attempt || current.identity != link)) {
		return errors.New("native link reservation mismatch")
	}
	adapters, err := m.api.adapters()
	if err != nil {
		return err
	}
	var found adapter
	for _, a := range adapters {
		if a.row.InterfaceIndex == uint32(link.Index) && windows.UTF16ToString(a.row.Alias[:]) == link.Interface {
			found = a
			break
		}
	}
	if found.row.InterfaceLuid == 0 {
		return &InterfaceError{}
	}
	data, err := m.store.read("network-allocation-" + found.row.InterfaceGuid.String() + ".json")
	if err != nil {
		return err
	}
	var record allocationRecord
	if err := decodeRecord(data, &record); err != nil {
		return err
	}
	if record.Version != journalVersion || record.Installation != m.installation || !validAllocation(record.Allocation) || record.Allocation.GUID != found.row.InterfaceGuid || record.Allocation.LUID != found.row.InterfaceLuid || record.Allocation.Name != link.Interface || record.Index != uint32(link.Index) {
		return &InterfaceError{}
	}
	m.mu.Lock()
	for otherID, other := range m.active {
		if otherID != id && other.identity.Index == link.Index {
			m.mu.Unlock()
			return &ConflictError{"native link is already registered to another attempt"}
		}
	}
	// Bind before persistence so a failed write cannot make a live allocation releasable.
	current.link, current.attempt, current.identity = link.Interface, attempt, link
	m.active[id] = current
	m.mu.Unlock()
	j.Version, j.Installation, j.Backend, j.Interface = journalVersion, m.installation, "native", link.Interface
	j.Link, j.Allocation, j.Index = &link, &record.Allocation, record.Index
	return m.save(ctx, j, persist)
}

// registeredLink checks the attempt, allocation and optionally acknowledged address identity.
func (m *Manager) registeredLink(effect session.Effect, j Journal, address bool) error {
	m.mu.Lock()
	current, exists := m.active[effect.Profile]
	m.mu.Unlock()
	if !exists || j.Link == nil || j.Profile != effect.Profile || j.Attempt != effect.Attempt || current.attempt != effect.Attempt || current.identity != effect.Link || *j.Link != effect.Link || effect.Interface != j.Interface || effect.Interface != effect.Link.Interface {
		return &InterfaceError{}
	}
	if _, present, err := m.adapterIdentity(j); err != nil || !present {
		return &InterfaceError{}
	}
	if address {
		if j.Address == nil || j.Address.State != mutationApplied || j.LocalIP != effect.LocalIP.String() {
			return &InterfaceError{}
		}
		row, expected := addressRow(j), addressRow(j)
		if err := m.api.address(&row, "get"); err != nil || !sameAddress(row, expected) || row.DadState != windows.IpDadStatePreferred {
			return &InterfaceError{}
		}
	}
	return nil
}

// ConfigureNative verifies endpoint conflicts, then journals MTU/metric and address creation.
func (m *Manager) ConfigureNative(ctx context.Context, effect session.Effect, j *Journal, persist func(Journal) error) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	if j == nil || persist == nil || !tunnelAddress(effect.LocalIP) || effect.MTU < 68 || effect.MTU > 65535 {
		return errors.New("invalid native link configuration")
	}
	if err := m.validateJournal(*j); err != nil {
		return err
	}
	if err := m.registeredLink(effect, *j, false); err != nil {
		return err
	}
	if j.LocalIP != "" && (j.LocalIP != effect.LocalIP.String() || j.MTU != effect.MTU) {
		return errors.New("native link configuration changed within an attempt")
	}
	if j.GatewayIP == effect.LocalIP.String() {
		return &ConflictError{"native endpoint conflicts with the TLS gateway"}
	}
	_, subnets, err := m.discover()
	if err != nil {
		return err
	}
	for _, subnet := range subnets {
		if subnet.Interface != effect.Interface && subnet.Prefix.Contains(effect.LocalIP) {
			return &ConflictError{"native endpoint overlaps a connected interface"}
		}
	}
	routes, err := m.conflictRoutes(ctx)
	if err != nil {
		return err
	}
	for _, route := range routes {
		prefix := netip.MustParsePrefix(route.CIDR)
		if prefix.Bits() == 0 || !prefix.Contains(effect.LocalIP) {
			continue
		}
		if j.Address != nil && j.Address.State == mutationApplied && route.LUID == j.Allocation.LUID && route.Index == j.Index && prefix == netip.PrefixFrom(effect.LocalIP, 32) && route.Protocol == windows.MIB_IPPROTO_LOCAL {
			continue
		}
		return &ConflictError{"native endpoint is covered by an existing route"}
	}
	m.mu.Lock()
	for id, other := range m.active {
		if id == effect.Profile {
			continue
		}
		for _, prefix := range reservationPrefixes(other) {
			if prefix.Contains(effect.LocalIP) {
				m.mu.Unlock()
				return &ConflictError{"native endpoint overlaps another active reservation"}
			}
		}
	}
	err = m.addresses(effect.Profile, effect.LocalIP)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	j.LocalIP, j.PeerIP, j.MTU = effect.LocalIP.String(), effect.LocalIP.String(), effect.MTU
	if err := m.configureInterface(ctx, j, persist); err != nil {
		return err
	}
	if err := m.configureAddress(ctx, j, persist); err != nil {
		return err
	}
	if err := m.registeredLink(effect, *j, true); err != nil {
		return err
	}
	m.mu.Lock()
	current := m.active[effect.Profile]
	current.configured = true
	m.active[effect.Profile] = current
	m.mu.Unlock()
	return ctx.Err()
}

// ReserveNegotiated exposes conflict checks without performing a native mutation.
func (m *Manager) ReserveNegotiated(ctx context.Context, p *profile.Profile, effect session.Effect) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	j, err := m.loadJournal(effect.Profile, effect.Attempt)
	if err != nil {
		return err
	}
	_, err = m.reserveNegotiated(ctx, p, effect, j)
	return err
}

// reserveNegotiated uses shared excludes, carving and wording with metadata-backed link classes.
func (m *Manager) reserveNegotiated(ctx context.Context, p *profile.Profile, effect session.Effect, j Journal) ([]netip.Prefix, error) {
	if p == nil || p.Validate() != nil || p.Backend != "native" || p.ID != effect.Profile {
		return nil, errors.New("invalid native route reservation")
	}
	if err := m.registeredLink(effect, j, true); err != nil {
		return nil, err
	}
	m.mu.Lock()
	current := m.active[p.ID]
	m.mu.Unlock()
	if !current.configured || current.profile.Routes.Mode != p.Routes.Mode || !slices.Equal(current.profile.Routes.Include, p.Routes.Include) || !slices.Equal(current.profile.Routes.Exclude, p.Routes.Exclude) || preserveLAN(&current.profile) != preserveLAN(p) || current.profile.DNS.Mode != p.DNS.Mode || !slices.Equal(current.profile.DNS.Domains, p.DNS.Domains) {
		return nil, errors.New("native network policy changed within an attempt")
	}
	prefixes, err := negotiatedPrefixes(p, effect)
	if err != nil {
		return nil, err
	}
	_, subnets, err := m.discover()
	if err != nil {
		return nil, err
	}
	if p.Routes.Mode != "custom" && preserveLAN(p) {
		prefixes, err = carveLocalNetworks(prefixes, subnets)
		if err != nil {
			return nil, err
		}
	}
	routes, err := m.conflictRoutes(ctx)
	if err != nil {
		return nil, err
	}
	peer, _ := netip.ParseAddr(j.GatewayIP)
	for _, prefix := range prefixes {
		for _, subnet := range subnets {
			if subnet.Interface != effect.Interface && prefix.Bits() > 1 && prefix.Overlaps(subnet.Prefix) {
				return nil, &ConflictError{lanConflict(prefix, subnet.Prefix, subnet.Interface)}
			}
		}
		for _, route := range routes {
			other := netip.MustParsePrefix(route.CIDR)
			if slices.ContainsFunc(j.Routes, func(owned JournalRoute) bool { return owned.State == mutationApplied && sameRoute(owned, route) }) {
				continue
			}
			if route.LUID == j.Allocation.LUID && route.Index == j.Index && route.Protocol == windows.MIB_IPPROTO_LOCAL && other == netip.PrefixFrom(effect.LocalIP, 32) && prefix.Bits() < 32 {
				continue
			}
			if other.Bits() == 32 && other.Addr() == peer && prefix.Bits() < 32 && physicalInterface(route.Interface) {
				continue
			}
			if other.Bits() == 0 {
				if prefix.Bits() <= 1 && !physicalInterface(route.Interface) {
					return nil, &ConflictError{"another tunnel default route is active"}
				}
				continue
			}
			if prefix == other || nativeOverlap(prefix, other) {
				return nil, &ConflictError{fmt.Sprintf("negotiated route %s overlaps existing route %s", prefix, other)}
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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
	if current.negotiated && !slices.Equal(current.prefixes, prefixes) {
		return nil, errors.New("negotiated routes changed within an attempt")
	}
	current.prefixes, current.negotiated = slices.Clone(prefixes), true
	m.active[p.ID] = current
	return prefixes, ctx.Err()
}

// Apply installs a protected TLS host lease before any selected prefix that could cover it.
// Failure retains durable ownership for helper teardown rather than hiding rollback errors.
func (m *Manager) Apply(ctx context.Context, p *profile.Profile, effect session.Effect, j *Journal, persist func(Journal) error) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	if j == nil || persist == nil || p == nil {
		return errors.New("invalid network attempt")
	}
	if err := m.validateJournal(*j); err != nil {
		return err
	}
	intent := j.Resolver
	if p.DNS.Mode == "split" && intent == nil {
		intent = &resolverIntent{Mode: "split", Installation: j.Installation, Profile: j.Profile, Domains: slices.Clone(p.DNS.Domains), State: mutationIntent}
		for _, server := range internalNameservers(effect.DNS) {
			intent.Servers = append(intent.Servers, server.String())
		}
		if _, err := normalizeServers(intent.Servers); err != nil {
			return err
		}
	}
	if err := m.resolver.Apply(ctx, intent, nil); err != nil {
		return err
	}
	prefixes, err := m.reserveNegotiated(ctx, p, effect, *j)
	if err != nil {
		return err
	}
	peer, _ := netip.ParseAddr(j.GatewayIP)
	if usesNativeDefaults(p, effect) && !tunnelAddress(peer) {
		return errors.New("full tunnel requires the actual IPv4 gateway address")
	}
	if tunnelAddress(peer) && slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(peer) }) {
		if err := m.acquireGateway(ctx, j, persist); err != nil {
			return err
		}
	}
	for _, prefix := range prefixes {
		if err := m.registeredLink(effect, *j, true); err != nil {
			return err
		}
		route := JournalRoute{CIDR: prefix.String(), Interface: j.Interface, LUID: j.Allocation.LUID, Index: j.Index, Metric: 0, Protocol: windows.MIB_IPPROTO_NETMGMT}
		rows, err := m.api.routes()
		if err != nil {
			return err
		}
		owned := false
		for _, row := range rows {
			if row.CIDR != route.CIDR {
				continue
			}
			if sameRoute(row, route) && slices.ContainsFunc(j.Routes, func(record JournalRoute) bool { return record.State == mutationApplied && sameRoute(record, row) }) {
				owned = true
				continue
			}
			return &ConflictError{"native route destination already exists"}
		}
		if !owned {
			if err := m.addOwnedRoute(ctx, route, j, persist); err != nil {
				return err
			}
		}
	}
	if p.DNS.Mode == "split" {
		if j.Resolver == nil {
			j.Resolver = intent
		}
		if err := m.resolver.Apply(ctx, j.Resolver, func() error { return m.save(ctx, j, persist) }); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// loadJournal reads only the authoritative Windows transaction record.
func (m *Manager) loadJournal(id string, attempt uint64) (Journal, error) {
	var j Journal
	if !validProfileID(id) || attempt == 0 {
		return j, errors.New("invalid journal identity")
	}
	data, err := m.store.read(journalName(Journal{Profile: id, Attempt: attempt}))
	if err != nil {
		return j, err
	}
	if err := decodeRecord(data, &j); err != nil {
		return j, err
	}
	if j.Profile != id || j.Attempt != attempt {
		return j, errors.New("journal identity mismatch")
	}
	return j, m.validateJournal(j)
}

// Teardown removes network resources but leaves live transport device closure to the helper.
// The authoritative record overrides stale helper metadata after a failed callback write.
func (m *Manager) Teardown(ctx context.Context, supplied Journal) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	if err := m.ensureInstallation(ctx); err != nil {
		return err
	}
	j, err := m.loadJournal(supplied.Profile, supplied.Attempt)
	if errors.Is(err, os.ErrNotExist) {
		if err := m.missingJournal(supplied); err != nil {
			return err
		}
		m.Release(supplied.Profile)
		return nil
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	current := m.active[j.Profile]
	m.mu.Unlock()
	if current.attempt != 0 && current.attempt != j.Attempt {
		return errors.New("network teardown generation mismatch")
	}
	if err := m.teardown(ctx, &j); err != nil {
		return err
	}
	j.CleanupComplete = true
	j.Routes, j.Address, j.Settings, j.GatewayException, j.Resolver = nil, nil, nil, nil, nil
	return m.save(ctx, &j, nil)
}

// Recover uses the batch boundary even for a single supplied journal so leases are rebuilt.
func (m *Manager) Recover(ctx context.Context, j Journal) error {
	return m.RecoverAll(ctx, []Journal{j})
}

// teardown respects DNS, routes/address, gateway, adapter and metadata dependency order.
func (m *Manager) teardown(ctx context.Context, j *Journal) error {
	if err := m.validateJournal(*j); err != nil {
		return err
	}
	if err := m.resolver.Remove(ctx, j.Resolver); err != nil {
		return err
	}
	if j.Resolver != nil {
		j.Resolver = nil
		if err := m.save(ctx, j, nil); err != nil {
			return err
		}
	}
	if err := m.removeOwnedNetwork(ctx, *j); err != nil {
		return err
	}
	if err := m.releaseGateway(ctx, *j); err != nil {
		return err
	}
	// Retain the allocation and journal until transport Release or startup recovery.
	return nil
}

// FinalizeRelease finishes metadata cleanup after the helper has joined and released transport.
// The reservation remains held until adapter removal and both protected deletions succeed.
func (m *Manager) FinalizeRelease(ctx context.Context, supplied Journal) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	j, err := m.loadJournal(supplied.Profile, supplied.Attempt)
	if err != nil {
		return err
	}
	if !j.CleanupComplete {
		return errors.New("network cleanup must finish before adapter release")
	}
	if _, _, err := m.adapterIdentity(j); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.api.removeAdapter(j.Allocation.GUID); err != nil {
		return err
	}
	if err := m.store.remove(journalName(j)); err != nil {
		return err
	}
	if err := m.store.remove(allocationName(*j.Allocation)); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.active, j.Profile)
	m.mu.Unlock()
	return nil
}
