package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// commandWait bounds inherited command pipe waits after process termination.
const commandWait = time.Second

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

// Options configures platform paths, command execution and connected-link discovery.
// OS defaults to the runtime platform; discovery and Runner default to host implementations.
// LinkExists includes down/addressless interfaces because resolved state dies on deletion,
// not merely when a link loses its IPv4 address.
// InterfaceIndex supplies read-only kernel identity lookup for native registration and
// reuse-safe cleanup. Missing links return os.ErrNotExist; other errors fail closed.
// Tests must inject Runner before applying resources, even when paths are relocated.
type Options struct {
	Paths           paths.Paths
	OS              string
	Runner          Runner
	Subnets         func() ([]InterfaceSubnet, error)
	LinkExists      func(string) (bool, error)
	VerifyInterface func(string, netip.Addr) error
	InterfaceIndex  func(string) (int, error)
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

// Manager serializes ownership transactions and conflict reservations across profiles.
// Failed cleanup retains reservations, preventing new attempts from overlapping leaks.
type Manager struct {
	mu              sync.Mutex
	transaction     chan struct{}
	os              string
	paths           paths.Paths
	runner          Runner
	subnets         func() ([]InterfaceSubnet, error)
	linkExists      func(string) (bool, error)
	verifyInterface func(string, netip.Addr) error
	active          map[string]tunnel
	interfaceIndex  func(string) (int, error)
	gateways        map[string]*gatewayLease
}

// New initializes an inert adapter without running commands or accessing host paths.
// Unsupported platforms and unsafe resolver locations fail before privileged work.
func New(o Options) (*Manager, error) {
	if o.OS == "" {
		o.OS = runtime.GOOS
	}
	if o.OS != "linux" && o.OS != "darwin" {
		return nil, errors.New("unsupported network platform")
	}
	if o.OS == "darwin" && (!filepath.IsAbs(o.Paths.ResolverDir) || filepath.Clean(o.Paths.ResolverDir) != o.Paths.ResolverDir) {
		return nil, errors.New("invalid resolver directory")
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.Subnets == nil {
		o.Subnets = ConnectedSubnets
	}
	if o.VerifyInterface == nil {
		o.VerifyInterface = verifyInterface
	}
	if o.LinkExists == nil {
		o.LinkExists = InterfaceExists
	}
	if o.InterfaceIndex == nil {
		o.InterfaceIndex = interfaceIndex
	}
	return &Manager{os: o.OS, paths: o.Paths, runner: o.Runner, subnets: o.Subnets, linkExists: o.LinkExists, verifyInterface: o.VerifyInterface, interfaceIndex: o.InterfaceIndex, active: make(map[string]tunnel), gateways: make(map[string]*gatewayLease), transaction: make(chan struct{}, 1)}, nil
}

// CheckUp reserves p's custom prefixes or full mode after inspecting active profiles,
// connected subnets and visible non-default routes. Live links are idempotent; pending
// reservations are revalidated and refreshed. Discovery never holds the state mutex.
// Invalid profiles, discovery failures and conflicts never create a reservation.
func (m *Manager) CheckUp(ctx context.Context, p *profile.Profile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return errors.New("invalid network profile")
	}
	m.mu.Lock()
	current := m.active[p.ID]
	m.mu.Unlock()
	if current.link != "" {
		return nil
	}
	var subnets []InterfaceSubnet
	var routes []JournalRoute
	if p.Routes.Mode == "custom" {
		var err error
		subnets, err = m.subnets()
		if err != nil {
			return errors.New("connected interface discovery failed")
		}
		routes, err = m.routes(ctx)
		if err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.active[p.ID].link != "" {
		return nil
	}
	for id, other := range m.active {
		if id == p.ID {
			continue
		}
		if p.Routes.Mode == "full" && other.profile.Routes.Mode == "full" {
			return &ConflictError{fullTunnelConflict(other.profile, *p)}
		}
		for _, candidate := range p.Routes.Include {
			prefix := netip.MustParsePrefix(candidate)
			for _, configured := range reservationPrefixes(other) {
				if nativeOverlap(prefix, configured) {
					return &ConflictError{profileConflict(other.profile, *p, configured)}
				}
			}
		}
		for _, domain := range p.DNS.Domains {
			if m.os == "darwin" && slices.Contains(other.profile.DNS.Domains, domain) {
				return &ConflictError{"split DNS domain is already owned by another profile"}
			}
		}
	}
	if p.Routes.Mode == "custom" {
		for _, candidate := range p.Routes.Include {
			prefix := netip.MustParsePrefix(candidate)
			for _, subnet := range subnets {
				if prefix.Overlaps(subnet.Prefix) {
					return &ConflictError{fmt.Sprintf("route %s overlaps connected interface %s", candidate, subnet.Interface)}
				}
			}
			for _, route := range routes {
				other := netip.MustParsePrefix(route.CIDR)
				// Ordinary and split default routes are checked separately, not LAN prefixes.
				if other.Bits() > 1 && prefix.Overlaps(other) {
					return &ConflictError{fmt.Sprintf("route %s overlaps existing route %s", candidate, route.CIDR)}
				}
			}
		}
	}
	copy := *p
	copy.Routes.Include = slices.Clone(p.Routes.Include)
	copy.DNS.Domains = slices.Clone(p.DNS.Domains)
	current = m.active[p.ID]
	current.profile = copy
	m.active[p.ID] = current
	return nil
}

// Release discards a pending reservation for id when no network transaction has bound
// a link. Live or failed-cleanup links can only be released by successful Teardown.
// Unknown identities are harmless and no host commands or filesystem writes occur.
func (m *Manager) Release(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active[id].link == "" {
		delete(m.active, id)
	}
}

// beginTransaction serializes network mutations while honoring ctx during contention.
// Reservation checks never acquire this gate; cancellation cannot authorize a mutation.
func (m *Manager) beginTransaction(ctx context.Context) error {
	select {
	case m.transaction <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-m.transaction
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CheckAddresses reserves the negotiated local IPv4 address immediately on receipt.
// A duplicate address on another active attempt is refused before PPP can be confused.
func (m *Manager) CheckAddresses(id string, address netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addresses(id, address)
}

// addresses checks address uniqueness with the caller holding m.mu; invalid or
// unreserved identities fail rather than allowing a tunnel outside conflict policy.
func (m *Manager) addresses(id string, address netip.Addr) error {
	current, ok := m.active[id]
	if !ok || !address.Is4() || address.IsUnspecified() {
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

// Apply installs reserved routes and profile-only split DNS on a verified tunnel link.
// Native attempts require prior RegisterLink and ConfigureNative calls; process attempts
// retain PPP verification. Intent precedes mutation and concrete ownership follows it.
// Failures roll back with an independent bounded context; failed rollback retains metadata.
func (m *Manager) Apply(ctx context.Context, p *profile.Profile, effect session.Effect, j *Journal, persist func(Journal) error) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer func() { <-m.transaction }()
	if p == nil || j == nil || persist == nil || j.Profile != p.ID || j.Attempt != effect.Attempt || effect.Profile != p.ID || !validInterface(effect.Interface) {
		return errors.New("invalid network attempt")
	}
	if err := p.Validate(); err != nil {
		return errors.New("invalid network profile")
	}
	if err := m.validateJournal(*j); err != nil {
		return err
	}
	if p.Backend == "native" {
		if err := m.registeredLink(effect, *j, true); err != nil {
			return err
		}
	} else if j.backendName() != "openfortivpn" || !numberedInterface(effect.Interface, "ppp") || m.verifyInterface(effect.Interface, effect.LocalIP) != nil {
		return &InterfaceError{}
	}
	m.mu.Lock()
	if err := m.addresses(p.ID, effect.LocalIP); err != nil {
		m.mu.Unlock()
		return err
	}
	current := m.active[p.ID]
	current.link, current.attempt = effect.Interface, effect.Attempt
	m.active[p.ID] = current
	m.mu.Unlock()
	j.Interface, j.Backend = effect.Interface, p.Backend
	if err := persist(*j); err != nil {
		return err
	}
	err := m.apply(ctx, p, effect, j, persist)
	if err == nil {
		return nil
	}
	// Cancellation must not suppress rollback, but rollback still has a finite budget.
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rollbackErr := m.teardown(rollbackCtx, *j)
	if rollbackErr == nil {
		j.Routes, j.ResolverFiles, j.DNSConfigured = nil, nil, false
		j.DNSServers, j.DNSDomains, j.GatewayException = nil, nil, nil
		rollbackErr = persist(*j)
	}
	return errors.Join(err, rollbackErr)
}

// apply checks pushed/default routes before any mutation and executes one transaction
// while the command gate is held, never the state mutex. Failures return to rollback.
func (m *Manager) apply(ctx context.Context, p *profile.Profile, effect session.Effect, j *Journal, persist func(Journal) error) error {
	if p.Backend == "native" {
		if err := m.applyNative(ctx, p, effect, j, persist); err != nil {
			return err
		}
	} else if err := m.applyProcessRoutes(ctx, p, effect, j, persist); err != nil {
		return err
	}
	if p.DNS.Mode == "split" && !j.DNSConfigured && len(j.ResolverFiles) == 0 {
		if len(effect.DNS) == 0 {
			return errors.New("split DNS requires negotiated nameservers")
		}
		for _, server := range effect.DNS {
			if !server.IsValid() || server.IsUnspecified() || server.Zone() != "" {
				return errors.New("invalid negotiated nameserver")
			}
		}
		effect.DNS = internalNameservers(effect.DNS)
		if m.os == "darwin" {
			return m.applyResolvers(ctx, p, effect, j, persist)
		}
		return m.applyResolved(ctx, p, effect, j, persist)
	}
	return ctx.Err()
}

// applyProcessRoutes preserves observed PPP routing checks and installs custom routes.
// Every add shares the typed rejection handling used for helper-owned native routes.
func (m *Manager) applyProcessRoutes(ctx context.Context, p *profile.Profile, effect session.Effect, j *Journal, persist func(Journal) error) error {
	routes, err := m.routes(ctx)
	if err != nil {
		return err
	}
	if p.Routes.Mode == "custom" {
		subnets, err := m.subnets()
		if err != nil {
			return errors.New("connected interface discovery failed")
		}
		for _, cidr := range p.Routes.Include {
			prefix := netip.MustParsePrefix(cidr)
			for _, subnet := range subnets {
				if subnet.Interface != effect.Interface && prefix.Overlaps(subnet.Prefix) {
					return &ConflictError{"custom route overlaps a connected interface after negotiation"}
				}
			}
			for _, route := range routes {
				other := netip.MustParsePrefix(route.CIDR)
				if route.Interface != effect.Interface && other.Bits() > 1 && prefix.Overlaps(other) {
					return &ConflictError{"custom route overlaps an existing route after negotiation"}
				}
			}
		}
	}
	if err := m.checkPushedRoutes(p.ID, effect.Interface, routes); err != nil {
		return err
	}
	for _, cidr := range p.Routes.Include {
		route := JournalRoute{CIDR: cidr, Interface: effect.Interface}
		for _, existing := range routes {
			if existing.CIDR == cidr {
				return &ConflictError{"custom route destination already exists"}
			}
		}
		if err := m.addOwnedRoute(ctx, route, j, persist); err != nil {
			return fmt.Errorf("adding custom route %s failed: %w", cidr, err)
		}
	}
	return ctx.Err()
}

// checkPushedRoutes compares the observed table with current reservations under the
// short-held state mutex. Defaults on another active PPP link count as full tunnelling
// regardless of configured mode; overlapping pushed prefixes also fail with CONFLICT.
func (m *Manager) checkPushedRoutes(id, link string, routes []JournalRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active[id].profile.Routes.Mode == "gateway" {
		for _, route := range routes {
			if route.Interface == link && netip.MustParsePrefix(route.CIDR).Bits() <= 1 {
				return &ConflictError{fmt.Sprintf("gateway mode rejects default and split-default routes on the tunnel (%s via %s); use full mode", route.CIDR, route.Gateway)}
			}
		}
	}
	for otherID, other := range m.active {
		if otherID == id {
			continue
		}
		full := other.profile.Routes.Mode == "full"
		for _, route := range routes {
			if route.Interface == other.link && netip.MustParsePrefix(route.CIDR).Bits() <= 1 {
				full = true
			}
		}
		for _, route := range routes {
			if route.Interface != link {
				continue
			}
			prefix := netip.MustParsePrefix(route.CIDR)
			if full && prefix.Bits() <= 1 {
				return &ConflictError{fullTunnelConflict(other.profile, m.active[id].profile)}
			}
			for _, candidate := range reservationPrefixes(other) {
				if prefix.Bits() > 1 && nativeOverlap(prefix, candidate) {
					return &ConflictError{profileConflict(other.profile, m.active[id].profile, candidate)}
				}
			}
			for _, pushed := range routes {
				otherPrefix := netip.MustParsePrefix(pushed.CIDR)
				if pushed.Interface == other.link && prefix.Bits() > 1 && otherPrefix.Bits() > 1 && prefix.Overlaps(otherPrefix) {
					return &ConflictError{profileConflict(other.profile, m.active[id].profile, otherPrefix)}
				}
			}
		}
	}
	return nil
}

// Teardown removes only unchanged owned resources, then releases the profile reservation.
// Failed commands or unsafe records retain the reservation and journal for a retry.
func (m *Manager) Teardown(ctx context.Context, j Journal) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer func() { <-m.transaction }()
	m.mu.Lock()
	current := m.active[j.Profile]
	m.mu.Unlock()
	if current.attempt != 0 && current.attempt != j.Attempt {
		return errors.New("network teardown generation mismatch")
	}
	if err := m.teardown(ctx, j); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.active, j.Profile)
	m.mu.Unlock()
	return nil
}

// Recover reconciles the recorded network ownership after helper process verification.
// It shares idempotent teardown semantics and never signals a PID itself.
func (m *Manager) Recover(ctx context.Context, j Journal) error { return m.Teardown(ctx, j) }

// teardown validates every recorded resource before changing anything, then removes
// matching entries in reverse application order. Missing/changed entries are left alone.
func (m *Manager) teardown(ctx context.Context, j Journal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.validateJournal(j); err != nil {
		return err
	}
	linkOwned := true
	if j.backendName() == "native" {
		var err error
		linkOwned, err = m.nativeLinkPresent(j)
		if err != nil {
			return err
		}
	}
	var failures []error
	if linkOwned && m.os == "linux" && j.DNSConfigured {
		failures = append(failures, m.removeResolved(ctx, j))
	}
	for i := len(j.ResolverFiles) - 1; i >= 0; i-- {
		failures = append(failures, m.removeResolver(j.Profile, j.ResolverFiles[i]))
	}
	if len(j.ResolverFiles) > 0 {
		m.flushResolverCache(ctx)
	}
	if linkOwned && len(j.Routes) > 0 {
		routes, err := m.routes(ctx)
		if err != nil {
			failures = append(failures, err)
		} else {
			for i := len(j.Routes) - 1; i >= 0; i-- {
				for _, actual := range routes {
					if sameRoute(j.Routes[i], actual) {
						if j.backendName() == "native" {
							owned, err := m.nativeLinkPresent(j)
							if err != nil || !owned {
								failures = append(failures, err)
								break
							}
						}
						failures = append(failures, m.changeRoute(ctx, actual, false))
						break
					}
				}
			}
		}
	}
	failures = append(failures, ctx.Err())
	if err := errors.Join(failures...); err != nil {
		return err
	}
	return m.releaseGateway(ctx, j)
}

// InterfaceError refuses network changes when the kernel cannot prove the tunnel link.
// Its fixed diagnostic can be shown to clients without exposing host command output.
type InterfaceError struct{}

// Error returns the public explanation of the refused interface binding.
func (*InterfaceError) Error() string {
	return "tunnel interface missing or does not carry the negotiated local IP"
}

// verifyInterface compares the reported interface and local address with kernel state.
// Missing links, unreadable addresses and mismatches fail before route or DNS writes.
func verifyInterface(name string, address netip.Addr) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	addresses, err := link.Addrs()
	if err != nil {
		return err
	}
	for _, actual := range addresses {
		prefix, err := netip.ParsePrefix(actual.String())
		if err == nil && prefix.Addr().Unmap() == address.Unmap() {
			return nil
		}
	}
	return &InterfaceError{}
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
