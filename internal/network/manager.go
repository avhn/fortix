package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

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

// Options configures platform paths, command execution and connected-link discovery.
// OS defaults to the runtime platform; discovery and Runner default to host implementations.
// LinkExists includes down/addressless interfaces because resolved state dies on deletion,
// not merely when a link loses its IPv4 address.
// Tests must inject Runner before applying resources, even when paths are relocated.
type Options struct {
	Paths      paths.Paths
	OS         string
	Runner     Runner
	Subnets    func() ([]InterfaceSubnet, error)
	LinkExists func(string) (bool, error)
}

// tunnel reserves configured prefixes and full mode while an attempt is in flight.
// Addresses and observed pushed routes are added as negotiation makes them available.
type tunnel struct {
	profile profile.Profile
	localIP netip.Addr
	link    string
}

// Manager serializes ownership transactions and conflict reservations across profiles.
// Failed cleanup retains reservations, preventing new attempts from overlapping leaks.
type Manager struct {
	mu          sync.Mutex
	transaction chan struct{}
	os          string
	paths       paths.Paths
	runner      Runner
	subnets     func() ([]InterfaceSubnet, error)
	linkExists  func(string) (bool, error)
	active      map[string]tunnel
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
	if o.LinkExists == nil {
		o.LinkExists = InterfaceExists
	}
	return &Manager{os: o.OS, paths: o.Paths, runner: o.Runner, subnets: o.Subnets, linkExists: o.LinkExists, active: make(map[string]tunnel), transaction: make(chan struct{}, 1)}, nil
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
			return &ConflictError{"another full tunnel is active"}
		}
		for _, candidate := range p.Routes.Include {
			prefix := netip.MustParsePrefix(candidate)
			for _, configured := range other.profile.Routes.Include {
				if prefix.Overlaps(netip.MustParsePrefix(configured)) {
					return &ConflictError{fmt.Sprintf("route %s overlaps active profile %s", candidate, other.profile.ID)}
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
	for otherID, other := range m.active {
		if otherID != id && other.localIP == address {
			return &ConflictError{fmt.Sprintf("local IP %s is already used by active profile %s", address, otherID)}
		}
	}
	current.localIP = address
	m.active[id] = current
	return nil
}

// Apply installs custom routes and split DNS on effect.Interface, journalling intent
// before each mutation and concrete ownership immediately afterwards. Failures roll back
// with an independent bounded context; failed rollback keeps metadata for later teardown.
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
	m.mu.Lock()
	if err := m.addresses(p.ID, effect.LocalIP); err != nil {
		m.mu.Unlock()
		return err
	}
	current := m.active[p.ID]
	current.link = effect.Interface
	m.active[p.ID] = current
	m.mu.Unlock()
	j.Interface = effect.Interface
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
		j.DNSServers, j.DNSDomains = nil, nil
		rollbackErr = persist(*j)
	}
	return errors.Join(err, rollbackErr)
}

// apply checks pushed/default routes before any mutation and executes one transaction
// while the command gate is held, never the state mutex. Failures return to rollback.
func (m *Manager) apply(ctx context.Context, p *profile.Profile, effect session.Effect, j *Journal, persist func(Journal) error) error {
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
		j.Routes = append(j.Routes, route)
		if err := persist(*j); err != nil {
			j.Routes = j.Routes[:len(j.Routes)-1]
			return err
		}
		if err := m.changeRoute(ctx, route, true); err != nil {
			// A definite command rejection cannot grant ownership of a racing route.
			// Cancellation is ambiguous, so its write-ahead intent remains recoverable.
			if ctx.Err() == nil {
				j.Routes = j.Routes[:len(j.Routes)-1]
				if persistErr := persist(*j); persistErr != nil {
					return errors.Join(err, persistErr)
				}
			}
			return fmt.Errorf("adding custom route %s failed: %w", cidr, err)
		}
		// Capture Darwin's concrete link gateway instead of retaining a wildcard intent.
		updated, err := m.routes(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, actual := range updated {
			if sameRoute(route, actual) {
				j.Routes[len(j.Routes)-1] = actual
				found = true
				break
			}
		}
		if !found {
			return errors.New("added custom route could not be verified")
		}
		if err := persist(*j); err != nil {
			return err
		}
	}
	if p.DNS.Mode == "split" {
		if len(effect.DNS) == 0 {
			return errors.New("split DNS requires negotiated nameservers")
		}
		for _, server := range effect.DNS {
			if !server.IsValid() || server.IsUnspecified() || server.Zone() != "" {
				return errors.New("invalid negotiated nameserver")
			}
		}
		if m.os == "darwin" {
			return m.applyResolvers(ctx, p, effect, j, persist)
		}
		return m.applyResolved(ctx, p, effect, j, persist)
	}
	return ctx.Err()
}

// checkPushedRoutes compares the observed table with current reservations under the
// short-held state mutex. Defaults on another active PPP link count as full tunnelling
// regardless of configured mode; overlapping pushed prefixes also fail with CONFLICT.
func (m *Manager) checkPushedRoutes(id, link string, routes []JournalRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
				return &ConflictError{"gateway pushed a default route while another full tunnel is active"}
			}
			for _, candidate := range other.profile.Routes.Include {
				if prefix.Bits() > 1 && prefix.Overlaps(netip.MustParsePrefix(candidate)) {
					return &ConflictError{"gateway pushed a route overlapping another active profile"}
				}
			}
			for _, pushed := range routes {
				otherPrefix := netip.MustParsePrefix(pushed.CIDR)
				if pushed.Interface == other.link && prefix.Bits() > 1 && otherPrefix.Bits() > 1 && prefix.Overlaps(otherPrefix) {
					return &ConflictError{"gateway pushed a route overlapping another active tunnel route"}
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
	var failures []error
	if m.os == "linux" && j.DNSConfigured {
		failures = append(failures, m.removeResolved(ctx, j))
	}
	for i := len(j.ResolverFiles) - 1; i >= 0; i-- {
		failures = append(failures, m.removeResolver(j.Profile, j.ResolverFiles[i]))
	}
	if len(j.Routes) > 0 {
		routes, err := m.routes(ctx)
		if err != nil {
			failures = append(failures, err)
		} else {
			for i := len(j.Routes) - 1; i >= 0; i-- {
				for _, actual := range routes {
					if sameRoute(j.Routes[i], actual) {
						failures = append(failures, m.changeRoute(ctx, actual, false))
						break
					}
				}
			}
		}
	}
	failures = append(failures, ctx.Err())
	return errors.Join(failures...)
}
