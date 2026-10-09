package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/session"
)

// interfaceIndex reads a kernel interface index without selecting or changing a link.
// A missing name returns os.ErrNotExist so recovery can distinguish absence from failure.
func interfaceIndex(name string) (int, error) {
	links, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, link := range links {
		if link.Name == name {
			return link.Index, nil
		}
	}
	return 0, os.ErrNotExist
}

// nativeInterface restricts native links to the kernel allocator's platform prefix.
// PPP remains process-owned; accepting a native spelling never establishes ownership.
func (m *Manager) nativeInterface(name string) bool {
	return (m.os == "darwin" && numberedInterface(name, "utun")) ||
		(m.os == "linux" && numberedInterface(name, "fortix"))
}

// RegisterLink binds a newly created native link to an existing profile reservation.
// The trusted transport supplies name/index, never a user-selected existing device.
// The kernel index and nonzero attempt must match before the journal is persisted;
// no address, route, DNS, or link deletion command is executed by registration.
func (m *Manager) RegisterLink(ctx context.Context, id string, attempt uint64, link backend.LinkIdentity, j *Journal, persist func(Journal) error) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer func() { <-m.transaction }()
	if j == nil || persist == nil || j.Profile != id || j.Attempt != attempt || attempt == 0 ||
		!m.nativeInterface(link.Interface) || link.Index <= 0 || link.PID != 0 || link.StartTime != "" || j.PID != 0 || j.StartTime != "" {
		return errors.New("invalid native link registration")
	}
	index, err := m.interfaceIndex(link.Interface)
	if err != nil || index != link.Index {
		return &InterfaceError{}
	}
	m.mu.Lock()
	current, exists := m.active[id]
	if !exists || current.profile.Backend != "native" ||
		(current.attempt != 0 && (current.attempt != attempt || current.identity != link)) {
		m.mu.Unlock()
		return errors.New("native link reservation mismatch")
	}
	for otherID, other := range m.active {
		if otherID != id && (other.link == link.Interface || other.identity.Index == link.Index) {
			m.mu.Unlock()
			return &ConflictError{"native link is already registered to another attempt"}
		}
	}
	m.mu.Unlock()
	updated := *j
	updated.Backend, updated.Interface, updated.Link = "native", link.Interface, &link
	if err := persist(updated); err != nil {
		return err
	}
	*j = updated
	m.mu.Lock()
	current, exists = m.active[id]
	if !exists {
		m.mu.Unlock()
		return errors.New("native reservation released during registration")
	}
	current.link, current.attempt, current.identity = link.Interface, attempt, link
	m.active[id] = current
	m.mu.Unlock()
	return nil
}

// registeredLink verifies effect against both the durable record and live reservation.
// Kernel index and, when requested, local IPv4 verification precede native mutations.
func (m *Manager) registeredLink(effect session.Effect, j Journal, address bool) error {
	m.mu.Lock()
	current, exists := m.active[effect.Profile]
	m.mu.Unlock()
	if !exists || j.backendName() != "native" || j.Link == nil || j.Profile != effect.Profile || j.Attempt != effect.Attempt ||
		current.attempt != effect.Attempt || current.identity != effect.Link || *j.Link != effect.Link ||
		effect.Interface != effect.Link.Interface || j.Interface != effect.Interface || !m.nativeInterface(effect.Interface) {
		return &InterfaceError{}
	}
	index, err := m.interfaceIndex(effect.Interface)
	if err != nil || index != effect.Link.Index {
		return &InterfaceError{}
	}
	if address {
		if !tunnelAddress(effect.LocalIP) || j.LocalIP != effect.LocalIP.String() || m.verifyInterface(effect.Interface, effect.LocalIP) != nil {
			return &InterfaceError{}
		}
	}
	return nil
}

// tunnelAddress accepts usable unscoped IPv4 endpoints for fixed privileged argv.
// Multicast, unspecified and broadcast addresses cannot be configured as tunnel peers.
func tunnelAddress(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && ip != netip.MustParseAddr("255.255.255.255")
}

// ConfigureNative journals and configures address, peer, MTU and link activation.
// effect must match a registered native link and provide usable IPv4 endpoints and
// an IPv4 MTU (68 through 65535). Commands use fixed trusted executables, never a
// shell. Repeated identical calls verify kernel state without duplicating commands.
// Successful configuration retains the peer for connected-route conflict checks.
// The transport owns device closure; this manager never deletes a native device.
func (m *Manager) ConfigureNative(ctx context.Context, effect session.Effect, j *Journal, persist func(Journal) error) error {
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer func() { <-m.transaction }()
	if j == nil || persist == nil || !tunnelAddress(effect.LocalIP) || !tunnelAddress(effect.PeerIP) || effect.MTU < 68 || effect.MTU > 65535 {
		return errors.New("invalid native link configuration")
	}
	if err := m.registeredLink(effect, *j, false); err != nil {
		return err
	}
	if j.LocalIP != "" && (j.LocalIP != effect.LocalIP.String() || j.PeerIP != effect.PeerIP.String() || j.MTU != effect.MTU) {
		return errors.New("native link configuration changed within an attempt")
	}
	m.mu.Lock()
	current := m.active[effect.Profile]
	if err := m.addresses(effect.Profile, effect.LocalIP); err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	if current.configured {
		return m.registeredLink(effect, *j, true)
	}
	addressApplied := j.LocalIP == effect.LocalIP.String() && m.verifyInterface(effect.Interface, effect.LocalIP) == nil
	updated := *j
	updated.LocalIP, updated.PeerIP, updated.MTU = effect.LocalIP.String(), effect.PeerIP.String(), effect.MTU
	if err := persist(updated); err != nil {
		return err
	}
	*j = updated
	mtu := strconv.Itoa(effect.MTU)
	if m.os == "darwin" {
		if _, err := m.runner.Run(ctx, []string{"/sbin/ifconfig"}, effect.Interface, "inet", j.LocalIP, j.PeerIP, "mtu", mtu, "up"); err != nil {
			return err
		}
	} else {
		// A prior attempt at this same configuration may have assigned the address
		// before failing activation. Do not duplicate an acknowledged address intent.
		if !addressApplied {
			if _, err := m.runner.Run(ctx, []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip"}, "addr", "add", j.LocalIP+"/32", "peer", j.PeerIP, "dev", effect.Interface); err != nil {
				return err
			}
		}
		if err := m.registeredLink(effect, *j, false); err != nil {
			return err
		}
		if _, err := m.runner.Run(ctx, []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip"}, "link", "set", "dev", effect.Interface, "mtu", mtu, "up"); err != nil {
			return err
		}
	}
	if err := m.registeredLink(effect, *j, true); err != nil {
		return err
	}
	m.mu.Lock()
	current = m.active[effect.Profile]
	current.configured, current.peerIP = true, effect.PeerIP
	m.active[effect.Profile] = current
	m.mu.Unlock()
	return ctx.Err()
}

// nativeLinkPresent proves a recorded native link still has its kernel index and IP.
// Missing or reused links are no longer owned and are skipped during cleanup; discovery
// errors fail closed. A live newer reservation cannot be cleared by an old journal.
func (m *Manager) nativeLinkPresent(j Journal) (bool, error) {
	m.mu.Lock()
	current, exists := m.active[j.Profile]
	m.mu.Unlock()
	if exists && current.attempt != 0 && (current.attempt != j.Attempt || j.Link == nil || current.identity != *j.Link) {
		return false, &InterfaceError{}
	}
	if j.Link == nil {
		return false, nil
	}
	index, err := m.interfaceIndex(j.Interface)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if index != j.Link.Index {
		return false, nil
	}
	if j.LocalIP != "" {
		if err := m.verifyInterface(j.Interface, netip.MustParseAddr(j.LocalIP)); err != nil {
			var mismatch *InterfaceError
			if errors.As(err, &mismatch) {
				return false, nil
			}
			return false, errors.New("native link address verification failed")
		}
	}
	return true, nil
}
