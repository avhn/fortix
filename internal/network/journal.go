// Package network applies and reconciles owned VPN routes and split DNS settings.
// Commands and interface discovery are injectable; failures retain recovery metadata.
package network

import "github.com/avhn/fortix/internal/backend"

// Journal identifies one backend generation and its exact owned network resources.
// PID and StartTime belong only to the process backend. Native records bind the
// kernel link index and negotiated local address; a name alone never grants ownership.
// PeerIP repeats LocalIP for new unnumbered native links; older distinct peer_ip values
// remain readable for cleanup, which relies only on the link identity and local address.
// An omitted Backend is interpreted as openfortivpn for older process records.
type Journal struct {
	Profile          string                `json:"profile"`
	Attempt          uint64                `json:"attempt"`
	PID              int                   `json:"pid"`
	StartTime        string                `json:"start_time"`
	Interface        string                `json:"interface,omitempty"`
	Backend          string                `json:"backend,omitempty"`
	Link             *backend.LinkIdentity `json:"link,omitempty"`
	LocalIP          string                `json:"local_ip,omitempty"`
	PeerIP           string                `json:"peer_ip,omitempty"`
	MTU              int                   `json:"mtu,omitempty"`
	GatewayIP        string                `json:"gateway_ip,omitempty"`
	GatewayException *JournalGateway       `json:"gateway_exception,omitempty"`
	Routes           []JournalRoute        `json:"routes,omitempty"`
	ResolverFiles    []JournalResolver     `json:"resolver_files,omitempty"`
	DNSConfigured    bool                  `json:"dns_configured,omitempty"`
	DNSServers       []string              `json:"dns_servers,omitempty"`
	DNSDomains       []string              `json:"dns_domains,omitempty"`
}

// JournalRoute identifies a destination, gateway and interface owned by an attempt.
// An empty gateway represents a directly attached route rather than a next-hop route.
type JournalRoute struct {
	CIDR      string `json:"cidr"`
	Gateway   string `json:"gateway,omitempty"`
	Interface string `json:"interface"`
}

// JournalGateway is a lease on a gateway host exception through a physical link.
// Owned distinguishes helper-created routes from borrowed preexisting host routes.
// Index guards physical interface reuse; every sharing attempt persists the same
// concrete route so batch recovery can reconstruct reference counts before deletion.
// GatewayIP in Journal is the actual IPv4 TLS peer, not the negotiated PPP peer.
type JournalGateway struct {
	Route JournalRoute `json:"route"`
	Index int          `json:"index"`
	Owned bool         `json:"owned"`
}

// backendName returns the effective backend without changing legacy journal bytes.
// Only an omitted value defaults; unknown explicit backends remain invalid.
func (j Journal) backendName() string {
	if j.Backend == "" {
		return "openfortivpn"
	}
	return j.Backend
}

// JournalResolver records the exact path and bytes installed by one attempt.
// Removal requires both the profile marker and unchanged content; symlinks are refused.
// Temporary is the private staging basename, recorded before creation so interrupted
// writes can be recovered without claiming unrelated resolver files.
type JournalResolver struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Temporary string `json:"temporary,omitempty"`
}
