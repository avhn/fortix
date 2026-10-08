// Package network applies and reconciles owned VPN routes and split DNS settings.
// Commands and interface discovery are injectable; failures retain recovery metadata.
package network

// Journal identifies one process generation and its exact owned network resources.
// PID and StartTime are verified by the helper before signalling any recovered process.
type Journal struct {
	Profile       string            `json:"profile"`
	Attempt       uint64            `json:"attempt"`
	PID           int               `json:"pid"`
	StartTime     string            `json:"start_time"`
	Interface     string            `json:"interface,omitempty"`
	Routes        []JournalRoute    `json:"routes,omitempty"`
	ResolverFiles []JournalResolver `json:"resolver_files,omitempty"`
	DNSConfigured bool              `json:"dns_configured,omitempty"`
	DNSServers    []string          `json:"dns_servers,omitempty"`
	DNSDomains    []string          `json:"dns_domains,omitempty"`
}

// JournalRoute identifies a destination, gateway and interface owned by an attempt.
// An empty gateway represents a directly attached route rather than a next-hop route.
type JournalRoute struct {
	CIDR      string `json:"cidr"`
	Gateway   string `json:"gateway,omitempty"`
	Interface string `json:"interface"`
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
