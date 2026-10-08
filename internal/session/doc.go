// Package session reduces attempt-bound observations to states and effect data.
// It owns no clocks, processes, credentials, sockets, or network configuration.
// Cleanup gates trust and reconnect; exhausted cleanup can be retried explicitly.
package session
