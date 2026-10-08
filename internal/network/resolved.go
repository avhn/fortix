package network

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// resolved runs systemd-resolved's CLI from fixed root-owned system locations.
// Output and cancellation handling are delegated to the injected command runner.
func (m *Manager) resolved(ctx context.Context, args ...string) ([]byte, error) {
	return m.runner.Run(ctx, []string{"/usr/bin/resolvectl", "/bin/resolvectl"}, args...)
}

// parseResolved extracts the values from one link-specific resolvectl query.
// It rejects other links, multiline or oversized replies and malformed link indexes.
func parseResolved(data []byte, link string) ([]string, error) {
	text := strings.TrimSpace(string(data))
	if len(data) > 64*1024 || strings.ContainsAny(text, "\r\n") {
		return nil, errors.New("invalid resolved link record")
	}
	header, values, ok := strings.Cut(text, ":")
	fields := strings.Fields(header)
	if !ok || len(fields) != 3 || fields[0] != "Link" || fields[2] != "("+link+")" {
		return nil, errors.New("invalid resolved link identity")
	}
	index, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || index == 0 {
		return nil, errors.New("invalid resolved link index")
	}
	return strings.Fields(values), nil
}

// resolvedValues queries one DNS property on link and validates the returned identity.
// A missing link or command failure is returned rather than assuming settings are absent.
func (m *Manager) resolvedValues(ctx context.Context, property, link string) ([]string, error) {
	data, err := m.resolved(ctx, property, link)
	if err != nil {
		return nil, err
	}
	return parseResolved(data, link)
}

// applyResolved refuses preexisting link settings, journals both intended properties,
// then configures DNS servers and routing-only domains. Partial command failures are
// reconciled by matching the recorded values against current per-link settings.
func (m *Manager) applyResolved(ctx context.Context, p *profile.Profile, effect session.Effect, j *Journal, persist func(Journal) error) error {
	for _, property := range []string{"dns", "domain"} {
		values, err := m.resolvedValues(ctx, property, effect.Interface)
		if err != nil {
			return err
		}
		if len(values) != 0 {
			return &ConflictError{"PPP interface already has DNS settings"}
		}
	}
	for _, server := range effect.DNS {
		j.DNSServers = append(j.DNSServers, server.String())
	}
	for _, domain := range p.DNS.Domains {
		j.DNSDomains = append(j.DNSDomains, "~"+domain)
	}
	j.DNSConfigured = true
	if err := persist(*j); err != nil {
		j.DNSConfigured, j.DNSServers, j.DNSDomains = false, nil, nil
		return err
	}
	if _, err := m.resolved(ctx, append([]string{"dns", effect.Interface}, j.DNSServers...)...); err != nil {
		return fmt.Errorf("configuring split DNS servers failed: %w", err)
	}
	if _, err := m.resolved(ctx, append([]string{"domain", effect.Interface}, j.DNSDomains...)...); err != nil {
		return fmt.Errorf("configuring split DNS domains failed: %w", err)
	}
	return nil
}

// removeResolved clears only recorded DNS properties that still match on an existing
// PPP link. Each property is compared independently for partial application/removal.
// Other resolved properties remain unchanged; deleted links have already lost their state.
func (m *Manager) removeResolved(ctx context.Context, j Journal) error {
	present, err := m.linkExists(j.Interface)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	servers, err := m.resolvedValues(ctx, "dns", j.Interface)
	if err != nil {
		return err
	}
	domains, err := m.resolvedValues(ctx, "domain", j.Interface)
	if err != nil {
		return err
	}
	var failures []error
	if slices.Equal(servers, j.DNSServers) {
		_, err := m.resolved(ctx, "dns", j.Interface, "")
		failures = append(failures, err)
	}
	if slices.Equal(domains, j.DNSDomains) {
		_, err := m.resolved(ctx, "domain", j.Interface, "")
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
