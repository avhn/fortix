package network

import (
	"context"
	"errors"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// validIPv4 accepts usable unscoped unicast endpoints, never multicast or broadcast.
func validIPv4(text string) bool {
	ip, err := netip.ParseAddr(text)
	return err == nil && tunnelAddress(ip) && ip.String() == text
}

// tunnelAddress limits native endpoints and TLS exceptions to usable IPv4 addresses.
func tunnelAddress(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && ip != netip.MustParseAddr("255.255.255.255")
}

// validateRoute refuses noncanonical destinations and incomplete native row identities.
func validateRoute(route JournalRoute) error {
	prefix, err := netip.ParsePrefix(route.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || route.LUID == 0 || route.Index == 0 || route.Protocol == 0 {
		return errors.New("invalid owned route")
	}
	if route.Gateway != "" && !validIPv4(route.Gateway) {
		return errors.New("invalid route next hop")
	}
	return nil
}

// sameRoute requires every stable identity field; aliases and transaction states are not keys.
func sameRoute(a, b JournalRoute) bool {
	return a.CIDR == b.CIDR && a.Gateway == b.Gateway && a.LUID == b.LUID && a.Index == b.Index && a.Metric == b.Metric && a.Protocol == b.Protocol
}

// routeExistsError maps native collisions without depending on localized diagnostics.
func routeExistsError(err error) bool {
	return errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}

// absentRow recognizes only documented missing-object statuses, never generic failures.
func absentRow(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}

// systemRoute excludes kernel rows already covered by connected-subnet policy.
// Unknown adapters and nonlocal routes remain competitors regardless of their aliases.
func systemRoute(route JournalRoute, adapters []adapter) bool {
	prefix, err := netip.ParsePrefix(route.CIDR)
	if err != nil {
		return false
	}
	if netip.MustParsePrefix("127.0.0.0/8").Contains(prefix.Addr()) && prefix.Bits() >= 8 ||
		route.CIDR == "224.0.0.0/4" || route.CIDR == "255.255.255.255/32" {
		return true
	}
	for _, a := range adapters {
		if a.row.InterfaceLuid != route.LUID || a.row.InterfaceIndex != route.Index {
			continue
		}
		if a.row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			return true
		}
		if route.Protocol != windows.MIB_IPPROTO_LOCAL || a.row.OperStatus != windows.IfOperStatusUp {
			return false
		}
		for _, connected := range a.prefixes {
			// The subnet check includes its address and directed broadcast host rows.
			if prefix == connected.Masked() || prefix.Bits() == 32 && connected.Contains(prefix.Addr()) {
				return true
			}
		}
	}
	return false
}

// conflictRoutes filters system rows only for policy; ownership checks use the full native table.
func (m *Manager) conflictRoutes(ctx context.Context) ([]JournalRoute, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	adapters, _, err := m.discover()
	if err != nil {
		return nil, err
	}
	rows, err := m.api.routes()
	if err != nil {
		return nil, err
	}
	filtered := rows[:0]
	for i := range rows {
		if systemRoute(rows[i], adapters) {
			continue
		}
		for _, a := range adapters {
			if a.row.InterfaceLuid == rows[i].LUID && a.row.InterfaceIndex == rows[i].Index {
				rows[i].Interface = windows.UTF16ToString(a.row.Alias[:])
				break
			}
		}
		filtered = append(filtered, rows[i])
	}
	return filtered, nil
}

// addOwnedRoute persists intent before create and acknowledged identity only after verification.
// An interrupted intent never authorizes deleting an existing row during recovery.
func (m *Manager) addOwnedRoute(ctx context.Context, route JournalRoute, j *Journal, persist func(Journal) error) error {
	route.State = mutationIntent
	j.Routes = append(j.Routes, route)
	index := len(j.Routes) - 1
	if err := m.save(ctx, j, persist); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.api.createRoute(route); err != nil {
		j.Routes[index].State = mutationRejected
		if routeExistsError(err) {
			err = &ConflictError{"route destination already exists and was not claimed"}
		}
		return errors.Join(err, m.save(context.WithoutCancel(ctx), j, persist))
	}
	rows, err := m.api.routes()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if sameRoute(route, row) {
			j.Routes[index].State = mutationApplied
			return m.save(context.WithoutCancel(ctx), j, persist)
		}
	}
	return errors.New("added route could not be verified")
}

// removeRoute leaves changed rows alone and retains ambiguous intent when a row still exists.
func (m *Manager) removeRoute(ctx context.Context, route JournalRoute) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if route.State == mutationRejected {
		return nil
	}
	rows, err := m.api.routes()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !sameRoute(route, row) {
			if route.LUID == row.LUID && route.Index == row.Index && route.CIDR == row.CIDR {
				return errors.New("route identity changed; journal retained")
			}
			continue
		}
		if route.State != mutationApplied {
			return errors.New("route ownership is uncertain; journal retained")
		}
		if err := m.api.deleteRoute(row); err != nil && !absentRow(err) {
			return err
		}
		return nil
	}
	return nil
}

// removeOwnedNetwork verifies the allocation before cleaning acknowledged resources.
// Intent rows on this allocation are left for adapter removal, never individually adopted.
func (m *Manager) removeOwnedNetwork(ctx context.Context, j Journal) error {
	_, present, err := m.adapterIdentity(j)
	if err != nil || !present {
		return err
	}
	for i := len(j.Routes) - 1; i >= 0; i-- {
		if j.Routes[i].State == mutationIntent {
			continue
		}
		if err := m.removeRoute(ctx, j.Routes[i]); err != nil {
			return err
		}
	}
	if j.Address != nil && j.Address.State != mutationIntent {
		if err := m.removeAddress(ctx, j); err != nil {
			return err
		}
	}
	if j.Settings != nil && j.Settings.State != mutationIntent {
		return m.restoreInterface(ctx, j)
	}
	return nil
}

// addressRow constructs the exact native address key and requested manual /32 properties.
func addressRow(j Journal) windows.MibUnicastIpAddressRow {
	a := j.Address
	var row windows.MibUnicastIpAddressRow
	raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
	raw.Family, raw.Addr = windows.AF_INET, netip.MustParseAddr(a.IP).As4()
	row.InterfaceLuid, row.InterfaceIndex = j.Allocation.LUID, j.Index
	row.OnLinkPrefixLength, row.PrefixOrigin, row.SuffixOrigin = a.Prefix, a.PrefixOrigin, a.SuffixOrigin
	row.ValidLifetime, row.PreferredLifetime = ^uint32(0), ^uint32(0)
	row.DadState = windows.IpDadStatePreferred
	return row
}

// sameAddress compares stable configuration rather than DAD progress or lifetime counters.
func sameAddress(a, b windows.MibUnicastIpAddressRow) bool {
	return a.Address == b.Address && a.InterfaceLuid == b.InterfaceLuid && a.InterfaceIndex == b.InterfaceIndex && a.OnLinkPrefixLength == b.OnLinkPrefixLength && a.PrefixOrigin == b.PrefixOrigin && a.SuffixOrigin == b.SuffixOrigin && a.SkipAsSource == b.SkipAsSource
}

// configureAddress journals creation before assigning an address to the allocation LUID.
func (m *Manager) configureAddress(ctx context.Context, j *Journal, persist func(Journal) error) error {
	if j.Address != nil {
		row, actual := addressRow(*j), addressRow(*j)
		if err := m.api.address(&actual, "get"); err != nil {
			return err
		}
		if j.Address.State != mutationApplied || !sameAddress(row, actual) {
			return errors.New("address ownership is uncertain; journal retained")
		}
		return m.waitPreferredAddress(ctx, *j)
	}
	j.Address = &JournalAddress{IP: j.LocalIP, Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, State: mutationIntent}
	if err := m.save(ctx, j, persist); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	row := addressRow(*j)
	if err := m.api.address(&row, "create"); err != nil {
		j.Address.State = mutationRejected
		if routeExistsError(err) {
			err = &ConflictError{"native address already exists and was not claimed"}
		}
		return errors.Join(err, m.save(context.WithoutCancel(ctx), j, persist))
	}
	expected := addressRow(*j)
	if err := m.api.address(&row, "get"); err != nil {
		return err
	}
	if !sameAddress(expected, row) {
		return errors.New("added address could not be verified")
	}
	j.Address.State = mutationApplied
	if err := m.save(context.WithoutCancel(ctx), j, persist); err != nil {
		return err
	}
	return m.waitPreferredAddress(ctx, *j)
}

// removeAddress deletes only a fully acknowledged, unchanged manual address.
func (m *Manager) removeAddress(ctx context.Context, j Journal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.Address == nil || j.Address.State == mutationRejected {
		return nil
	}
	row, expected := addressRow(j), addressRow(j)
	if err := m.api.address(&row, "get"); err != nil {
		if absentRow(err) {
			return nil
		}
		return err
	}
	if !sameAddress(expected, row) {
		return errors.New("address identity changed; journal retained")
	}
	if j.Address.State != mutationApplied {
		return errors.New("address ownership is uncertain; journal retained")
	}
	err := m.api.address(&row, "delete")
	if absentRow(err) {
		return nil
	}
	return err
}

// interfaceSettings extracts the exact mutable settings retained in the journal.
func interfaceSettings(row ipInterfaceRow) interfaceValues {
	return interfaceValues{row.MTU, row.Metric, row.AutomaticMetric}
}

// setInterfaceSettings preserves unrelated IP interface fields read immediately before set.
func (m *Manager) setInterfaceSettings(row *ipInterfaceRow, values interfaceValues) error {
	row.MTU, row.Metric, row.AutomaticMetric = values.MTU, values.Metric, values.AutomaticMetric
	if row.SitePrefixLength > 32 {
		row.SitePrefixLength = 0
	}
	return m.api.ipInterface(row, true)
}

// configureInterface records previous MTU/metric values before changing the owned adapter.
func (m *Manager) configureInterface(ctx context.Context, j *Journal, persist func(Journal) error) error {
	row := ipInterfaceRow{Family: windows.AF_INET, LUID: j.Allocation.LUID, Index: j.Index}
	if err := m.api.ipInterface(&row, false); err != nil {
		return err
	}
	if j.Settings != nil {
		if j.Settings.State != mutationApplied || interfaceSettings(row) != j.Settings.After {
			return errors.New("interface settings ownership is uncertain; journal retained")
		}
		return nil
	}
	j.Settings = &JournalInterface{Before: interfaceSettings(row), After: interfaceValues{uint32(j.MTU), 5, 0}, State: mutationIntent}
	if err := m.save(ctx, j, persist); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.setInterfaceSettings(&row, j.Settings.After); err != nil {
		return err
	}
	if err := m.api.ipInterface(&row, false); err != nil {
		return err
	}
	if interfaceSettings(row) != j.Settings.After {
		return errors.New("interface settings could not be verified")
	}
	j.Settings.State = mutationApplied
	return m.save(context.WithoutCancel(ctx), j, persist)
}

// restoreInterface restores only unchanged settings, never another administrator's edits.
func (m *Manager) restoreInterface(ctx context.Context, j Journal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.Settings == nil || j.Settings.State == mutationRejected {
		return nil
	}
	row := ipInterfaceRow{Family: windows.AF_INET, LUID: j.Allocation.LUID, Index: j.Index}
	if err := m.api.ipInterface(&row, false); err != nil {
		if absentRow(err) {
			return nil
		}
		return err
	}
	if interfaceSettings(row) == j.Settings.Before {
		return nil
	}
	if interfaceSettings(row) != j.Settings.After {
		return errors.New("interface settings changed; journal retained")
	}
	if j.Settings.State != mutationApplied {
		return errors.New("interface settings ownership is uncertain; journal retained")
	}
	return m.setInterfaceSettings(&row, j.Settings.Before)
}

// waitPreferredAddress bounds duplicate-address detection before traffic can use the endpoint.
// Acknowledged ownership is already durable, so cancellation still permits safe teardown.
func (m *Manager) waitPreferredAddress(ctx context.Context, j Journal) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		row, expected := addressRow(j), addressRow(j)
		if err := m.api.address(&row, "get"); err != nil {
			return err
		}
		if !sameAddress(row, expected) {
			return &InterfaceError{}
		}
		switch row.DadState {
		case windows.IpDadStatePreferred:
			return nil
		case windows.IpDadStateDuplicate:
			return &ConflictError{"native endpoint is duplicated on the tunnel"}
		case windows.IpDadStateTentative:
		default:
			return &InterfaceError{}
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
