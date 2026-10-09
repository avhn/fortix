package network

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// marker identifies a resolver's owning profile on its first line.
// Validated profile identifiers prevent newline injection into this fixed header.
func marker(id string) string { return "# managed by fortix profile=" + id + "\n" }

// validDomain verifies a lowercase split domain through the shared profile validator.
// Only the DNS fields are inspected; callers validate profile/process identity separately.
func validDomain(domain string) bool {
	p := profile.Profile{SchemaVersion: 1, ID: "work", Name: "Work", Backend: "openfortivpn", Gateway: profile.Gateway{Host: "vpn.example.com", Port: 443}, Username: "jane.doe", MFA: profile.MFA{Mode: "none"}, Routes: profile.Routes{Mode: "gateway"}, DNS: profile.DNS{Mode: "split", Domains: []string{domain}}}
	return p.Validate() == nil
}

// validateJournal rejects unsafe backend, link, route, resolver and resolved ownership.
// Legacy records remain process-backed and PPP-only. Native resources require a
// registered index and local IP; physical routes are allowed only as typed host leases.
func (m *Manager) validateJournal(j Journal) error {
	if j.Profile == "" || strings.ContainsAny(j.Profile, "/\n\r") {
		return errors.New("invalid network journal profile")
	}
	if j.backendName() == "native" {
		if j.Attempt == 0 || j.PID != 0 || j.StartTime != "" {
			return errors.New("invalid native journal identity")
		}
		// A crash before device creation leaves only a resource-free native intent.
		if j.Link == nil && j.Interface == "" && len(j.Routes) == 0 && len(j.ResolverFiles) == 0 && !j.DNSConfigured && j.GatewayException == nil {
			return nil
		}
		if j.Link == nil || j.Link.Index <= 0 || j.Link.PID != 0 || j.Link.StartTime != "" ||
			j.Link.Interface != j.Interface || !m.nativeInterface(j.Interface) {
			return errors.New("invalid native journal identity")
		}
		if j.LocalIP != "" {
			local, err := netip.ParseAddr(j.LocalIP)
			if err != nil || !tunnelAddress(local) {
				return errors.New("invalid native journal address")
			}
		}
		if (len(j.Routes) > 0 || j.DNSConfigured) && j.LocalIP == "" {
			return errors.New("native resources require a negotiated local address")
		}
	} else if j.backendName() != "openfortivpn" || j.Link != nil || j.GatewayException != nil ||
		(j.Interface != "" && !numberedInterface(j.Interface, "ppp")) {
		return errors.New("invalid process journal identity")
	}
	if j.GatewayException != nil {
		if err := validateGateway(*j.GatewayException); err != nil {
			return err
		}
		ip, err := netip.ParseAddr(j.GatewayIP)
		if err != nil || netip.PrefixFrom(ip, 32).String() != j.GatewayException.Route.CIDR {
			return errors.New("gateway lease does not match the TLS peer")
		}
	}
	for _, route := range j.Routes {
		prefix, err := netip.ParsePrefix(route.CIDR)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || !validInterface(route.Interface) || route.Interface != j.Interface {
			return errors.New("invalid owned route identity")
		}
		if route.Gateway != "" && route.Gateway != route.Interface && !strings.HasPrefix(route.Gateway, "link#") {
			return errors.New("owned route is not a direct PPP route")
		}
	}
	for _, file := range j.ResolverFiles {
		if m.os != "darwin" || filepath.Clean(file.Path) != file.Path || filepath.Dir(file.Path) != m.paths.ResolverDir || !validDomain(filepath.Base(file.Path)) || !strings.HasPrefix(file.Content, marker(j.Profile)) || len(file.Content) > 64*1024 || (file.Temporary != "" && !validTemporary(j.Profile, file.Temporary)) {
			return errors.New("invalid resolver ownership")
		}
	}
	if j.DNSConfigured {
		if m.os != "linux" || !validInterface(j.Interface) || len(j.DNSServers) == 0 || len(j.DNSDomains) == 0 {
			return errors.New("invalid resolved ownership")
		}
		for _, server := range j.DNSServers {
			ip, err := netip.ParseAddr(server)
			if err != nil || ip.IsUnspecified() || ip.Zone() != "" {
				return errors.New("invalid owned DNS server")
			}
		}
		for _, domain := range j.DNSDomains {
			if !strings.HasPrefix(domain, "~") || !validDomain(domain[1:]) {
				return errors.New("invalid owned DNS domain")
			}
		}
	}
	return nil
}

// resolverDirectory pins a checked resolver directory without following its final link.
// Production requires trusted ancestors; test paths use the explicit trust override.
// Missing directories can be created only for application, never during teardown.
func (m *Manager) resolverDirectory(create bool) (*os.File, error) {
	path := m.paths.ResolverDir
	if !m.paths.SkipTrust {
		for current := filepath.Dir(path); ; current = filepath.Dir(current) {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return nil, err
			}
			var st unix.Stat_t
			if err := unix.Stat(resolved, &st); err != nil {
				return nil, err
			}
			if st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return nil, errors.New("unsafe resolver ancestor")
			}
			if current == "/" {
				break
			}
		}
	}
	if create {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, err
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		_ = file.Close()
		return nil, errors.New("unsafe resolver directory")
	}
	return file, nil
}

// resolverAt reads a bounded regular non-writable file relative to a pinned directory.
// Symlinks and foreign ownership fail; a missing file retains os.ErrNotExist semantics.
func resolverAt(dir *os.File, name string) ([]byte, unix.Stat_t, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		return nil, st, errors.New("unsafe resolver file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err == nil && len(data) > 64*1024 {
		err = errors.New("oversized resolver file")
	}
	return data, st, err
}

// applyResolvers installs one immutable resolver per domain after persisting its intent.
// Existing files, including marked files belonging to another attempt, are never replaced.
func (m *Manager) applyResolvers(ctx context.Context, p *profile.Profile, effect session.Effect, j *Journal, persist func(Journal) error) error {
	dir, err := m.resolverDirectory(true)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	content := marker(p.ID) + fmt.Sprintf("# attempt=%d\n", j.Attempt)
	for _, server := range effect.DNS {
		content += "nameserver " + server.String() + "\n"
	}
	for _, domain := range p.DNS.Domains {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, _, err := resolverAt(dir, domain); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return errors.New("existing resolver file is unsafe")
			}
			return &ConflictError{"split DNS resolver file already exists"}
		}
		entry := JournalResolver{Path: filepath.Join(m.paths.ResolverDir, domain), Content: content, Temporary: ".fortix-" + p.ID + "-" + rand.Text()}
		j.ResolverFiles = append(j.ResolverFiles, entry)
		if err := persist(*j); err != nil {
			j.ResolverFiles = j.ResolverFiles[:len(j.ResolverFiles)-1]
			return err
		}
		if err := installResolver(dir, domain, entry.Temporary, []byte(content)); err != nil {
			return fmt.Errorf("installing split DNS resolver failed: %w", err)
		}
	}
	return nil
}

// installResolver durably publishes complete bytes with an atomic no-replace link.
// The private temporary file is removed on every path; racing existing files survive.
func installResolver(dir *os.File, name, temp string, data []byte) error {
	fd, err := unix.Openat(int(dir.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temp)
	defer func() { _ = file.Close(); _ = unix.Unlinkat(int(dir.Fd()), temp, 0) }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(0644); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := unix.Linkat(int(dir.Fd()), temp, int(dir.Fd()), name, 0); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(dir.Fd()), temp, 0); err != nil {
		return err
	}
	return dir.Sync()
}

// removeResolver unlinks only a regular file with matching first-line marker, exact
// content and the inode inspected through the pinned directory. Missing/changed files
// are not owned anymore; unsafe symlinks are left untouched and reported for inspection.
func (m *Manager) removeResolver(id string, entry JournalResolver) error {
	dir, err := m.resolverDirectory(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	finalErr := removeResolverFile(dir, filepath.Base(entry.Path), id, entry.Content, false)
	var tempErr error
	if entry.Temporary != "" {
		tempErr = removeResolverFile(dir, entry.Temporary, id, entry.Content, true)
	}
	return errors.Join(finalErr, tempErr)
}

// removeResolverFile unlinks matching published bytes or an owned staging prefix.
// Staging basenames are unguessable and journalled before creation; a crash can leave
// an empty or partial write. Published domain files always require their complete marker.
func removeResolverFile(dir *os.File, name, id, content string, temporary bool) error {
	data, before, err := resolverAt(dir, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if temporary {
		if !strings.HasPrefix(content, string(data)) {
			return nil
		}
	} else if !strings.HasPrefix(string(data), marker(id)) || string(data) != content {
		return nil
	}
	var after unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		return errors.New("resolver ownership changed during removal")
	}
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return dir.Sync()
}

// validTemporary accepts only a profile-bound random staging basename with no traversal.
// The random suffix uses the base32 alphabet returned by crypto/rand.Text.
func validTemporary(id, name string) bool {
	suffix, ok := strings.CutPrefix(name, ".fortix-"+id+"-")
	if !ok || len(suffix) != 26 {
		return false
	}
	for _, c := range suffix {
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}
