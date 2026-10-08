package helper

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Peer contains kernel-authenticated user and primary group identifiers, never
// client-supplied claims. Supplementary group authorization uses the account database.
type Peer struct{ UID, GID uint32 }

// Authorizer decides whether a kernel-authenticated peer may manage all profiles.
// Returning an error refuses the connection without reading any request contents.
type Authorizer func(Peer) error

// Authorize permits root or an account belonging to the fortix group. Lookup errors
// deny access; neither a client message nor an environment variable can grant access.
func Authorize(peer Peer) error {
	if peer.UID == 0 {
		return nil
	}
	group, err := user.LookupGroup("fortix")
	if err != nil {
		return errors.New("fortix group unavailable")
	}
	account, err := user.LookupId(strconv.FormatUint(uint64(peer.UID), 10))
	if err != nil {
		return errors.New("peer account unavailable")
	}
	groups, err := account.GroupIds()
	if err != nil {
		return errors.New("peer groups unavailable")
	}
	for _, gid := range groups {
		if gid == group.Gid {
			return nil
		}
	}
	return errors.New("peer is not authorized")
}

// peerCredentials reads peer identity from the connected Unix socket's descriptor.
// Failed raw-connection access or kernel credential retrieval always denies access.
func peerCredentials(conn *net.UnixConn) (Peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var peer Peer
	var credentialErr error
	err = raw.Control(func(fd uintptr) { peer, credentialErr = socketPeer(int(fd)) })
	return peer, errors.Join(err, credentialErr)
}

// randomToken returns 32 cryptographically random bytes as lowercase hex, or an
// entropy-source error. The temporary byte buffer is cleared before returning.
func randomToken() (string, error) {
	data := make([]byte, 32)
	defer clear(data)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// trustedFile verifies a root-owned regular program/library and every traversed
// directory, including intermediate symlink targets. Sticky or writable parents,
// user-owned symlinks, and excessive link chains fail closed.
func trustedFile(path string, executable bool) error {
	resolved, err := trustedPath(path, 0)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(resolved, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("program is not a regular file")
	}
	if executable && stat.Mode&0111 == 0 {
		return errors.New("file is not executable")
	}
	return nil
}

// trustedPath validates each path component before following a root-owned symlink.
// The resolved path is returned only if all intermediate locations are trustworthy.
func trustedPath(path string, links int) (string, error) {
	return checkedPath(path, links, false)
}

// checkedPath follows root-owned links under the selected permission policy.
// Runtime ancestors allow trusted system-group writes; executable paths never do.
func checkedPath(path string, links int, runtime bool) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || links > 40 {
		return "", errors.New("untrusted path")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for i, component := range components {
		current = filepath.Join(current, component)
		var stat unix.Stat_t
		if err := unix.Lstat(current, &stat); err != nil {
			return "", err
		}
		if stat.Uid != 0 {
			return "", errors.New("path is not root owned")
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			target, err := os.Readlink(current)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(current), target)
			}
			// Validate the target itself before appending the remaining path components.
			resolved, err := checkedPath(filepath.Clean(target), links+1, runtime)
			if err != nil {
				return "", err
			}
			if i+1 < len(components) {
				return checkedPath(filepath.Join(append([]string{resolved}, components[i+1:]...)...), links+1, runtime)
			}
			return resolved, nil
		}
		if !trustedMode(stat, runtime) {
			return "", errors.New("writable or sticky path")
		}
		if i < len(components)-1 && stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return "", errors.New("parent is not a directory")
		}
	}
	return current, nil
}

// trustedMode rejects non-root ownership, sticky paths and world writes. Runtime
// directories alone may grant write access to named system groups; lookup errors deny.
func trustedMode(stat unix.Stat_t, runtime bool) bool {
	if stat.Uid != 0 || stat.Mode&(0002|unix.S_ISVTX) != 0 {
		return false
	}
	if stat.Mode&0020 == 0 {
		return true
	}
	if !runtime || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false
	}
	if stat.Gid == 0 {
		return true
	}
	for _, name := range []string{"daemon", "syslog"} {
		group, err := user.LookupGroup(name)
		if err == nil && group.Gid == strconv.FormatUint(uint64(stat.Gid), 10) {
			return true
		}
	}
	return false
}

// trustedAncestor verifies runtime ancestors before creating a directory, allowing
// root-owned system-group writable parents. secureDir pins each helper leaf's mode.
func trustedAncestor(path string) error {
	for {
		_, err := os.Lstat(path)
		if err == nil {
			_, err = checkedPath(path, 0, true)
			return err
		}
		if !errors.Is(err, os.ErrNotExist) || path == "/" {
			return err
		}
		path = filepath.Dir(path)
	}
}

// verifyExecutables validates both spawned programs and platform library dependencies.
// Only the explicit paths test override skips these checks; root cannot use that mode.
func (s *Server) verifyExecutables() (string, error) {
	if s.opts.Paths.SkipTrust && os.Geteuid() == 0 {
		return "", errors.New("root cannot skip executable trust")
	}
	if !s.opts.Paths.SkipTrust {
		if err := trustedFile(s.opts.Paths.Pinentry, true); err != nil {
			return "", err
		}
	}
	for _, candidate := range s.opts.Paths.OpenFortiVPN {
		st, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
			return "", errors.New("invalid openfortivpn executable")
		}
		if !s.opts.Paths.SkipTrust {
			if err := trustedFile(candidate, true); err != nil {
				return "", err
			}
			// Inspect and execute the same resolved image so loader-relative dependencies
			// cannot be checked against a different directory from the binary's location.
			resolved, err := trustedPath(candidate, 0)
			if err != nil {
				return "", err
			}
			candidate = resolved
			if err := trustedLibraries(candidate); err != nil {
				return "", err
			}
		}
		return candidate, nil
	}
	return "", errors.New("openfortivpn executable not found")
}

// serviceLockAt excludes concurrent helpers before any journal recovery can signal
// processes. The descriptor is close-on-exec and crash release is kernel-managed.
func serviceLockAt(dir *os.File) (*os.File, error) {
	f, err := privateFileAt(dir, "helper.lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("helper is already running")
	}
	return f, nil
}
