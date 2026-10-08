package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

// openSource opens an absolute regular source with O_NOFOLLOW. A symlink, device,
// FIFO, relative path or unreadable file fails without copying any content.
func openSource(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("source must be a clean absolute path")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open source %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(errors.New("source must be a regular file"), err, f.Close())
	}
	return f, nil
}

// errUnsafeOwnership identifies an existing path that cannot be trusted for root
// writes. Optional CLI links may be skipped, but privileged paths must fail.
var errUnsafeOwnership = errors.New("unsafe ownership or permissions")

// trusted checks root ownership and write permissions for a file or directory.
// Only isolated test roots may bypass ownership, not file type or symlink checks.
// World-writable, sticky and group-writable entries are refused; see trustedAt
// for the single runtime directory exception.
func (i *installer) trusted(info os.FileInfo) error {
	return i.trustedAt(info, "")
}

// trustedAt applies trusted to the entry at canonical path. Group write is
// accepted only on the system runtime directory that holds the socket
// directories (macOS ships /var/run as root:daemon 0775), and only for wheel or
// daemon. Executable, service, profile and resolver paths stay strict.
func (i *installer) trustedAt(info os.FileInfo, canonical string) error {
	if i.paths.SkipTrust {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0002 != 0 || info.Mode()&os.ModeSticky != 0 {
		return fmt.Errorf("%w: %s", errUnsafeOwnership, info.Name())
	}
	if info.Mode().Perm()&0020 != 0 && (!info.IsDir() || !i.runtimeBase(canonical) || !systemGroup(stat.Gid)) {
		return fmt.Errorf("%w: %s", errUnsafeOwnership, info.Name())
	}
	return nil
}

// runtimeBase reports whether canonical is the resolved parent of the socket
// directories, for example /private/var/run for /var/run/fortix/fortix.sock.
func (i *installer) runtimeBase(canonical string) bool {
	if canonical == "" || i.paths.ControlSocket == "" {
		return false
	}
	base, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(i.paths.ControlSocket)))
	return err == nil && base == canonical
}

// systemGroup reports whether gid is wheel/root or the daemon service group,
// whose members are system services rather than interactive or admin accounts.
func systemGroup(gid uint32) bool {
	if gid == 0 {
		return true
	}
	group, err := user.LookupGroup("daemon")
	return err == nil && group.Gid == strconv.FormatUint(uint64(gid), 10)
}

// checkDirectory refuses symlink installation directories and validates every
// canonical parent up to root. Root-owned /etc, /var and /tmp system aliases may resolve
// to their canonical location, but sticky writable temporary parents remain unsafe.
func (i *installer) checkDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if path != "/var" && path != "/tmp" && path != "/etc" {
			return fmt.Errorf("directory is a symlink: %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("unsafe directory alias: %s", path)
		}
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for {
		info, err := os.Lstat(canonical)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("not a directory: %s", canonical)
		}
		if err := i.trustedAt(info, canonical); err != nil {
			return err
		}
		if canonical == "/" {
			return nil
		}
		canonical = filepath.Dir(canonical)
	}
}

// checkParent verifies the target's parent hierarchy before an installation write
// or removal. It does not authorize the target itself or create missing parents.
func (i *installer) checkParent(path string) error {
	parent := filepath.Dir(path)
	for current := parent; current != "/"; current = filepath.Dir(current) {
		if err := i.checkDirectory(current); err != nil {
			return err
		}
	}
	return i.checkDirectory("/")
}

// directory creates missing ancestors as root-owned 0755 directories, then assigns
// the requested final mode and group. Existing unsafe parents are never repaired.
func (i *installer) directory(path string, mode os.FileMode, gid int) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(path)
		if err := i.parents(parent); err != nil {
			return err
		}
		if err := os.Mkdir(path, 0755); err != nil {
			return err
		}
		if err := i.options.Chown(path, 0, 0); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := i.checkDirectory(path); err != nil {
		return err
	}
	if err := i.checkParent(path); err != nil {
		return err
	}
	if err := i.options.Chown(path, 0, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// parents creates absent ancestors without changing an existing ancestor's owner,
// mode or group. Every existing ancestor must pass directory trust verification.
func (i *installer) parents(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return i.checkParent(filepath.Join(path, "entry"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := i.parents(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0755); err != nil {
		return err
	}
	if err := i.options.Chown(path, 0, 0); err != nil {
		return err
	}
	return i.checkDirectory(path)
}

// checkFile verifies a destination is a root-owned non-writable regular file.
// Symlinks, directories and other special file types are always refused.
func (i *installer) checkFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular installed file: %s", path)
	}
	return i.trusted(info)
}

// destination validates an existing target before replacement; absence is allowed.
// Installation never overwrites a symlink or an unrelated unsafe writable object.
func (i *installer) destination(path string) error {
	if err := i.checkParent(path); err != nil {
		return err
	}
	err := i.checkFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// stage creates a private root-owned staging directory beneath a trusted parent.
// A failed ownership or mode change removes the new directory before returning.
func (i *installer) stage(parent string) (string, error) {
	if err := i.checkDirectory(parent); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(parent, ".fortix-install-")
	if err != nil {
		return "", err
	}
	if err := i.options.Chown(stage, 0, 0); err != nil {
		return "", errors.Join(err, os.Remove(stage))
	}
	if err := os.Chmod(stage, 0700); err != nil {
		return "", errors.Join(err, os.Remove(stage))
	}
	return stage, nil
}

// copyExclusive streams a no-follow regular source into a new staged destination,
// syncs it, and assigns root ownership and executable permissions before publishing.
func (i *installer) copyExclusive(source, target string) (err error) {
	in, err := openSource(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, in.Close()) }()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := i.options.Chown(target, 0, 0); err != nil {
		return err
	}
	return out.Chmod(0755)
}

// binaries stages the CLI and helper together and makes pinentry a hard link to
// the staged helper. No service is started until all three files are published.
func (i *installer) binaries() (err error) {
	stage, err := i.stage(i.paths.BinaryDir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	for _, item := range []struct{ name, source string }{{"fortix-helper", i.options.Helper}, {"fortix", i.options.CLI}} {
		if err := i.copyExclusive(item.source, filepath.Join(stage, item.name)); err != nil {
			return err
		}
	}
	if err := os.Link(filepath.Join(stage, "fortix-helper"), filepath.Join(stage, "fortix-pinentry")); err != nil {
		return err
	}
	for _, name := range []string{"fortix-helper", "fortix-pinentry", "fortix"} {
		target := filepath.Join(i.paths.BinaryDir, name)
		if err := i.destination(target); err != nil {
			return err
		}
	}
	linkAllowed, err := i.cliLinkAllowed(true)
	if err != nil {
		return err
	}
	if linkAllowed {
		if err := i.validateLink(); err != nil {
			return err
		}
	}
	for _, name := range []string{"fortix-helper", "fortix-pinentry", "fortix"} {
		if err := os.Rename(filepath.Join(stage, name), filepath.Join(i.paths.BinaryDir, name)); err != nil {
			return err
		}
	}
	if !linkAllowed {
		return nil
	}
	link := filepath.Join(stage, "cli-link")
	if err := os.Symlink(filepath.Join(i.paths.BinaryDir, "fortix"), link); err != nil {
		return err
	}
	if !i.paths.SkipTrust {
		if err := os.Lchown(link, 0, 0); err != nil {
			return err
		}
	}
	return os.Rename(link, i.paths.CLILink)
}

// cliLinkAllowed verifies or creates the optional CLI link's parent. A directory
// controlled by another user is left untouched with a warning; other filesystem
// failures remain errors. It never relaxes trust for helper or pinentry files.
func (i *installer) cliLinkAllowed(create bool) (bool, error) {
	var err error
	if create {
		err = i.parents(filepath.Dir(i.paths.CLILink))
	} else {
		err = i.checkParent(i.paths.CLILink)
	}
	if errors.Is(err, errUnsafeOwnership) {
		i.options.Warn(fmt.Sprintf("warning: skipping CLI link %s: %v; use %s directly", i.paths.CLILink, err, filepath.Join(i.paths.BinaryDir, "fortix")))
		return false, nil
	}
	return err == nil, err
}

// validateLink permits absence or the exact fortix CLI symlink, never replacing a
// regular file, another product's symlink or a link through an unsafe parent.
func (i *installer) validateLink() error {
	if err := i.checkParent(i.paths.CLILink); err != nil {
		return err
	}
	target, err := os.Readlink(i.paths.CLILink)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if target != filepath.Join(i.paths.BinaryDir, "fortix") {
		return errors.New("CLI link points outside the installation")
	}
	return nil
}

// writeFile writes service configuration exclusively in a private staging dir and
// renames it after root ownership, permissions and durable file contents are set.
func (i *installer) writeFile(path string, content []byte, mode os.FileMode) (err error) {
	if err := i.destination(path); err != nil {
		return err
	}
	stage, err := i.stage(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	target := filepath.Join(stage, "service")
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(content)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	if err := i.options.Chown(target, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(target, mode); err != nil {
		return err
	}
	return os.Rename(target, path)
}

// removeFile removes a verified regular installation file, ignoring missing paths.
// No symlink or unsafe existing parent can be used to redirect the deletion.
func (i *installer) removeFile(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := i.checkParent(path); err != nil {
		return err
	}
	if err := i.checkFile(path); err != nil {
		return err
	}
	return os.Remove(path)
}

// removeLink removes only the expected CLI symlink and treats absence as success.
func (i *installer) removeLink() error {
	if _, err := os.Lstat(i.paths.CLILink); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	allowed, err := i.cliLinkAllowed(false)
	if err != nil || !allowed {
		return err
	}
	if err := i.validateLink(); err != nil {
		return err
	}
	return os.Remove(i.paths.CLILink)
}

// removeTree removes a trusted fortix-owned directory without following nested
// symlinks. Missing directories are harmless; unsafe roots fail before deletion.
func (i *installer) removeTree(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := i.checkDirectory(path); err != nil {
		return err
	}
	if err := i.checkParent(path); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// removeEmpty removes a verified empty product directory while preserving sibling
// files, including retained profiles. Missing or nonempty directories are harmless.
func (i *installer) removeEmpty(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := i.checkDirectory(path); err != nil {
		return err
	}
	if err := i.checkParent(path); err != nil {
		return err
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) || isNotEmpty(err) {
		return nil
	}
	return err
}

// isNotEmpty recognizes the platform errno for retained nonempty directories.
// It allows uninstall to preserve sibling files instead of recursively deleting them.
func isNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST)
}

// cleanPath rejects controls and noncanonical absolute template paths so service
// configuration cannot introduce a second directive or an option-like pathname.
func cleanPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsFunc(path, unicode.IsControl)
}

// profileModes restricts existing regular profile files during installation upgrades.
// Trusted parents and non-writable root-owned files are required before changing modes.
func (i *installer) profileModes() error {
	entries, err := os.ReadDir(i.paths.Profiles)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(i.paths.Profiles, entry.Name())
		if err := i.checkFile(path); err != nil {
			return err
		}
		if err := i.options.Chown(path, 0, i.gid); err != nil {
			return err
		}
		if err := os.Chmod(path, 0640); err != nil {
			return err
		}
	}
	return nil
}
