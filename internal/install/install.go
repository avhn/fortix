// Package install installs and removes the privileged helper and its service.
// Callers must explicitly invoke it as root. Commands, ownership changes and
// machine paths are injectable so tests never need privileged access.
package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"github.com/avhn/fortix/internal/paths"
)

// Runner executes a named program without a shell. It returns bounded diagnostic
// output and an error on cancellation or unsuccessful exit; arguments are not secrets.
type Runner interface {
	Run(context.Context, string, ...string) (string, error)
}

// ExecRunner runs commands with a fixed system PATH and locale, a root working
// directory, and a 30-second deadline. It never inherits caller environment values.
type ExecRunner struct{}

// Run executes program with args and returns its combined output and exit error.
// The caller's earlier deadline wins over the built-in service-operation timeout.
func (ExecRunner) Run(ctx context.Context, program string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	var out diagnosticBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.buffer.String(), err
}

// diagnosticBuffer retains at most 64 KiB of a command's combined diagnostics.
// The exec package serializes writes when stdout and stderr share this writer.
type diagnosticBuffer struct{ buffer bytes.Buffer }

// Write accepts all output bytes but discards bytes beyond the diagnostic limit.
// Returning the full accepted length avoids blocking a noisy child on a short write.
func (b *diagnosticBuffer) Write(data []byte) (int, error) {
	accepted := len(data)
	remaining := 65536 - b.buffer.Len()
	if len(data) > remaining {
		data = data[:remaining]
	}
	_, _ = b.buffer.Write(data)
	return accepted, nil
}

// Options selects source binaries, service platform and filesystem overrides.
// Helper and CLI are absolute regular source files; OpenFortiVPN is an optional
// macOS Mach-O binary. Purge removes stored profiles on uninstall. SudoUser defaults
// to SUDO_USER. Nil hooks use the real effective UID, group database and chown.
// Linux group lookup uses NSS through getent. Warn reports skipped optional CLI
// links and defaults to stderr; no privileged executable trust check is relaxed.
// Tests must supply an isolated Paths.RootDir and Paths.SkipTrust before bypassing
// root ownership verification; EUID alone never disables filesystem verification.
type Options struct {
	Helper       string
	CLI          string
	OpenFortiVPN string
	Purge        bool
	SudoUser     string
	Platform     string
	Paths        paths.Override
	Runner       Runner
	EUID         func() int
	GroupID      func(string) (int, error)
	Chown        func(string, int, int) error
	Warn         func(string)
}

// installer carries resolved paths and injected privileged operations for one call.
// gid is resolved after group creation and is never inferred from the invoking user.
type installer struct {
	options Options
	paths   paths.Paths
	gid     int
}

// userName limits account names to ordinary local-account syntax. It prevents
// option-like names, whitespace and control bytes from reaching account tools.
var userName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*\$?$`)

// prepare checks root authority and options before any filesystem or command side
// effect. It resolves all machine locations through paths.Installation.
func prepare(o Options) (*installer, error) {
	if o.EUID == nil {
		o.EUID = os.Geteuid
	}
	if o.EUID() != 0 {
		return nil, errors.New("installation requires effective UID 0")
	}
	if o.Platform == "" {
		o.Platform = runtime.GOOS
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.Chown == nil {
		o.Chown = os.Chown
	}
	if o.Warn == nil {
		o.Warn = func(message string) { _, _ = fmt.Fprintln(os.Stderr, message) }
	}
	if o.SudoUser == "" {
		o.SudoUser = os.Getenv("SUDO_USER")
	}
	if o.SudoUser != "" && !userName.MatchString(o.SudoUser) {
		return nil, errors.New("invalid invoking account name")
	}
	p, err := paths.Installation(o.Platform, o.Paths)
	if err != nil {
		return nil, err
	}
	if o.OpenFortiVPN != "" && o.Platform != "darwin" {
		return nil, errors.New("openfortivpn copying is only supported on macOS")
	}
	return &installer{options: o, paths: p}, nil
}

// lookupGroup resolves a local group's numeric GID and reports missing or malformed
// account-database entries instead of guessing a privileged ownership value.
func lookupGroup(name string) (int, error) {
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		return 0, errors.New("invalid group ID")
	}
	return gid, nil
}

// command runs one external operation and retains its diagnostic output on failure.
// The Runner always receives separate arguments, never a shell command string.
func (i *installer) command(ctx context.Context, name string, args ...string) error {
	out, err := i.options.Runner.Run(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, out)
	}
	return nil
}

// group creates the fortix group if absent and enrolls the invoking non-root user.
// Failed creation, membership updates or GID lookup stop installation immediately.
func (i *installer) group(ctx context.Context) error {
	if _, err := i.groupID(ctx); err != nil {
		if !errors.Is(err, errGroupAbsent) {
			return err
		}
		if i.options.Platform == "darwin" {
			if err := i.command(ctx, "/usr/sbin/dseditgroup", "-o", "create", "fortix"); err != nil {
				return err
			}
		} else if err := i.command(ctx, "/usr/sbin/groupadd", "--system", "fortix"); err != nil {
			return err
		}
	}
	gid, err := i.groupID(ctx)
	if err != nil || gid < 0 {
		return fmt.Errorf("resolve fortix group: %w", errors.Join(err, errors.New("group ID unavailable")))
	}
	i.gid = gid
	if name := i.options.SudoUser; name != "" && name != "root" {
		if i.options.Platform == "darwin" {
			return i.command(ctx, "/usr/sbin/dseditgroup", "-o", "edit", "-a", name, "-t", "user", "fortix")
		}
		return i.command(ctx, "/usr/sbin/usermod", "-a", "-G", "fortix", name)
	}
	return nil
}

// Install installs trusted, root-owned executable copies and service configuration,
// then starts the helper. Each file is staged and renamed atomically; failures are
// returned without starting a service against incomplete files. Existing profiles
// are never replaced. Source validation precedes group creation and filesystem writes.
func Install(ctx context.Context, o Options) error {
	i, err := prepare(o)
	if err != nil {
		return err
	}
	for _, source := range []string{o.Helper, o.CLI} {
		f, err := openSource(source)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	if o.OpenFortiVPN != "" {
		if _, err := inspectMachO(o.OpenFortiVPN); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	installed := false
	if _, err := os.Lstat(i.paths.ServiceFile); err == nil {
		if err := i.destination(i.paths.ServiceFile); err != nil {
			return err
		}
		installed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := i.group(ctx); err != nil {
		return err
	}
	for _, dir := range []struct {
		path string
		mode os.FileMode
		gid  int
	}{
		{i.paths.BinaryDir, 0755, 0}, {i.paths.Profiles, 0755, 0},
		{i.paths.State, 0700, 0}, {i.paths.Logs, 0750, i.gid},
		{filepath.Dir(i.paths.ControlSocket), 0755, i.gid},
		{filepath.Dir(i.paths.PinentrySocket), 0700, 0},
		{filepath.Dir(i.paths.ServiceFile), 0755, 0},
	} {
		if err := i.directory(dir.path, dir.mode, dir.gid); err != nil {
			return err
		}
	}
	// Finish dependency rewriting and signing before replacing running helper files.
	if o.OpenFortiVPN != "" {
		if err := i.bundle(ctx); err != nil {
			return err
		}
	}
	if err := i.binaries(); err != nil {
		return err
	}
	service, err := RenderService(i.options.Platform, i.paths)
	if err != nil {
		return err
	}
	if err := i.writeFile(i.paths.ServiceFile, []byte(service), 0644); err != nil {
		return err
	}
	if i.options.Platform == "darwin" {
		if installed {
			// An existing plist may describe a stopped job. Only unload registered jobs.
			if _, err := i.options.Runner.Run(ctx, "/bin/launchctl", "print", "system/com.github.avhn.fortix.helper"); err == nil {
				if err := i.command(ctx, "/bin/launchctl", "bootout", "system/com.github.avhn.fortix.helper"); err != nil {
					return err
				}
			} else if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		return i.command(ctx, "/bin/launchctl", "bootstrap", "system", i.paths.ServiceFile)
	}
	if err := i.command(ctx, "/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := i.command(ctx, "/bin/systemctl", "enable", "--now", "fortix-helper.service"); err != nil {
		return err
	}
	if installed {
		// Enabling an active unit does not replace its running executable.
		return i.command(ctx, "/bin/systemctl", "restart", "fortix-helper.service")
	}
	return nil
}

// Uninstall stops and unregisters the helper before removing owned installation
// locations. Profiles survive unless Purge is set. Missing files are harmless,
// but unsafe directory ownership, symlinks and service-manager errors are returned.
// The fortix group is removed only after all filesystem cleanup succeeds.
func Uninstall(ctx context.Context, o Options) error {
	i, err := prepare(o)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(i.paths.ServiceFile); err == nil {
		if err := i.checkParent(i.paths.ServiceFile); err != nil {
			return err
		}
		if err := i.checkFile(i.paths.ServiceFile); err != nil {
			return err
		}
		if i.options.Platform == "darwin" {
			if _, err := i.options.Runner.Run(ctx, "/bin/launchctl", "print", "system/com.github.avhn.fortix.helper"); err == nil {
				if err := i.command(ctx, "/bin/launchctl", "bootout", "system", i.paths.ServiceFile); err != nil {
					return err
				}
			} else if ctx.Err() != nil {
				return ctx.Err()
			}
		} else if err := i.command(ctx, "/bin/systemctl", "disable", "--now", "fortix-helper.service"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := i.removeResolvers(ctx); err != nil {
		return err
	}
	if err := i.removeFile(i.paths.ServiceFile); err != nil {
		return err
	}
	if i.options.Platform == "linux" {
		if err := i.command(ctx, "/bin/systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if err := i.removeLink(); err != nil {
		return err
	}
	for _, name := range []string{"fortix-pinentry", "fortix-helper", "fortix"} {
		if err := i.removeFile(filepath.Join(i.paths.BinaryDir, name)); err != nil {
			return err
		}
	}
	for _, dir := range []string{i.paths.VPNDir, i.paths.State, i.paths.Logs, filepath.Dir(i.paths.ControlSocket), filepath.Dir(i.paths.PinentrySocket)} {
		if dir == "" {
			continue
		}
		if err := i.removeTree(dir); err != nil {
			return err
		}
	}
	if o.Purge {
		if err := i.removeTree(i.paths.Profiles); err != nil {
			return err
		}
	}
	// Retain nonempty product parents and never remove generic system parents.
	for _, dir := range []string{i.paths.BinaryDir, filepath.Dir(i.paths.State), filepath.Dir(i.paths.Profiles), filepath.Dir(i.paths.VPNDir)} {
		if filepath.Base(dir) == "fortix" {
			if err := i.removeEmpty(dir); err != nil {
				return err
			}
		}
	}
	if _, err := i.groupID(ctx); err == nil {
		if i.options.Platform == "darwin" {
			return i.command(ctx, "/usr/sbin/dseditgroup", "-o", "delete", "fortix")
		}
		return i.command(ctx, "/usr/sbin/groupdel", "fortix")
	} else if !errors.Is(err, errGroupAbsent) {
		return err
	}
	return nil
}
