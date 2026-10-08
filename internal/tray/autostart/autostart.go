// Package autostart renders and manages user-owned tray startup registrations.
package autostart

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/avhn/fortix/internal/paths"
)

// marker identifies files this package may replace or remove, never unrelated entries.
const marker = "managed by fortix tray"

// Render returns a LaunchAgent or desktop entry for an absolute executable path.
// It rejects controls, noncanonical paths, and unsupported platforms; executable
// existence is deliberately left to installation. Arguments never go through a shell.
func Render(platform, executable string) ([]byte, error) {
	if !validPath(executable) {
		return nil, errors.New("autostart: executable must be a clean absolute path without controls")
	}
	switch platform {
	case "darwin":
		var escaped bytes.Buffer
		if err := xml.EscapeText(&escaped, []byte(executable)); err != nil {
			return nil, fmt.Errorf("escape executable: %w", err)
		}
		return []byte(xml.Header + "<!-- " + marker + " -->\n" +
			"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
			"<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.github.avhn.fortix.tray</string>\n" +
			"<key>RunAtLoad</key><true/>\n<key>ProgramArguments</key><array><string>" + escaped.String() + "</string></array>\n</dict></plist>\n"), nil
	case "linux":
		// Desktop Exec has its own escaping, followed by desktop string escaping.
		argument := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "`", "\\`", "$", "\\$", "%", "%%").Replace(executable)
		argument = strings.ReplaceAll(argument, "\\", "\\\\")
		return []byte("# " + marker + "\n[Desktop Entry]\nType=Application\nName=fortix\nExec=\"" + argument + "\"\nTerminal=false\n"), nil
	default:
		return nil, errors.New("autostart: unsupported platform")
	}
}

// Enable atomically installs a user startup file at p.TrayAutostart, mode 0600.
// Context cancellation, invalid locations, symlinks, foreign files, and filesystem
// failures return errors. This writes only a registration, never loads a service.
// The supplied paths must belong to the current user, not a privileged system tree.
func Enable(ctx context.Context, platform string, p paths.Paths, executable string) error {
	data, err := Render(platform, executable)
	if err != nil {
		return err
	}
	if err := validateLocation(platform, p.TrayAutostart); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(p.TrayAutostart)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create autostart directory: %w", err)
	}
	if err := ownedFile(p.TrayAutostart); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".fortix-tray-*")
	if err != nil {
		return fmt.Errorf("create autostart temporary file: %w", err)
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write autostart: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close autostart: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), p.TrayAutostart); err != nil {
		return fmt.Errorf("install autostart: %w", err)
	}
	return nil
}

// Disable removes only a recognized user registration; missing files are success.
// Cancellation, foreign files, symlinks, and filesystem errors are returned unchanged
// or with context. It does not stop the currently running tray process.
func Disable(ctx context.Context, platform string, p paths.Paths) error {
	if err := validateLocation(platform, p.TrayAutostart); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ownedFile(p.TrayAutostart); err != nil {
		return err
	}
	if err := os.Remove(p.TrayAutostart); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove autostart: %w", err)
	}
	return nil
}

// validPath accepts canonical absolute paths without controls; it performs no I/O.
func validPath(path string) bool {
	return utf8.ValidString(path) && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsFunc(path, unicode.IsControl)
}

// validateLocation checks the registration basename for platform, returning errors
// for unsupported platforms and unsafe paths before any directory is created.
func validateLocation(platform, path string) error {
	expected := ""
	switch platform {
	case "darwin":
		expected = "com.github.avhn.fortix.tray.plist"
	case "linux":
		expected = "fortix-tray.desktop"
	}
	if expected == "" || !validPath(path) || filepath.Base(path) != expected {
		return errors.New("autostart: invalid registration location")
	}
	return nil
}

// ownedFile permits absent files or regular marked registrations in real directories.
// It refuses symlink entries and unrelated content instead of overwriting user data.
func ownedFile(path string) error {
	dir, err := os.Lstat(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect autostart directory: %w", err)
	}
	if !dir.IsDir() {
		return errors.New("autostart: directory must not be a symlink")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect autostart: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("autostart: registration must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open autostart: %w", err)
	}
	// Only the ownership preamble matters; bound reads of user-editable files.
	data, readErr := io.ReadAll(io.LimitReader(file, 256))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("read autostart: %w", err)
	}
	if !bytes.HasPrefix(data, []byte("# "+marker+"\n")) && !bytes.HasPrefix(data, []byte(xml.Header+"<!-- "+marker+" -->\n")) {
		return errors.New("autostart: refusing unrelated registration")
	}
	return nil
}
