// Package userconfig reads strict user preferences and writes them atomically.
// Missing files yield defaults; malformed or insecure files return errors, not defaults.
package userconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/paths"
)

// maxBytes bounds preference input to prevent accidental unbounded reads.
const maxBytes = 16 * 1024

// Config contains only non-secret preferences. Omitted fields default to true.
// Explicit false values survive both decoding and atomic persistence.
type Config struct {
	RememberPasswords bool `json:"remember_passwords"`
	AnimateIcon       bool `json:"animate_icon"`
	Notifications     bool `json:"notifications"`
}

// Defaults returns a fresh configuration with each user preference enabled.
func Defaults() Config { return Config{true, true, true} }

// Decode reads one bounded object, rejecting unknown, duplicate, null, or non-boolean fields.
// It returns no partial configuration on syntax or reader errors.
func Decode(r io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read preferences: %w", err)
	}
	if len(data) > maxBytes {
		return Config{}, errors.New("preferences exceed size limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return Config{}, errors.New("preferences must be an object")
	}
	cfg := Defaults()
	seen := make(map[string]bool)
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return Config{}, errors.New("invalid preference key")
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return Config{}, errors.New("invalid or duplicate preference key")
		}
		seen[key] = true
		var target *bool
		switch key {
		case "remember_passwords":
			target = &cfg.RememberPasswords
		case "animate_icon":
			target = &cfg.AnimateIcon
		case "notifications":
			target = &cfg.Notifications
		default:
			return Config{}, errors.New("unknown preference key")
		}
		value, err := d.Token()
		b, ok := value.(bool)
		if err != nil || !ok {
			return Config{}, errors.New("preference values must be booleans")
		}
		*target = b
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return Config{}, errors.New("invalid preferences object")
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("trailing preferences data")
	}
	return cfg, nil
}

// Load reads p.Preferences without following a final symlink; absent preferences use defaults.
// Non-regular files, permissive modes, cancelled contexts, and decoding failures return errors.
func Load(ctx context.Context, p paths.Paths) (Config, error) {
	if err := ctx.Err(); err != nil {
		return Config{}, err
	}
	if !filepath.IsAbs(p.Preferences) {
		return Config{}, errors.New("preferences path must be absolute")
	}
	dir := filepath.Dir(p.Preferences)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("inspect preference directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return Config{}, errors.New("preference directory must be real and not group- or world-writable")
	}
	root, err := os.OpenRoot(dir)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("open preference directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(filepath.Base(p.Preferences), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("open preferences: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err = f.Stat()
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return Config{}, errors.New("preferences must be regular and not group- or world-writable")
	}
	return Decode(f)
}

// Save atomically replaces p.Preferences with a synced 0600 file in a 0700 directory.
// It refuses symlink directories and non-regular existing targets, cleans temporary files,
// and preserves the previous file on failures before replacement. A directory sync
// failure is reported after replacement, when the new file is already visible.
func Save(ctx context.Context, p paths.Paths, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(p.Preferences) {
		return errors.New("preferences path must be absolute")
	}
	dir := filepath.Dir(p.Preferences)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create preference directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("preference directory must not be a symlink")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Chmod(0700); err != nil {
		return err
	}
	name := filepath.Base(p.Preferences)
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("preferences target must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// A root-relative exclusive file keeps temporary writes inside the opened directory.
	temporary := fmt.Sprintf(".config-%x", rand.Text())
	f, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(temporary) }()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err == nil {
		err = f.Chmod(0600)
	}
	if err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		return err
	}
	return directory.Sync()
}
