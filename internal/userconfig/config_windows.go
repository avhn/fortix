//go:build windows

// Package userconfig reads strict user preferences and writes them atomically.
// Missing files yield defaults; malformed or insecure files return errors, not defaults.
package userconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/winfs"
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

// Load reads preferences from a pinned directory with a protected current-user/SYSTEM DACL.
// Missing directories or files use defaults; links, foreign grants and malformed JSON fail.
func Load(ctx context.Context, p paths.Paths) (Config, error) {
	if err := ctx.Err(); err != nil {
		return Config{}, err
	}
	if !winfs.ValidPath(p.Preferences) {
		return Config{}, errors.New("preferences path must be a canonical local drive path")
	}
	policy, err := winfs.UserPolicy()
	if err != nil {
		return Config{}, err
	}
	root, err := winfs.OpenRoot(filepath.Dir(p.Preferences))
	if winfs.IsNotExist(err) {
		return Defaults(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("open preference directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := winfs.CheckSecurity(root.Handle(), policy, true); err != nil {
		return Config{}, fmt.Errorf("inspect preference directory: %w", err)
	}
	file, err := root.Open(filepath.Base(p.Preferences), policy)
	if winfs.IsNotExist(err) {
		return Defaults(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("open preferences: %w", err)
	}
	defer func() { _ = file.Close() }()
	cfg, err := Decode(file)
	if err != nil {
		return Config{}, err
	}
	if err := ctx.Err(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Save flushes and atomically replaces preferences with an explicit private DACL.
// Existing insecure directories or files are refused, not silently adopted or repaired.
// All creation and publication occurs relative to pinned non-reparse directory handles.
func Save(ctx context.Context, p paths.Paths, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !winfs.ValidPath(p.Preferences) {
		return errors.New("preferences path must be a canonical local drive path")
	}
	policy, err := winfs.UserPolicy()
	if err != nil {
		return err
	}
	root, err := winfs.SecureDirectory(filepath.Dir(p.Preferences), policy)
	if err != nil {
		return fmt.Errorf("create preference directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return root.AtomicWrite(ctx, filepath.Base(p.Preferences), append(data, '\n'), policy)
}
