//go:build darwin || linux

package install

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// resolverMarker recognizes the exact first line written for a validated profile.
// Similar comments, empty identifiers and markers elsewhere in a file are not ours.
var resolverMarker = regexp.MustCompile(`^# managed by fortix profile=[a-z0-9][a-z0-9-]{0,62}\n$`)

// removeResolvers removes macOS resolver files carrying the fortix first-line
// marker after the helper stops. It leaves foreign files and symlinks untouched,
// requires trusted regular owned files, and returns failures before state is lost.
// Linux DNS settings belong to the tunnel link and have no resolver files to remove.
func (i *installer) removeResolvers(ctx context.Context) error {
	if i.options.Platform != "darwin" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(i.paths.ResolverDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := i.checkDirectory(i.paths.ResolverDir); err != nil {
		return err
	}
	if err := i.checkParent(filepath.Join(i.paths.ResolverDir, "entry")); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(i.paths.ResolverDir, entry.Name())
		file, err := openSource(path)
		if err != nil {
			return err
		}
		// Bound reads even when a foreign file has no line terminator.
		line, readErr := bufio.NewReader(io.LimitReader(file, 4096)).ReadString('\n')
		if err := errors.Join(file.Close(), nonEOF(readErr)); err != nil {
			return err
		}
		if resolverMarker.MatchString(line) {
			if err := i.removeFile(path); err != nil {
				return err
			}
		}
	}
	return nil
}

// nonEOF discards the expected end of a short foreign file. Other I/O errors must
// reach the caller rather than silently allowing uninstall to erase recovery state.
func nonEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
