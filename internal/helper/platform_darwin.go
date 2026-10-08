//go:build darwin

package helper

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// socketPeer retrieves Darwin LOCAL_PEERCRED rather than trusting socket payloads.
// Unknown xucred versions and missing group credentials fail closed.
func socketPeer(fd int) (Peer, error) {
	p, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Peer{}, err
	}
	if p.Version != 0 || p.Ngroups < 1 {
		return Peer{}, errors.New("unsupported peer credentials")
	}
	return Peer{UID: p.Uid, GID: p.Groups[0]}, nil
}

// processStart obtains a kernel process birth timestamp, including microseconds.
// Missing/reaped processes return an error and can never pass recovery verification.
func processStart(pid int) (string, error) {
	p, err := processInfo(pid)
	if err != nil {
		return "", err
	}
	if p.Proc.P_pid != int32(pid) {
		return "", errors.New("process identity unavailable")
	}
	return fmt.Sprintf("%d.%06d", p.Proc.P_starttime.Sec, p.Proc.P_starttime.Usec), nil
}

// trustedLibraries checks load commands in thin or universal Mach-O executables.
// Every absolute library and loader-relative library must be rooted in trusted
// directories; unresolved runtime search paths are rejected rather than guessed.
func trustedLibraries(path string) error {
	return inspectMachO(path, path, make(map[string]bool))
}

// inspectMachO checks every architecture and recursively follows non-system images.
// Resolved paths form a bounded visited set, preventing cycles or unbounded graphs.
func inspectMachO(path, executable string, visited map[string]bool) error {
	if visited[path] {
		return nil
	}
	if len(visited) >= 256 {
		return errors.New("too many executable dependencies")
	}
	visited[path] = true
	f, err := macho.Open(path)
	if err == nil {
		defer func() { _ = f.Close() }()
		return walkMachO(f, path, executable, visited)
	}
	fat, err := macho.OpenFat(path)
	if err != nil {
		return errors.New("cannot inspect executable libraries")
	}
	defer func() { _ = fat.Close() }()
	for _, arch := range fat.Arches {
		if err := walkMachO(arch.File, path, executable, visited); err != nil {
			return err
		}
	}
	return nil
}

// checkMachO validates each imported dylib in one architecture without executing it.
// Runtime search paths are allowed only when every candidate directory is trusted;
// loader/executable-relative paths resolve against this root-owned executable.
func checkMachO(f *macho.File, path string) error {
	return walkMachO(f, path, path, map[string]bool{path: true})
}

// walkMachO validates every dylib load variant and every resolved non-system
// dependency. Loader-relative names use the current image, executable-relative names
// use the original program; unresolved or untrusted search paths fail closed.
func walkMachO(f *macho.File, path, executable string, visited map[string]bool) error {
	for _, load := range f.Loads {
		lib, present, err := dylibName(load, f.ByteOrder)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		candidate := expandMachOPath(lib, path, executable)
		if strings.HasPrefix(lib, "@rpath/") {
			candidate, err = resolveRpath(f, lib, path, executable)
			if err != nil {
				return err
			}
		}
		if err := trustedLibrary(candidate, path); err != nil {
			return err
		}
		// System imports are supplied by SIP-protected images or the shared cache.
		if systemLibrary(candidate) {
			continue
		}
		resolved, err := trustedPath(candidate, 0)
		if err != nil {
			return err
		}
		if err := inspectMachO(resolved, executable, visited); err != nil {
			return err
		}
	}
	return nil
}

// dylibName decodes the bounded name offset for all commands that cause dyld to
// load a dependency. Unrelated commands are ignored; malformed dependency data fails.
func dylibName(load macho.Load, order binary.ByteOrder) (string, bool, error) {
	raw := load.Raw()
	if len(raw) == 0 {
		// Synthetic parsed load commands have no backing bytes in unit tests.
		if dylib, ok := load.(*macho.Dylib); ok {
			return dylib.Name, true, nil
		}
		return "", false, nil
	}
	if len(raw) < 8 || order == nil {
		return "", false, errors.New("invalid Mach-O load command")
	}
	switch order.Uint32(raw[:4]) {
	case 0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20:
	default:
		return "", false, nil
	}
	if len(raw) < 24 || order.Uint32(raw[4:8]) != uint32(len(raw)) {
		return "", false, errors.New("invalid dylib load command")
	}
	offset := order.Uint32(raw[8:12])
	if offset < 24 || uint64(offset) >= uint64(len(raw)) {
		return "", false, errors.New("invalid dylib name offset")
	}
	name := raw[offset:]
	end := bytes.IndexByte(name, 0)
	if end <= 0 {
		return "", false, errors.New("invalid dylib name")
	}
	return string(name[:end]), true, nil
}

// resolveRpath chooses the first existing trusted dependency after validating every
// search directory. Missing candidates can be skipped; unsafe candidates cannot.
func resolveRpath(f *macho.File, lib, path, executable string) (string, error) {
	var candidates []string
	for _, load := range f.Loads {
		rpath, ok := load.(*macho.Rpath)
		if !ok {
			continue
		}
		dir := expandMachOPath(rpath.Path, path, executable)
		resolved, err := trustedPath(dir, 0)
		if err != nil {
			return "", err
		}
		var st unix.Stat_t
		if err := unix.Stat(resolved, &st); err != nil {
			return "", err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return "", errors.New("library search path is not a directory")
		}
		candidates = append(candidates, filepath.Join(resolved, strings.TrimPrefix(lib, "@rpath/")))
	}
	for _, candidate := range candidates {
		if err := trustedFile(candidate, false); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", err
		}
		return candidate, nil
	}
	return "", errors.New("unresolved library search path")
}

// systemLibrary recognizes only clean absolute SIP-protected system locations.
// Relative or traversal-containing names never qualify for the shared-cache exception.
func systemLibrary(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path &&
		(strings.HasPrefix(path, "/usr/lib/") || strings.HasPrefix(path, "/System/Library/"))
}

// expandMachOPath resolves each supported token against the image dyld would use.
// Unsupported tokens remain non-absolute and are rejected by executable trust checks.
func expandMachOPath(value, loader, executable string) string {
	if strings.HasPrefix(value, "@executable_path/") || value == "@executable_path" {
		return expandLibraryPath(value, executable)
	}
	return expandLibraryPath(value, loader)
}

// trustedLibrary checks an import without loading it. Only clean absolute system
// imports missing on disk may come from the SIP-protected dyld shared cache.
// Relative imports and existing files retain the full executable-path policy.
func trustedLibrary(lib, executable string) error {
	err := trustedFile(expandLibraryPath(lib, executable), false)
	if errors.Is(err, os.ErrNotExist) && filepath.IsAbs(lib) && filepath.Clean(lib) == lib &&
		(strings.HasPrefix(lib, "/usr/lib/") || strings.HasPrefix(lib, "/System/Library/")) {
		return nil
	}
	return err
}

// expandLibraryPath resolves supported Mach-O location tokens without filesystem
// access. Unsupported tokens remain non-absolute and are rejected by trust checks.
func expandLibraryPath(value, path string) string {
	for _, prefix := range []string{"@loader_path/", "@executable_path/"} {
		if strings.HasPrefix(value, prefix) {
			return filepath.Join(filepath.Dir(path), strings.TrimPrefix(value, prefix))
		}
	}
	if value == "@loader_path" || value == "@executable_path" {
		return filepath.Dir(path)
	}
	return value
}

// waitChild conservatively inspects the reserved child PID because the portable
// Darwin syscall bindings do not expose waitid. Transient inspection errors retry;
// the slower cadence avoids waking five times as often for long-lived tunnels.
// True confirms a reserved zombie PID; false forbids signalling an absent child.
func waitChild(pid int) bool {
	return waitUntilFinished(pid, processFinished, 100*time.Millisecond)
}

// processFinished queries a child's zombie state without reaping its reserved PID.
// Darwin's BSD process ABI uses state 5 for SZOMB; kernel lookup failures propagate.
func processFinished(pid int) (bool, error) {
	p, err := processInfo(pid)
	if err != nil {
		return false, err
	}
	return p.Proc.P_stat == 5, nil
}

// processInfo distinguishes a missing Darwin process from a malformed kernel reply.
// The slice API accepts the zero-length result returned after a process is reaped.
func processInfo(pid int) (*unix.KinfoProc, error) {
	records, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, unix.ESRCH
	}
	if len(records) != 1 || records[0].Proc.P_pid != int32(pid) {
		return nil, errors.New("invalid process identity")
	}
	return &records[0], nil
}
