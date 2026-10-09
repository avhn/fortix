//go:build darwin || linux

package install

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// image describes a Mach-O image's imported libraries and runtime search paths.
// Universal images include the union across slices so no architecture is omitted.
type image struct {
	libraries []string
	rpaths    []string
}

// inspectMachO opens a no-follow regular source and reads its Mach-O load commands.
// Malformed, non-Mach-O and inaccessible files fail before any privileged command.
func inspectMachO(path string) (result image, err error) {
	f, err := openSource(path)
	if err != nil {
		return image{}, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return readImage(f)
}

// readImage parses thin or universal Mach-O data without filesystem writes. It
// rejects malformed slices and deduplicates imports while preserving rpath priority.
func readImage(reader io.ReaderAt) (image, error) {
	var files []*macho.File
	if fat, err := macho.NewFatFile(reader); err == nil {
		for _, arch := range fat.Arches {
			files = append(files, arch.File)
		}
	} else {
		thin, err := macho.NewFile(reader)
		if err != nil {
			return image{}, fmt.Errorf("read Mach-O: %w", err)
		}
		files = append(files, thin)
	}
	libraries, rpaths := map[string]bool{}, map[string]bool{}
	result := image{}
	for _, file := range files {
		for _, load := range file.Loads {
			name, imported, err := importedLibrary(load.Raw(), file.ByteOrder)
			if err != nil {
				return image{}, err
			}
			if imported {
				libraries[name] = true
			}
			if rpath, ok := load.(*macho.Rpath); ok && !rpaths[rpath.Path] {
				rpaths[rpath.Path] = true
				result.rpaths = append(result.rpaths, rpath.Path)
			}
		}
	}
	for name := range libraries {
		result.libraries = append(result.libraries, name)
	}
	sort.Strings(result.libraries)
	return result, nil
}

// importedLibrary decodes ordinary, weak, reexported, lazy and upward dylib loads.
// debug/macho leaves several of these as raw commands, so they must be inspected
// explicitly to avoid omitting executable dependencies. Other command kinds are
// ignored; malformed name offsets, missing terminators and empty imports fail.
func importedLibrary(raw []byte, order binary.ByteOrder) (string, bool, error) {
	if len(raw) < 8 {
		return "", false, errors.New("truncated Mach-O load command")
	}
	switch order.Uint32(raw[:4]) {
	case 0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023:
		if len(raw) < 24 {
			return "", false, errors.New("truncated Mach-O dylib command")
		}
		offset := order.Uint32(raw[8:12])
		if offset < 24 || uint64(offset) >= uint64(len(raw)) {
			return "", false, errors.New("invalid Mach-O dylib name offset")
		}
		data := raw[offset:]
		end := bytes.IndexByte(data, 0)
		if end <= 0 {
			return "", false, errors.New("invalid Mach-O dylib name")
		}
		return string(data[:end]), true, nil
	default:
		return "", false, nil
	}
}

// systemLibrary identifies OS-supplied libraries left outside the private bundle.
// Prefix boundaries are checked so similarly named user directories are not trusted.
func systemLibrary(path string) bool {
	return strings.HasPrefix(path, "/usr/lib/") || strings.HasPrefix(path, "/System/")
}

// expandLocation resolves dyld loader and executable placeholders against original
// source locations. Unknown placeholders and nonabsolute results are rejected.
func expandLocation(name, loader, executable string) (string, error) {
	switch {
	case strings.HasPrefix(name, "@loader_path/"):
		name = filepath.Join(filepath.Dir(loader), strings.TrimPrefix(name, "@loader_path/"))
	case name == "@loader_path":
		name = filepath.Dir(loader)
	case strings.HasPrefix(name, "@executable_path/"):
		name = filepath.Join(filepath.Dir(executable), strings.TrimPrefix(name, "@executable_path/"))
	case name == "@executable_path":
		name = filepath.Dir(executable)
	}
	if !filepath.IsAbs(name) || strings.ContainsAny(name, "\x00\n\r") {
		return "", fmt.Errorf("unresolved Mach-O path: %s", name)
	}
	return filepath.Clean(name), nil
}

// resolveLibrary expands an import using the importing image and its inherited
// runtime paths. System shared-cache libraries need not exist as ordinary files;
// non-system candidates must be readable regular no-follow files.
func resolveLibrary(name, loader, executable string, rpaths []string) (string, error) {
	candidates := []string{name}
	if strings.HasPrefix(name, "@rpath/") {
		candidates = make([]string, 0, len(rpaths))
		for _, path := range rpaths {
			candidates = append(candidates, filepath.Join(path, strings.TrimPrefix(name, "@rpath/")))
		}
	}
	for _, candidate := range candidates {
		path, err := expandLocation(candidate, loader, executable)
		if err != nil {
			continue
		}
		if systemLibrary(path) {
			return path, nil
		}
		f, err := openSource(path)
		if err == nil {
			if err := f.Close(); err != nil {
				return "", err
			}
			return path, nil
		}
	}
	return "", fmt.Errorf("cannot resolve imported library %s in %s", name, loader)
}

// bundledImage records the staged destination and original import rewrites for one
// executable or dylib. The source path is used only to resolve its load commands.
type bundledImage struct {
	source, target string
	image          image
	replacements   map[string]string
}

// collectBundle recursively copies and inspects the executable and all non-system
// imports into an exclusive private staging directory. Name collisions, unresolved
// dependencies and graphs over 256 images fail rather than producing ambiguous code.
func (i *installer) collectBundle(stage string) ([]bundledImage, error) {
	executable := i.options.OpenFortiVPN
	seen, names := map[string]int{}, map[string]string{}
	var images []bundledImage
	var visit func(string, []string) error
	// Dependencies inherit the caller's resolved LC_RPATH search list, as dyld does.
	visit = func(source string, inherited []string) error {
		// Resolve directory aliases, retaining O_NOFOLLOW protection for the file.
		parent, err := filepath.EvalSymlinks(filepath.Dir(source))
		if err != nil {
			return err
		}
		identity := filepath.Join(parent, filepath.Base(source))
		if _, ok := seen[identity]; ok {
			return nil
		}
		if len(images) >= 256 {
			return errors.New("Mach-O dependency graph exceeds 256 images")
		}
		name := filepath.Base(source)
		if source == executable {
			name = "openfortivpn"
		}
		if previous, ok := names[name]; ok && previous != identity {
			return fmt.Errorf("dylib basename collision: %s", name)
		}
		names[name] = identity
		target := filepath.Join(stage, name)
		if err := i.copyExclusive(source, target); err != nil {
			return err
		}
		metadata, err := inspectMachO(target)
		if err != nil {
			return err
		}
		rpaths := make([]string, 0, len(metadata.rpaths)+len(inherited))
		for _, path := range metadata.rpaths {
			expanded, err := expandLocation(path, source, executable)
			if err != nil {
				return err
			}
			rpaths = append(rpaths, expanded)
		}
		rpaths = append(rpaths, inherited...)
		index := len(images)
		seen[identity] = index
		images = append(images, bundledImage{source: source, target: target, image: metadata, replacements: map[string]string{}})
		for _, imported := range metadata.libraries {
			dependency, err := resolveLibrary(imported, source, executable, rpaths)
			if err != nil {
				return err
			}
			if systemLibrary(dependency) {
				if imported != dependency {
					images[index].replacements[imported] = dependency
				}
				continue
			}
			images[index].replacements[imported] = "@loader_path/" + filepath.Base(dependency)
			if err := visit(dependency, rpaths); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(executable, nil); err != nil {
		return nil, err
	}
	return images, nil
}

// bundle rewrites every non-system import to a sibling dylib, removes source rpaths,
// ad-hoc signs all images, verifies executable trust and publishes the directory.
// An existing bundle is retained until the new bundle is fully prepared; a failed
// publication restores it. Source executables and dylibs are never modified.
func (i *installer) bundle(ctx context.Context) (err error) {
	parent := filepath.Dir(i.paths.VPNDir)
	if err := i.parents(parent); err != nil {
		return err
	}
	stage, err := i.stage(parent)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	images, err := i.collectBundle(stage)
	if err != nil {
		return err
	}
	for _, item := range images {
		var imports []string
		for imported := range item.replacements {
			imports = append(imports, imported)
		}
		sort.Strings(imports)
		for _, imported := range imports {
			if err := i.command(ctx, "/usr/bin/install_name_tool", "-change", imported, item.replacements[imported], item.target); err != nil {
				return err
			}
		}
		for _, rpath := range item.image.rpaths {
			if err := i.command(ctx, "/usr/bin/install_name_tool", "-delete_rpath", rpath, item.target); err != nil {
				return err
			}
		}
		if item.source != i.options.OpenFortiVPN {
			if err := i.command(ctx, "/usr/bin/install_name_tool", "-id", "@loader_path/"+filepath.Base(item.target), item.target); err != nil {
				return err
			}
		}
		if err := i.command(ctx, "/usr/bin/codesign", "--force", "-s", "-", item.target); err != nil {
			return err
		}
		if err := i.command(ctx, "/usr/bin/codesign", "--verify", "--strict", item.target); err != nil {
			return err
		}
		if err := i.options.Chown(item.target, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(item.target, 0755); err != nil {
			return err
		}
		if err := i.checkFile(item.target); err != nil {
			return err
		}
		if err := i.checkParent(item.target); err != nil {
			return err
		}
	}
	if err := os.Chmod(stage, 0755); err != nil {
		return err
	}
	if err := i.checkDirectory(stage); err != nil {
		return err
	}
	// A sibling private backup allows restoration if the final rename fails.
	backup, err := i.stage(parent)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(backup)) }()
	previous := filepath.Join(backup, "previous")
	exists := false
	if _, err := os.Lstat(i.paths.VPNDir); err == nil {
		if err := i.checkDirectory(i.paths.VPNDir); err != nil {
			return err
		}
		if err := os.Rename(i.paths.VPNDir, previous); err != nil {
			return err
		}
		exists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage, i.paths.VPNDir); err != nil {
		if exists {
			return errors.Join(err, os.Rename(previous, i.paths.VPNDir))
		}
		return err
	}
	for _, item := range images {
		target := filepath.Join(i.paths.VPNDir, filepath.Base(item.target))
		if err := i.checkFile(target); err != nil {
			return err
		}
		if err := i.checkParent(target); err != nil {
			return err
		}
	}
	return nil
}
