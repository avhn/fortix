// Command unixproof compares selected Unix sources and release inputs with a fixed checkout.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Keep exceptions explicit so each later phase has to declare its additional scope.
var ALLOWED_NEW = map[string]bool{"internal/network/routing_shared.go": true}
var MOVE_DONORS = map[string]bool{"internal/network/native.go": true, "internal/network/manager.go": true}

// The app icon moved to the graphite artwork in both appearances; these are its only
// intended macOS packaging changes.
var ALLOWED_CHANGED = map[string]bool{"packaging/macos/AppIcon.icns": true, "packaging/macos/Assets.car": true}
var ALLOWED_PATHS = []string{
	"docs/windows.md", "docs/release.md", "assets/icon/art.py", "docs/assets/readme-header.png",
	"packaging/macos/AppIcon.icns", "packaging/macos/Assets.car", "scripts/check-unix-unchanged.sh",
	"scripts/render-winget.sh", "scripts/verify-release-assets.sh", "scripts/release-checksums.sh",
	"scripts/test-packaging.sh", ".github/workflows/windows.yml",
	".github/workflows/unix-unchanged.yml", ".github/workflows/release.yml",
}
var ALLOWED_PREFIXES = []string{"internal/winfs/", "internal/winapi/", "windows/", "packaging/windows/", "scripts/_unixproof/"}
var PROTECTED_FILES = []string{"go.mod", "go.sum", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.txt", ".goreleaser.yaml"}
var PROTECTED_PREFIXES = []string{"macos/", "packaging/macos/", "packaging/debian/"}

const unixHeader = "//go:build darwin || linux\n\n"

// target fixes the platform and cgo selection without compiling its packages.
type target struct {
	os, arch, cgo string
}

// listedPackage retains original source names, excluding generated test harnesses.
type listedPackage struct {
	Dir, ImportPath                                                                           string
	Module                                                                                    *struct{ Main bool }
	GoFiles, CgoFiles, TestGoFiles, XTestGoFiles, EmbedFiles, TestEmbedFiles, XTestEmbedFiles []string
}

// packageProof holds verbatim declaration multisets and the package-wide import union.
type packageProof struct {
	declarations map[string][]string
	imports      map[string]bool
}

// sourceProof groups original files by directory and package clause, including external tests.
type sourceProof struct {
	packages map[string]*packageProof
	names    map[string]map[string]bool
}

// reporter accumulates failures while emitting one deterministic line per check.
type reporter struct{ failed bool }

// check reports named failures without letting one mismatch suppress the remaining checks.
func (r *reporter) check(scope, name string, err error) {
	status, detail := "PASS", ""
	if err != nil {
		r.failed = true
		status, detail = "FAIL", ": "+err.Error()
	}
	line := fmt.Sprintf("%s %s %s%s", status, scope, name, detail)
	fmt.Println(strings.NewReplacer("\n", "; ", "\r", "", "\u2013", "-", "\u2014", "-").Replace(line))
}

// main bounds the complete proof and returns a failing exit status for any mismatch.
func main() {
	base := flag.String("base", "", "checkout of the baseline commit")
	head := flag.String("head", "", "repository working tree to check")
	flag.Parse()
	r := &reporter{}
	if *base == "" || *head == "" || flag.NArg() != 0 {
		r.check("repository", "arguments", fmt.Errorf("use -base CHECKOUT -head REPOSITORY"))
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()
		runProof(ctx, r, *base, *head)
	}
	if r.failed {
		fmt.Println("FAIL")
		os.Exit(1)
	}
	fmt.Println("PASS")
}

// checkoutRoot resolves directory aliases so go list's physical paths stay inside the checkout.
func checkoutRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}

// runProof compares each platform serially, then checks immutable inputs and changed paths.
func runProof(ctx context.Context, r *reporter, base, head string) {
	base, err := checkoutRoot(base)
	if err != nil {
		r.check("repository", "base path", err)
		return
	}
	head, err = checkoutRoot(head)
	if err != nil {
		r.check("repository", "head path", err)
		return
	}
	for _, t := range []target{{"darwin", "amd64", "1"}, {"darwin", "arm64", "1"}, {"linux", "amd64", "0"}, {"linux", "arm64", "0"}} {
		scope := t.os + "/" + t.arch
		oldFiles, oldErr := listSources(ctx, base, t)
		newFiles, newErr := listSources(ctx, head, t)
		if oldErr != nil || newErr != nil {
			r.check(scope, "source listing", fmt.Errorf("base: %v; head: %v", oldErr, newErr))
			continue
		}
		r.check(scope, "file sets", compareFileSets(oldFiles, newFiles))
		r.check(scope, "file bytes", compareFileBytes(oldFiles, newFiles))
		oldProof, oldErr := parseSources(oldFiles)
		newProof, newErr := parseSources(newFiles)
		if oldErr != nil || newErr != nil {
			r.check(scope, "source parsing", fmt.Errorf("base: %v; head: %v", oldErr, newErr))
		} else {
			r.check(scope, "declarations", comparePackages(oldProof, newProof, false))
			r.check(scope, "imports", comparePackages(oldProof, newProof, true))
			r.check(scope, "package names", compareNames(oldProof, newProof))
		}
		oldGraph, oldErr := command(ctx, base, t, "go", "list", "-mod=readonly", "-m", "all")
		newGraph, newErr := command(ctx, head, t, "go", "list", "-mod=readonly", "-m", "all")
		graphErr := error(nil)
		if oldErr != nil || newErr != nil {
			graphErr = fmt.Errorf("base: %v; head: %v", oldErr, newErr)
		} else if !bytes.Equal(oldGraph, newGraph) {
			graphErr = fmt.Errorf("module graph differs")
		}
		r.check(scope, "module graph", graphErr)
	}
	r.check("repository", "protected bytes", compareProtected(ctx, base, head))
	r.check("repository", "path policy", checkPaths(ctx, base, head))
}

// command runs a bounded child with deterministic Go settings and preserves failure output.
func command(ctx context.Context, root string, t target, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = root
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "GOMAXPROCS=2", "GOFLAGS=-p=2", "GOWORK=off")
	if t.os != "" {
		cmd.Env = append(cmd.Env, "GOOS="+t.os, "GOARCH="+t.arch, "CGO_ENABLED="+t.cgo)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// listSources reads module-local original sources, deduplicating the variants from go list -test.
func listSources(ctx context.Context, root string, t target) (map[string][]byte, error) {
	out, err := command(ctx, root, t, "go", "list", "-mod=readonly", "-deps", "-test", "-json", "./...")
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := decoder.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		// Test executables use generated cache files, not repository source declarations.
		if p.Module == nil || !p.Module.Main || strings.HasSuffix(p.ImportPath, ".test") {
			continue
		}
		for _, group := range [][]string{p.GoFiles, p.CgoFiles, p.TestGoFiles, p.XTestGoFiles, p.EmbedFiles, p.TestEmbedFiles, p.XTestEmbedFiles} {
			for _, name := range group {
				full := name
				if !filepath.IsAbs(full) {
					full = filepath.Join(p.Dir, full)
				}
				rel, err := filepath.Rel(root, full)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return nil, fmt.Errorf("module-local file escapes checkout: %s", full)
				}
				rel = filepath.ToSlash(rel)
				if _, exists := files[rel]; exists {
					continue
				}
				data, err := readRegular(full)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", rel, err)
				}
				files[rel] = data
			}
		}
	}
	return files, nil
}

// readRegular rejects symlink substitutions before reading a checked input.
func readRegular(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	return os.ReadFile(name)
}

// sortedKeys stabilizes diagnostics regardless of map iteration order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// compareFileSets permits only declared additions and never Windows source on a Unix target.
func compareFileSets(base, head map[string][]byte) error {
	for _, name := range sortedKeys(base) {
		if _, exists := head[name]; !exists {
			return fmt.Errorf("removed Unix file: %s", name)
		}
	}
	for _, name := range sortedKeys(head) {
		if strings.Contains(path.Base(name), "_windows") && strings.HasSuffix(name, ".go") {
			return fmt.Errorf("Windows file selected for Unix: %s", name)
		}
		if _, exists := base[name]; !exists && !ALLOWED_NEW[name] {
			return fmt.Errorf("unexpected Unix file: %s", name)
		}
	}
	return nil
}

// allowedBytes admits identity, the exact leading Unix header, or an explicit move donor.
func allowedBytes(name string, base, head []byte) bool {
	if bytes.Equal(base, head) || MOVE_DONORS[name] {
		return true
	}
	// A second build directive is not a permissible header-only edit.
	return !bytes.Contains(base, []byte("//go:build")) && bytes.Equal(head, append([]byte(unixHeader), base...))
}

// compareFileBytes leaves donor changes to the package-wide declaration and import proof.
func compareFileBytes(base, head map[string][]byte) error {
	for _, name := range sortedKeys(base) {
		if data, exists := head[name]; exists && !allowedBytes(name, base[name], data) {
			return fmt.Errorf("Unix file changed beyond allowed header: %s", name)
		}
	}
	return nil
}

// parseSources preserves declaration bytes and multiplicity while ignoring file positions.
func parseSources(files map[string][]byte) (sourceProof, error) {
	proof := sourceProof{packages: map[string]*packageProof{}, names: map[string]map[string]bool{}}
	for _, name := range sortedKeys(files) {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		data := files[name]
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, data, parser.ParseComments)
		if err != nil {
			return proof, err
		}
		dir := path.Dir(name)
		if proof.names[dir] == nil {
			proof.names[dir] = map[string]bool{}
		}
		proof.names[dir][file.Name.Name] = true
		key := dir + "/" + file.Name.Name
		p := proof.packages[key]
		if p == nil {
			p = &packageProof{declarations: map[string][]string{}, imports: map[string]bool{}}
			proof.packages[key] = p
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return proof, err
			}
			p.imports[importPath] = true
		}
		for _, decl := range file.Decls {
			keys, doc, err := declarationKeys(fset, decl)
			if err != nil {
				return proof, fmt.Errorf("%s: %w", name, err)
			}
			start := decl.Pos()
			if doc != nil {
				start = doc.Pos()
			}
			value := string(data[fset.Position(start).Offset:fset.Position(decl.End()).Offset])
			for _, key := range keys {
				p.declarations[key] = append(p.declarations[key], value)
			}
		}
	}
	for _, p := range proof.packages {
		for _, values := range p.declarations {
			sort.Strings(values)
		}
	}
	return proof, nil
}

// declarationKeys names declarations by kind, receiver type and identifier, excluding imports.
func declarationKeys(fset *token.FileSet, decl ast.Decl) ([]string, *ast.CommentGroup, error) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		receiver := ""
		if d.Recv != nil {
			var out bytes.Buffer
			if err := format.Node(&out, fset, d.Recv.List[0].Type); err != nil {
				return nil, nil, err
			}
			receiver = out.String()
		}
		return []string{"func:" + receiver + ":" + d.Name.Name}, d.Doc, nil
	case *ast.GenDecl:
		if d.Tok == token.IMPORT {
			return nil, nil, nil
		}
		var keys []string
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				keys = append(keys, d.Tok.String()+"::"+s.Name.Name)
			case *ast.ValueSpec:
				for _, name := range s.Names {
					keys = append(keys, d.Tok.String()+"::"+name.Name)
				}
			}
		}
		return keys, d.Doc, nil
	default:
		return nil, nil, fmt.Errorf("unsupported declaration %T", decl)
	}
}

// comparePackages checks either verbatim declaration multisets or import unions per package.
func comparePackages(base, head sourceProof, imports bool) error {
	all := map[string]bool{}
	for key := range base.packages {
		all[key] = true
	}
	for key := range head.packages {
		all[key] = true
	}
	for _, key := range sortedKeys(all) {
		a, b := base.packages[key], head.packages[key]
		if a == nil || b == nil {
			return fmt.Errorf("package added or removed: %s", key)
		}
		if imports {
			if !reflect.DeepEqual(a.imports, b.imports) {
				return fmt.Errorf("import set changed: %s", key)
			}
		} else if !reflect.DeepEqual(a.declarations, b.declarations) {
			keys := map[string]bool{}
			for name := range a.declarations {
				keys[name] = true
			}
			for name := range b.declarations {
				keys[name] = true
			}
			for _, name := range sortedKeys(keys) {
				if !reflect.DeepEqual(a.declarations[name], b.declarations[name]) {
					return fmt.Errorf("declaration changed: %s %s", key, name)
				}
			}
		}
	}
	return nil
}

// compareNames ensures file regrouping cannot alter normal or external-test package clauses.
func compareNames(base, head sourceProof) error {
	if !reflect.DeepEqual(base.names, head.names) {
		return fmt.Errorf("package clause names differ: base %v; head %v", base.names, head.names)
	}
	return nil
}

// gitPaths decodes NUL-delimited names so spaces and other unusual bytes remain intact.
func gitPaths(ctx context.Context, root string, args ...string) ([]string, error) {
	out, err := command(ctx, root, target{}, "git", args...)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00"), nil
}

// hasPrefix confines recursive allowlists to directory boundaries.
func hasPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// compareProtected checks the union of tracked and visible untracked immutable inputs.
func compareProtected(ctx context.Context, base, head string) error {
	files := map[string]bool{}
	for _, name := range PROTECTED_FILES {
		files[name] = true
	}
	for _, root := range []string{base, head} {
		names, err := gitPaths(ctx, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
		if err != nil {
			return err
		}
		for _, name := range names {
			if hasPrefix(name, PROTECTED_PREFIXES) {
				files[name] = true
			}
		}
	}
	for _, name := range sortedKeys(files) {
		if ALLOWED_CHANGED[name] {
			continue
		}
		a, aErr := readRegular(filepath.Join(base, filepath.FromSlash(name)))
		b, bErr := readRegular(filepath.Join(head, filepath.FromSlash(name)))
		if os.IsNotExist(aErr) && os.IsNotExist(bErr) {
			continue
		}
		if aErr != nil || bErr != nil || !bytes.Equal(a, b) {
			return fmt.Errorf("protected file differs: %s (base: %v; head: %v)", name, aErr, bErr)
		}
	}
	return nil
}

// pathAllowed admits scoped tooling and Windows paths, or Go edits covered by the byte rule.
func pathAllowed(base, head, name string) bool {
	if ALLOWED_CHANGED[name] || ALLOWED_NEW[name] || hasPrefix(name, ALLOWED_PREFIXES) {
		return true
	}
	for _, allowed := range ALLOWED_PATHS {
		if name == allowed {
			return true
		}
	}
	if strings.HasSuffix(name, "_windows.go") || strings.HasSuffix(name, "_windows_test.go") {
		return true
	}
	a, aErr := readRegular(filepath.Join(base, filepath.FromSlash(name)))
	b, bErr := readRegular(filepath.Join(head, filepath.FromSlash(name)))
	if strings.HasPrefix(name, "testdata/interop/") {
		return os.IsNotExist(aErr) && bErr == nil
	}
	return strings.HasSuffix(name, ".go") && aErr == nil && bErr == nil && allowedBytes(name, a, b)
}

// checkPaths includes committed, staged, unstaged and untracked changes against the base hash.
func checkPaths(ctx context.Context, base, head string) error {
	hash, err := command(ctx, base, target{}, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	changed := map[string]bool{}
	for _, args := range [][]string{
		{"diff", "--name-only", "-z", "--no-renames", strings.TrimSpace(string(hash)) + "..HEAD", "--"},
		{"diff", "--name-only", "-z", "--no-renames", "HEAD", "--"},
		{"ls-files", "--others", "--exclude-standard", "-z"},
	} {
		names, err := gitPaths(ctx, head, args...)
		if err != nil {
			return err
		}
		for _, name := range names {
			if name != "" {
				changed[name] = true
			}
		}
	}
	var rejected []string
	for _, name := range sortedKeys(changed) {
		if !pathAllowed(base, head, name) {
			rejected = append(rejected, name)
		}
	}
	if len(rejected) != 0 {
		return fmt.Errorf("changed paths outside allowlist: %s", strings.Join(rejected, ", "))
	}
	return nil
}
