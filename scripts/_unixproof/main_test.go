package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAllowedBytes requires the exact header and rejects source edits or duplicate directives.
func TestAllowedBytes(t *testing.T) {
	base := []byte("package fixture\n\nfunc value() int { return 1 }\n")
	for _, tc := range []struct {
		name, file string
		base, head []byte
		want       bool
	}{
		{"unchanged", "fixture.go", base, base, true},
		{"header", "fixture.go", base, append([]byte(unixHeader), base...), true},
		{"extra blank line", "fixture.go", base, append([]byte(unixHeader+"\n"), base...), false},
		{"wrong header", "fixture.go", base, append([]byte("//go:build linux || darwin\n\n"), base...), false},
		{"body", "fixture.go", base, []byte(strings.ReplaceAll(string(base), "return 1", "return 2")), false},
		{"header and body", "fixture.go", base, []byte(unixHeader + strings.ReplaceAll(string(base), "return 1", "return 2")), false},
		{"existing directive", "fixture.go", []byte("//go:build linux\n\npackage fixture\n"), []byte(unixHeader + "//go:build linux\n\npackage fixture\n"), false},
		{"donor", "internal/network/native.go", base, []byte("package fixture\n"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := allowedBytes(tc.file, tc.base, tc.head); got != tc.want {
				t.Fatalf("allowedBytes = %v, want %v", got, tc.want)
			}
		})
	}
}

// proofFixture parses in-memory files and fails immediately if the fixture is malformed.
func proofFixture(t *testing.T, sources map[string]string) sourceProof {
	t.Helper()
	files := map[string][]byte{}
	for name, data := range sources {
		files[name] = []byte(data)
	}
	proof, err := parseSources(files)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// TestDeclarationComparison allows verbatim moves but catches semantic and comment edits.
func TestDeclarationComparison(t *testing.T) {
	declarations := "// item is a movable fixture.\ntype item struct{ n int }\n\n" +
		"// value returns the stored fixture.\nfunc (i *item) value() int { return i.n }\n\n" +
		"// labels retains the complete grouped declaration.\nconst (\n first = 1\n second = 2\n)\n\n" +
		"func init() {}\nfunc init() {}\n"
	base := proofFixture(t, map[string]string{
		"fixture/donor.go": "package fixture\n\nimport \"fmt\"\n\n" + declarations,
		"fixture/other.go": "package fixture\n",
	})
	moved := map[string]string{
		"fixture/donor.go":  unixHeader + "package fixture\n",
		"fixture/shared.go": "package fixture\n\nimport \"fmt\"\n\n" + declarations,
		"fixture/other.go":  "package fixture\n",
	}
	head := proofFixture(t, moved)
	if err := comparePackages(base, head, false); err != nil {
		t.Fatalf("verbatim move failed: %v", err)
	}
	if err := comparePackages(base, head, true); err != nil {
		t.Fatalf("import move failed: %v", err)
	}
	if err := compareNames(base, head); err != nil {
		t.Fatalf("package-preserving move failed: %v", err)
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"body", "return i.n", "return i.n + 1"},
		{"doc", "stored fixture", "changed fixture"},
		{"receiver", "(i *item)", "(i item)"},
		{"group", "second = 2", "second = 3"},
		{"multiplicity", "func init() {}\nfunc init() {}", "func init() {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := map[string]string{}
			for name, data := range moved {
				changed[name] = strings.ReplaceAll(data, tc.old, tc.replacement)
			}
			if err := comparePackages(base, proofFixture(t, changed), false); err == nil {
				t.Fatal("declaration edit passed")
			}
		})
	}
}

// TestImportComparison detects import changes even when every declaration remains identical.
func TestImportComparison(t *testing.T) {
	base := proofFixture(t, map[string]string{"fixture/a.go": "package fixture\nimport \"fmt\"\nfunc f() {}\n"})
	head := proofFixture(t, map[string]string{"fixture/a.go": "package fixture\nimport \"os\"\nfunc f() {}\n"})
	if err := comparePackages(base, head, false); err != nil {
		t.Fatalf("import edit changed declaration comparison: %v", err)
	}
	if err := comparePackages(base, head, true); err == nil {
		t.Fatal("import edit passed")
	}
}

// TestPackageNames keeps external tests separate and detects changed package clauses.
func TestPackageNames(t *testing.T) {
	base := proofFixture(t, map[string]string{
		"fixture/a.go":      "package fixture\nfunc f() {}\n",
		"fixture/a_test.go": "package fixture_test\nfunc f() {}\n",
	})
	if len(base.packages) != 2 {
		t.Fatalf("external tests merged with production: %v", base.packages)
	}
	head := proofFixture(t, map[string]string{
		"fixture/a.go":      "package fixture\nfunc f() {}\n",
		"fixture/a_test.go": "package fixture\nfunc f() {}\n",
	})
	if err := compareNames(base, head); err == nil {
		t.Fatal("package clause edit passed")
	}
}

// TestFileSets admits only the named shared source and rejects missing or Windows sources.
func TestFileSets(t *testing.T) {
	base := map[string][]byte{"fixture.go": []byte("package fixture\n")}
	for _, tc := range []struct {
		name string
		head map[string][]byte
		want bool
	}{
		{"same", base, true},
		{"shared", map[string][]byte{"fixture.go": base["fixture.go"], "internal/network/routing_shared.go": nil}, true},
		{"new", map[string][]byte{"fixture.go": base["fixture.go"], "new.go": nil}, false},
		{"removed", map[string][]byte{}, false},
		{"windows", map[string][]byte{"fixture.go": base["fixture.go"], "new_windows.go": nil}, false},
		{"windows tests", map[string][]byte{"fixture.go": base["fixture.go"], "new_windows_test.go": nil}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := compareFileSets(base, tc.head); (err == nil) != tc.want {
				t.Fatalf("compareFileSets = %v, want pass %v", err, tc.want)
			}
		})
	}
	if err := compareFileBytes(base, map[string][]byte{"fixture.go": []byte("package changed\n")}); err == nil {
		t.Fatal("file edit passed")
	}
}

// writeFixture creates regular source inputs beneath a test-owned directory.
func writeFixture(t *testing.T, root, name, data string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestPathPolicy covers working-tree byte checks, scoped additions and added-only vectors.
func TestPathPolicy(t *testing.T) {
	base, head := t.TempDir(), t.TempDir()
	writeFixture(t, base, "internal/a.go", "package fixture\n")
	writeFixture(t, head, "internal/a.go", unixHeader+"package fixture\n")
	writeFixture(t, head, "internal/b.go", "package fixture\n")
	writeFixture(t, base, "internal/c.go", "package fixture\n")
	writeFixture(t, head, "internal/c.go", "package changed\n")
	writeFixture(t, head, "testdata/interop/new.json", "{}\n")
	writeFixture(t, base, "testdata/interop/existing.json", "{}\n")
	writeFixture(t, head, "testdata/interop/existing.json", "{\"changed\": true}\n")
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"internal/a.go", true}, {"internal/b.go", false}, {"internal/c.go", false},
		{"internal/native_windows.go", true}, {"internal/native_windows_test.go", true},
		{"internal/native_windows_extra.go", false}, {"internal/winapi/native.go", true},
		{"internal/winapi-other/native.go", false}, {"windows/Fortix/Program.cs", true},
		{"scripts/_unixproof/main.go", true}, {"scripts/check-unix-unchanged.sh", true},
		{"scripts/other.sh", false}, {"README.md", true}, {"LICENSE", false}, {"docs/windows.md", true},
		{"testdata/interop/new.json", true}, {"testdata/interop/existing.json", false},
		{"testdata/interop/missing.json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathAllowed(base, head, tc.name); got != tc.want {
				t.Fatalf("pathAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCheckoutRoot canonicalizes directory aliases before comparing go list paths.
func TestCheckoutRoot(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "checkout")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	want, err := checkoutRoot(actual)
	if err != nil {
		t.Fatal(err)
	}
	got, err := checkoutRoot(alias)
	if err != nil || got != want {
		t.Fatalf("checkoutRoot(alias) = %q, %v; want %q", got, err, want)
	}
}

// TestReadRegular rejects a source symlink instead of proving bytes from another path.
func TestReadRegular(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "source.go", "package fixture\n")
	if err := os.Symlink(filepath.Join(root, "source.go"), filepath.Join(root, "link.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(filepath.Join(root, "link.go")); err == nil {
		t.Fatal("symlink input passed")
	}
}
