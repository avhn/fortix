package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReleaseProofPreflight rejects invalid invocation and baseline before building payloads.
func TestReleaseProofPreflight(t *testing.T) {
	script, err := filepath.Abs("../check-release-unchanged.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, baseline, want string
		args                 []string
	}{
		{"arguments", "HEAD", "usage: check-release-unchanged.sh", []string{"unexpected"}},
		{"baseline", "fortix-proof-nonexistent-baseline", "invalid Unix baseline:", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", append([]string{script}, tc.args...)...)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "FORTIX_UNIX_BASE=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "FORTIX_UNIX_BASE="+tc.baseline)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("preflight: err=%v, output=%s", err, out)
			}
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
		})
	}
}

// TestReleaseSymbolNormalization exercises layout tolerance and instruction-change rejection.
func TestReleaseSymbolNormalization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "release_symbols_test.py")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("symbol normalization: %v\n%s", err, out)
	}
}

// TestReleaseSymbolsBinaries proves layout changes pass while actual instructions fail.
func TestReleaseSymbolsBinaries(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "main.go")
	fixture := "package main\nimport \"fmt\"\n// value avoids inlining so instruction changes have a named symbol.\n//go:noinline\nfunc value() int { return 1234 }\nfunc main() { fmt.Println(value()) }\n"
	bins := make([]string, 3)
	for i, text := range []string{fixture, unixHeader + fixture, strings.Replace(fixture, "1234", "1235", 1)} {
		if err := os.WriteFile(source, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		bins[i] = filepath.Join(root, []string{"base", "moved", "changed"}[i])
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-ldflags=-w -buildid=", "-o", bins[i], source)
		cmd.Env = append(os.Environ(), "GOMAXPROCS=2", "GOFLAGS=-p=2", "GOWORK=off")
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("fixture build: %v\n%s", err, out)
		}
	}
	for i, bin := range bins[1:] {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		cmd := exec.CommandContext(ctx, "python3", "-I", "release_symbols.py", "fixture", bins[0], bin)
		cmd.Env = append(os.Environ(), "GOMAXPROCS=2", "GOFLAGS=-p=2")
		out, err := cmd.CombinedOutput()
		cancel()
		if i == 0 && (err != nil || !strings.Contains(string(out), "PASS fixture")) {
			t.Fatalf("layout control: %v\n%s", err, out)
		}
		if i == 1 && (err == nil || !strings.Contains(string(out), "disassembly: main.value")) {
			t.Fatalf("changed instruction accepted: %v\n%s", err, out)
		}
	}
}

// TestReleaseProofPathPolicy permits the verifier without loosening protected release inputs.
func TestReleaseProofPathPolicy(t *testing.T) {
	allowed := false
	for _, path := range ALLOWED_PATHS {
		if path == "scripts/check-release-unchanged.sh" {
			allowed = true
		}
		if path == "README.md" || path == ".goreleaser.yaml" {
			t.Fatalf("protected release input allowlisted: %s", path)
		}
	}
	if !allowed {
		t.Fatal("release proof script is not allowlisted")
	}
}
