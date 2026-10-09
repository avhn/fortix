// Package animate tests read-only preference probes and malformed native output.
package animate

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// probeRunner captures argv and timeout while returning a synthetic probe response.
type probeRunner struct {
	output  string
	err     error
	name    string
	args    []string
	bounded bool
}

// Output records the read-only invocation and returns configured bytes and error.
func (r *probeRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.name, r.args = name, args
	deadline, ok := ctx.Deadline()
	r.bounded = ok && time.Until(deadline) <= 2*time.Second
	return []byte(r.output), r.err
}

// TestSystemMotion covers native booleans, missing tools, unknown outputs, and exact argv.
func TestSystemMotion(t *testing.T) {
	for _, tc := range []struct {
		platform, output string
		err              error
		want             Motion
	}{
		{"darwin", "1\n", nil, Reduce}, {"darwin", "0\n", nil, Allow}, {"darwin", "true", nil, Reduce}, {"darwin", "false", nil, Allow},
		{"linux", "true\n", nil, Allow}, {"linux", "false\n", nil, Reduce}, {"linux", "1", nil, Unknown},
		{"darwin", "missing", nil, Unknown}, {"linux", "", nil, Unknown}, {"linux", "true", errors.New("missing tool"), Unknown}, {"other", "true", nil, Unknown},
	} {
		runner := &probeRunner{output: tc.output, err: tc.err}
		if got := (SystemMotion{Platform: tc.platform, Runner: runner}).Read(context.Background()); got != tc.want {
			t.Fatalf("%+v: got %v", tc, got)
		}
		if tc.platform == "other" {
			if runner.name != "" {
				t.Fatal("unsupported platform ran a command")
			}
			continue
		}
		if !runner.bounded {
			t.Fatal("probe lacked timeout")
		}
		name, args := "defaults", []string{"read", "com.apple.universalaccess", "reduceMotion"}
		if tc.platform == "linux" {
			name, args = "gsettings", []string{"get", "org.gnome.desktop.interface", "enable-animations"}
		}
		if runner.name != name || !reflect.DeepEqual(runner.args, args) {
			t.Fatal(runner)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (execRunner{}).Output(ctx, "fortix-nonexistent-test-command"); err == nil {
		t.Fatal("cancelled/missing command succeeded")
	}
}

// FuzzParseMotion ensures arbitrary desktop output never grants motion permission
// unless it is exactly one of the supported native boolean spellings after trimming.
func FuzzParseMotion(f *testing.F) {
	for _, s := range []string{"true", "false", "0", "1", "", " true\n", "true\nfalse", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, output string) {
		for _, platform := range []string{"darwin", "linux", "other"} {
			got := parseMotion(platform, output)
			if got > Allow {
				t.Fatal("invalid policy")
			}
			if got != Unknown {
				value := strings.TrimSpace(output)
				valid := (platform == "darwin" && (value == "0" || value == "1" || value == "true" || value == "false")) ||
					(platform == "linux" && (value == "true" || value == "false"))
				if !valid {
					t.Fatal("unrecognized output enabled a known policy")
				}
				runner := &probeRunner{output: output}
				if read := (SystemMotion{Platform: platform, Runner: runner}).Read(context.Background()); read != got {
					t.Fatal("probe and parser disagree")
				}
			}
		}
	})
}
