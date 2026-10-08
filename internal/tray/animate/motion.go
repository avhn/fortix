// Package animate also provides bounded, read-only desktop preference probes.
package animate

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// CommandRunner executes a named program without a shell, honoring context cancellation.
// Missing programs and nonzero exits return errors. ExitError.Stderr must contain
// diagnostics so an absent Darwin preference can be distinguished from probe failures.
type CommandRunner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}

// SystemMotion probes the selected platform using Runner, or exec when Runner is nil.
// Unsupported platforms and unavailable services return Unknown; an unset Darwin
// reduceMotion preference uses the system default, Allow.
type SystemMotion struct {
	Platform string
	Runner   CommandRunner
}

// Read returns live motion policy after a read-only command with a two-second timeout.
// Darwin reduceMotion is inverted relative to GNOME enable-animations; malformed
// output, missing desktop services, and command errors fail closed to Unknown,
// except a confirmed absent Darwin key, which defaults to allowing motion.
func (s SystemMotion) Read(ctx context.Context) Motion {
	runner := s.Runner
	if runner == nil {
		runner = execRunner{}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var output []byte
	var err error
	switch s.Platform {
	case "darwin":
		output, err = runner.Output(ctx, "defaults", "read", "com.apple.universalaccess", "reduceMotion")
	case "linux":
		output, err = runner.Output(ctx, "gsettings", "get", "org.gnome.desktop.interface", "enable-animations")
	default:
		return Unknown
	}
	if ctx.Err() != nil {
		return Unknown
	}
	if err != nil {
		var exit *exec.ExitError
		// defaults omits this key until the user changes the system preference.
		if s.Platform == "darwin" && errors.As(err, &exit) && exit.ExitCode() > 0 &&
			strings.Contains(string(exit.Stderr), "The domain/default pair of (com.apple.universalaccess, reduceMotion) does not exist") {
			return Allow
		}
		return Unknown
	}
	return parseMotion(s.Platform, string(output))
}

// parseMotion strictly maps native boolean spellings to policy, without I/O or errors.
// Other outputs, including empty output, are Unknown rather than permission to animate.
func parseMotion(platform, output string) Motion {
	value := strings.TrimSpace(output)
	switch platform {
	case "darwin":
		switch value {
		case "1", "true":
			return Reduce
		case "0", "false":
			return Allow
		}
	case "linux":
		switch value {
		case "true":
			return Allow
		case "false":
			return Reduce
		}
	}
	return Unknown
}

// execRunner runs desktop probes without a shell and never logs captured output.
type execRunner struct{}

// Output returns stdout or a command error, with cancellation and pipe-wait bounds.
func (execRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	return cmd.Output()
}
