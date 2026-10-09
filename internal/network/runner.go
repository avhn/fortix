//go:build darwin || linux

package network

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Runner executes argv without a shell, selecting only the supplied absolute candidates.
// Run returns bounded stdout or an error; implementations must honor cancellation.
type Runner interface {
	Run(context.Context, []string, ...string) ([]byte, error)
}

// ExecRunner selects trusted system executables without consulting PATH or the shell.
// It checks each candidate and its ancestors before execution and bounds output.
type ExecRunner struct{}

// Run chooses the first existing root-owned executable in candidates and executes args.
// Missing candidates are skipped; unsafe files, command failures and cancellation fail.
// A ten-second ceiling also bounds callers that supplied no command deadline.
func (ExecRunner) Run(ctx context.Context, candidates []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, path := range candidates {
		if err := trustedExecutable(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		cmd.Dir = "/"
		cmd.WaitDelay = commandWait
		var output boundedOutput
		var diagnostic boundedDiagnostic
		cmd.Stdout = &output
		cmd.Stderr = &diagnostic
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, errors.Join(ctx.Err(), &CommandError{Stderr: diagnostic.buffer.String()})
			}
			return nil, &CommandError{Stderr: diagnostic.buffer.String()}
		}
		return output.buffer.Bytes(), nil
	}
	return nil, errors.New("network command unavailable")
}

// CommandError retains bounded command stderr exclusively for internal classification.
// Error deliberately returns a fixed message, never raw privileged command diagnostics.
// Injected runners may return this type to emulate route collisions without execution.
type CommandError struct{ Stderr string }

// Error returns a stable non-secret diagnostic suitable for public error handling.
func (*CommandError) Error() string { return "network command failed" }

// routeExistsError classifies fixed-locale route collision messages from a typed failure.
// The inspected text is bounded even for injected runners, and is never displayed.
func routeExistsError(err error) bool {
	var command *CommandError
	if !errors.As(err, &command) {
		return false
	}
	text := command.Stderr
	if len(text) > 4096 {
		text = text[:4096]
	}
	text = strings.ToLower(text)
	return strings.Contains(text, "file exists") || strings.Contains(text, "already exists")
}

// boundedDiagnostic drains stderr while retaining only its first four KiB.
// Truncation cannot block a noisy child or hide a route error behind unbounded memory.
type boundedDiagnostic struct{ buffer bytes.Buffer }

// Write captures the diagnostic prefix and reports all bytes consumed to drain pipes.
// The buffer never grows beyond four KiB even when the child writes a single huge block.
func (b *boundedDiagnostic) Write(p []byte) (int, error) {
	n := min(len(p), 4096-b.buffer.Len())
	_, _ = b.buffer.Write(p[:n])
	return len(p), nil
}

// boundedOutput limits command output to one MiB; overflow fails rather than truncating.
// A named buffer prevents io.Copy from bypassing Write through a promoted ReadFrom.
type boundedOutput struct{ buffer bytes.Buffer }

// Write accepts p only if the combined output remains within the command record limit.
// Oversized data returns zero and an error without allocating a copy of that data.
func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 1<<20 {
		return 0, errors.New("network command output exceeds limit")
	}
	return b.buffer.Write(p)
}

// trustedExecutable verifies a clean absolute candidate and its resolved ancestors.
// Root ownership, regular/executable mode and non-writable ancestors are required.
func trustedExecutable(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid network executable path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for current := resolved; ; current = filepath.Dir(current) {
		var st unix.Stat_t
		if err := unix.Lstat(current, &st); err != nil {
			return err
		}
		if st.Uid != 0 || st.Mode&0022 != 0 {
			return errors.New("unsafe network executable ownership")
		}
		if current == resolved {
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0111 == 0 {
				return errors.New("unsafe network executable mode")
			}
		} else if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("unsafe network executable ancestor")
		}
		if current == "/" {
			return nil
		}
	}
}
