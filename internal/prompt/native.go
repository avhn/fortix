// Package prompt provides hidden terminal input and injectable native desktop dialogs.
// Cancellation and unavailable UI are explicit errors; command errors never expose output.
package prompt

import (
	"context"
	"errors"
	"html"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Prompt errors distinguish cancellation, missing UI, and failed execution without secrets.
var (
	ErrCancelled   = errors.New("prompt cancelled")
	ErrUnavailable = errors.New("prompt unavailable")
	ErrFailed      = errors.New("prompt failed")
)

// dialogTimeout bounds native processes even if a caller supplies no deadline.
const dialogTimeout = 2 * time.Minute

// Dialog requests a hidden password or a two-button confirmation.
// Password returns no secret on error; Confirm returns false for a negative choice.
type Dialog interface {
	Password(ctx context.Context, title, message string) (string, error)
	Confirm(ctx context.Context, title, message string) (bool, error)
}

// Runner executes a program directly with arguments and optional script input.
// Output contains only stdout; errors must never be displayed without sanitization.
type Runner interface {
	Run(ctx context.Context, program string, args []string, stdin io.Reader) ([]byte, error)
}

// ExecRunner is the production subprocess runner. It never invokes a shell.
type ExecRunner struct{}

// Run captures stdout while discarding stderr; cancellation is bounded by ctx.
// Command errors are returned for internal classification, never as user-facing text.
func (ExecRunner) Run(ctx context.Context, program string, args []string, stdin io.Reader) ([]byte, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = stdin
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	return cmd.Output()
}

// Native implements platform dialogs and notifications with injectable process discovery.
// The zero value uses this OS, exec.LookPath, and ExecRunner; tests inject both dependencies.
type Native struct {
	Runner   Runner
	LookPath func(string) (string, error)
	platform string
}

// dependencies returns production defaults for omitted injection fields without executing UI.
func (n Native) dependencies() (Runner, func(string) (string, error), string) {
	runner, lookup, platform := n.Runner, n.LookPath, n.platform
	if runner == nil {
		runner = ExecRunner{}
	}
	if lookup == nil {
		lookup = exec.LookPath
	}
	if platform == "" {
		platform = runtime.GOOS
	}
	return runner, lookup, platform
}

// AppleScript programs consume all visible text as argv, never as executable source.
// Tagged password output distinguishes an arbitrary password from the cancellation marker.
const (
	passwordScript = `on run argv
try
set response to display dialog (item 2 of argv) with title (item 1 of argv) default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel"
return "ok:" & text returned of response
on error number -128
return "cancel:"
end try
end run`
	confirmScript = `on run argv
try
set response to display dialog (item 2 of argv) with title (item 1 of argv) buttons {"No", "Yes"} default button "No"
return button returned of response
on error number -128
return "cancel:"
end try
end run`
	notifyScript = `on run argv
display notification (item 2 of argv) with title (item 1 of argv)
end run`
)

// Password presents hidden input, returning ErrCancelled or ErrUnavailable as appropriate.
// Passwords travel only through stdout; titles and messages are literal command arguments.
func (n Native) Password(ctx context.Context, title, message string) (string, error) {
	out, apple, err := n.dialog(ctx, title, message, true)
	if err != nil {
		return "", err
	}
	text := trimLine(out)
	if apple {
		if text == "cancel:" {
			return "", ErrCancelled
		}
		if !strings.HasPrefix(text, "ok:") {
			return "", ErrFailed
		}
		text = strings.TrimPrefix(text, "ok:")
	}
	return text, nil
}

// Confirm presents Yes and No buttons, returning false on No and ErrCancelled on dismissal.
// Linux tools cannot distinguish No from dismissal, so both return ErrCancelled.
func (n Native) Confirm(ctx context.Context, title, message string) (bool, error) {
	out, apple, err := n.dialog(ctx, title, message, false)
	if err != nil {
		return false, err
	}
	if !apple {
		return true, nil
	}
	switch trimLine(out) {
	case "Yes":
		return true, nil
	case "No":
		return false, nil
	case "cancel:":
		return false, ErrCancelled
	default:
		return false, ErrFailed
	}
}

// dialog selects an installed native tool and runs it under a bounded context.
// It maps cancellation exit codes but suppresses all raw subprocess error text.
func (n Native) dialog(ctx context.Context, title, message string, password bool) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	runner, lookup, platform := n.dependencies()
	var program, script string
	var args []string
	switch platform {
	case "darwin":
		program = "/usr/bin/osascript"
		script = confirmScript
		if password {
			script = passwordScript
		}
		args = []string{"-", title, message}
	case "linux":
		if path, err := lookup("zenity"); err == nil {
			program = path
			mode := "--question"
			if password {
				mode = "--password"
			}
			args = []string{mode, "--title=" + title}
			// Older zenity password dialogs do not accept the question's text option.
			if !password {
				args = append(args, "--no-markup", "--text="+message)
			}
		} else if path, err := lookup("kdialog"); err == nil {
			program = path
			mode := "--yesno"
			if password {
				mode = "--password"
			}
			args = []string{"--title=" + html.EscapeString(title), mode, "--", html.EscapeString(message)}
		} else {
			return nil, false, ErrUnavailable
		}
	default:
		return nil, false, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, dialogTimeout)
	defer cancel()
	out, err := runner.Run(ctx, program, args, strings.NewReader(script))
	if err != nil {
		if ctx.Err() != nil {
			return nil, platform == "darwin", ctx.Err()
		}
		var exit interface{ ExitCode() int }
		if platform == "linux" && errors.As(err, &exit) && exit.ExitCode() == 1 {
			return nil, false, ErrCancelled
		}
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil, platform == "darwin", ErrUnavailable
		}
		return nil, platform == "darwin", ErrFailed
	}
	if err := ctx.Err(); err != nil {
		return nil, platform == "darwin", err
	}
	if len(out) > maxInput+16 {
		return nil, platform == "darwin", ErrFailed
	}
	return out, platform == "darwin", nil
}

// Notify sends a desktop notification, silently skipping unsupported or missing tools.
// Notification command failures are sanitized; no shell interprets title or body.
func (n Native) Notify(ctx context.Context, title, body string) error {
	runner, lookup, platform := n.dependencies()
	var program, script string
	var args []string
	switch platform {
	case "darwin":
		program, script = "/usr/bin/osascript", notifyScript
		args = []string{"-", title, body}
	case "linux":
		var err error
		program, err = lookup("notify-send")
		if err != nil {
			return nil
		}
		args = []string{"--", title, body}
	default:
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := runner.Run(ctx, program, args, strings.NewReader(script)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrFailed
	}
	return nil
}

// Notify uses the current desktop's default runner; absent notification tools are ignored.
func Notify(ctx context.Context, title, body string) error {
	return (Native{}).Notify(ctx, title, body)
}

// trimLine removes exactly one process-added line ending, preserving secret whitespace.
func trimLine(data []byte) string {
	return strings.TrimSuffix(string(data), "\n")
}
