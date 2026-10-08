// Package prompt provides hidden terminal input and native desktop interaction.
// Terminal responses never enter command arguments or diagnostic output.
package prompt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// maxInput limits a terminal response without truncating an accepted password.
const maxInput = 64 * 1024

// Terminal reads from Input and writes prompt text to Output (stdin and stderr by default).
// Reader overrides plain line input for tests; hidden input always uses the terminal fd.
// Callers own input cancellation: an arbitrary Reader cannot be interrupted by context.
type Terminal struct {
	Input        *os.File
	Output       io.Writer
	Reader       io.Reader
	isTerminal   func(int) bool
	readPassword func(int) ([]byte, error)
}

// sources resolves terminal dependencies without reading or writing any data.
func (t Terminal) sources() (*os.File, io.Writer, io.Reader, func(int) bool, func(int) ([]byte, error)) {
	input, output, reader := t.Input, t.Output, t.Reader
	isTerminal, readPassword := t.isTerminal, t.readPassword
	if input == nil {
		input = os.Stdin
	}
	if output == nil {
		output = os.Stderr
	}
	if reader == nil {
		reader = input
	}
	if isTerminal == nil {
		isTerminal = term.IsTerminal
	}
	return input, output, reader, isTerminal, readPassword
}

// Password reads hidden terminal input, or one unbuffered line only when stdinLine is true.
// A non-TTY without explicit opt-in returns ErrUnavailable before consuming any bytes.
// Reader and output errors propagate without including the password.
func (t Terminal) Password(ctx context.Context, label string, stdinLine bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	input, output, reader, isTerminal, readPassword := t.sources()
	fd := int(input.Fd())
	tty := isTerminal(fd)
	if !stdinLine && !tty {
		return "", ErrUnavailable
	}
	if _, err := fmt.Fprint(output, label); err != nil {
		return "", err
	}
	if !tty {
		password, err := readLine(reader)
		if err != nil {
			return "", err
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return password, nil
	}
	var password []byte
	var err error
	if readPassword != nil {
		password, err = readPassword(fd)
	} else {
		password, err = hiddenPassword(ctx, fd)
	}
	defer clear(password)
	_, newlineErr := fmt.Fprintln(output)
	if err != nil {
		if errors.Is(err, ErrCancelled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		return "", ErrFailed
	}
	if newlineErr != nil {
		return "", newlineErr
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(password) > maxInput {
		return "", ErrFailed
	}
	return string(password), nil
}

// Confirm reads a single yes/no response, defaulting an empty response to No.
// Other responses and input failures return errors rather than approving an action.
func (t Terminal) Confirm(ctx context.Context, message string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, output, reader, _, _ := t.sources()
	if _, err := fmt.Fprint(output, message+" [y/N] "); err != nil {
		return false, err
	}
	line, err := readLine(reader)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return parseConfirmation(line)
}

// parseConfirmation accepts case-insensitive yes/no words and a safe empty default.
// Anything else is invalid and cannot silently become consent.
func parseConfirmation(line string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	case "", "n", "no":
		return false, nil
	default:
		return false, errors.New("answer must be yes or no")
	}
}

// readLine reads exactly one bounded line without buffering bytes from the next response.
// EOF after content completes a line; an empty EOF and oversized input return errors.
func readLine(r io.Reader) (string, error) {
	var data []byte
	var one [1]byte
	for len(data) <= maxInput {
		n, err := r.Read(one[:])
		if n > 0 {
			if one[0] == '\n' {
				return strings.TrimSuffix(string(data), "\r"), nil
			}
			data = append(data, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(data) > 0 && len(data) <= maxInput {
				return string(data), nil
			}
			return "", err
		}
		if n == 0 {
			return "", io.ErrNoProgress
		}
	}
	return "", errors.New("prompt response exceeds size limit")
}
