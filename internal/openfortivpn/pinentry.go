package openfortivpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Kind identifies a credential purpose inferred from the SETKEYINFO suffix.
// It is only a hint; the relay must independently authenticate and bind the attempt.
type Kind string

// Pinentry constants define credential kinds, outgoing data and incoming command bounds
// including LF, and a fixed cancellation reply that never contains errors or secrets.
const (
	Password Kind = "password"
	Code     Kind = "code"

	MaxAssuanLine    = 1000
	maxAssuanCommand = 4096
	cancelReply      = "ERR 83886179 Operation cancelled\n"
)

// Request contains decoded, bounded prompt metadata, never a credential response.
// Kind is Password for _password and Code for _otp or _2fa; unknown suffixes are refused.
type Request struct {
	Kind    Kind
	KeyInfo string
	Prompt  string
}

// Serve answers Assuan commands from r on w, asking only for recognized GETPIN requests.
// ask receives ctx and decoded metadata and must honor cancellation; returned secrets
// are percent-escaped directly onto w and never included in errors. Callback errors
// produce the fixed cancellation reply. Malformed or oversized lines and I/O failures
// return errors. EOF ends the exchange normally, while BYE is acknowledged before exit.
// On cancellation a ReadCloser r is closed to unblock input; a plain Reader must have
// bounded reads. The caller owns cancellation of any blocking writes to w.
func Serve(ctx context.Context, r io.Reader, w io.Writer, ask func(context.Context, Request) (string, error)) error {
	if ctx == nil || r == nil || w == nil || ask == nil {
		return errors.New("pinentry: context, reader, writer, and callback are required")
	}
	stop := context.AfterFunc(ctx, func() {
		if closer, ok := r.(io.ReadCloser); ok {
			// Closing an owned input pipe makes a cancelled exchange terminate promptly.
			_ = closer.Close()
		}
	})
	defer stop()
	if err := writeAssuan(w, "OK fortix pinentry\n"); err != nil {
		return err
	}
	scanner := bufio.NewScanner(r)
	// Escaped usernames, realms, and gateway hints can exceed the data-record bound.
	scanner.Buffer(make([]byte, maxAssuanCommand), maxAssuanCommand+1)
	request := Request{}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, writeAssuan(w, cancelReply))
		}
		line := scanner.Text()
		if len(line)+1 > maxAssuanCommand || strings.ContainsRune(line, '\x00') {
			return errors.Join(errors.New("pinentry: invalid or oversized command"), writeAssuan(w, cancelReply))
		}
		command, argument, _ := strings.Cut(line, " ")
		switch command {
		case "BYE":
			return writeAssuan(w, "OK\n")
		case "SETKEYINFO", "SETPROMPT":
			decoded, err := percentDecode(argument)
			if err != nil {
				return errors.Join(err, writeAssuan(w, cancelReply))
			}
			if command == "SETKEYINFO" {
				request.KeyInfo = decoded
				request.Kind = keyKind(decoded)
			}
			if command == "SETPROMPT" {
				request.Prompt = decoded
			}
			if err := writeAssuan(w, "OK\n"); err != nil {
				return err
			}
		case "GETPIN":
			if err := answerPIN(ctx, w, ask, request); err != nil {
				return err
			}
		default:
			// OPTION, SETTITLE, SETDESC, and unknown commands have no metadata to decode.
			if err := writeAssuan(w, "OK\n"); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, writeAssuan(w, cancelReply))
	}
	if err := scanner.Err(); err != nil {
		// Scanner errors contain no input text, preserving credential confidentiality.
		return errors.Join(fmt.Errorf("read pinentry command: %w", err), writeAssuan(w, cancelReply))
	}
	return nil
}

// answerPIN asks for one recognized request and writes a bounded, escaped data reply.
// Unknown kinds and callback errors cancel the request. Context or write errors end
// the exchange; oversized secrets cancel and return a generic, secret-free error.
func answerPIN(ctx context.Context, w io.Writer, ask func(context.Context, Request) (string, error), request Request) error {
	if request.Kind == "" {
		return writeAssuan(w, cancelReply)
	}
	secret, err := ask(ctx, request)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, writeAssuan(w, cancelReply))
	}
	if err != nil {
		return writeAssuan(w, cancelReply)
	}
	// Bound before escaping as well, avoiding an allocation for an unbounded response.
	if len(secret) > MaxAssuanLine-3 {
		return errors.Join(errors.New("pinentry: credential response exceeds line limit"), writeAssuan(w, cancelReply))
	}
	encoded := percentEscape(secret)
	if len(encoded)+3 > MaxAssuanLine {
		return errors.Join(errors.New("pinentry: credential response exceeds line limit"), writeAssuan(w, cancelReply))
	}
	// The child may close its pipe after its first read, so deliver both records together.
	return writeAssuan(w, "D "+encoded+"\nOK\n")
}

// keyKind returns the credential kind for a recognized keyinfo suffix.
// Unknown or empty hints return the empty kind and are not sent to the callback.
func keyKind(keyInfo string) Kind {
	switch {
	case strings.HasSuffix(keyInfo, "_password"):
		return Password
	case strings.HasSuffix(keyInfo, "_otp"), strings.HasSuffix(keyInfo, "_2fa"):
		return Code
	default:
		return ""
	}
}

// writeAssuan writes one complete reply, returning short-write or underlying I/O errors.
// It never wraps the reply text into an error, since data replies contain credentials.
func writeAssuan(w io.Writer, reply string) error {
	n, err := io.WriteString(w, reply)
	if err != nil {
		return fmt.Errorf("write pinentry reply: %w", err)
	}
	if n != len(reply) {
		return io.ErrShortWrite
	}
	return nil
}

// percentEscape encodes percent, CR, LF, and NUL bytes for an Assuan data record.
// Other bytes, including plus and UTF-8, remain literal; it cannot fail.
func percentEscape(value string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", "\x00", "%00").Replace(value)
}

// percentDecode decodes Assuan's percent-hex bytes without treating plus as a space.
// Invalid or incomplete escapes return a generic error with no input text.
func percentDecode(value string) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			decoded.WriteByte(value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", errors.New("pinentry: malformed percent escape")
		}
		high, low := hexDigit(value[i+1]), hexDigit(value[i+2])
		if high < 0 || low < 0 {
			return "", errors.New("pinentry: malformed percent escape")
		}
		decoded.WriteByte(byte(high<<4 | low))
		i += 2
	}
	return decoded.String(), nil
}

// hexDigit returns a hex character's numeric value, or -1 for non-hex input.
// It accepts either ASCII letter case and has no side effects.
func hexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}
