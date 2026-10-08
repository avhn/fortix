// Package pinentry bridges the bounded Assuan responder to a private helper socket.
// It never logs credentials, tokens, or prompt payloads and has no keychain access.
package pinentry

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/avhn/fortix/internal/openfortivpn"
	"github.com/avhn/fortix/internal/protocol"
)

// Config contains only helper-provided relay coordinates from the child environment.
// Token authenticates a single live attempt and is not an account credential.
type Config struct{ Socket, Token string }

// Request is the private socket envelope sent for each recognized GETPIN command.
// Kind is derived again from KeyInfo by the helper, never trusted as caller input.
type Request struct {
	Token   string `json:"token"`
	KeyInfo string `json:"keyinfo"`
	Prompt  string `json:"prompt"`
}

// Response carries one credential or a cancellation. A cancelled response omits
// Secret; callers must not persist or log either the encoded message or the value.
// The Assuan responder uses strings, whose backing bytes cannot be reliably erased;
// clearing framing buffers and dropping references only reduces their retention.
type Response struct {
	Secret string `json:"secret,omitempty"`
	Cancel bool   `json:"cancel,omitempty"`
}

// Run serves stdin/stdout using one private relay connection per prompt. Invalid
// configuration and transport failures cancel rather than reflecting sensitive data.
func Run(ctx context.Context, config Config, r io.Reader, w io.Writer) error {
	if !filepath.IsAbs(config.Socket) || filepath.Clean(config.Socket) != config.Socket || len(config.Token) != 64 {
		return errors.New("invalid pinentry configuration")
	}
	if _, err := hex.DecodeString(config.Token); err != nil {
		return errors.New("invalid pinentry token")
	}
	return openfortivpn.Serve(ctx, r, w, func(ctx context.Context, request openfortivpn.Request) (string, error) {
		// The helper owns the human deadline; only establishing the socket is timed here.
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", config.Socket)
		if err != nil {
			return "", errors.New("credential relay unavailable")
		}
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		if err := protocol.Write(conn, Request{Token: config.Token, KeyInfo: request.KeyInfo, Prompt: request.Prompt}); err != nil {
			return "", errors.New("credential relay unavailable")
		}
		var reply Response
		if err := protocol.NewReader(conn).Read(&reply); err != nil || reply.Cancel {
			return "", errors.New("credential request cancelled")
		}
		return reply.Secret, nil
	})
}
