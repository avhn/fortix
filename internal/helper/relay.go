package helper

import (
	"net"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/avhn/fortix/internal/openfortivpn"
	"github.com/avhn/fortix/internal/pinentry"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// pinReply is the shared private relay response, deliberately separate from events.
type pinReply = pinentry.Response

// pendingPIN binds one credential waiter to a random public challenge identifier.
// Its one-slot response channel is owned by the supervisor and consumed by the relay.
type pendingPIN struct {
	id      string
	request openfortivpn.Request
	reply   chan pinReply
}

// relay authorizes the socket peer and live capability before accepting a prompt.
// Tokens from prior attempts fail without creating an event. Relay errors use only
// cancellation replies and never print token, keyinfo, prompt, or secret contents.
func (s *Server) relay(conn *net.UnixConn) {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	reject := func() { _ = protocol.Write(conn, pinReply{Cancel: true}) }
	peer, err := peerCredentials(conn)
	if err != nil || peer.UID != uint32(os.Geteuid()) {
		reject()
		return
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	var request pinentry.Request
	if err := protocol.NewReader(conn).Read(&request); err != nil {
		reject()
		return
	}
	if len(request.Token) != 64 || len(request.KeyInfo) > 4096 || len(request.Prompt) > 4096 || strings.ContainsFunc(request.Prompt, unicode.IsControl) {
		reject()
		return
	}
	s.mu.Lock()
	binding, ok := s.tokens[request.Token]
	s.mu.Unlock()
	request.Token = ""
	if !ok {
		reject()
		return
	}
	kind := openfortivpn.Kind("")
	switch {
	case strings.HasSuffix(request.KeyInfo, "_password"):
		kind = openfortivpn.Password
	case strings.HasSuffix(request.KeyInfo, "_otp"), strings.HasSuffix(request.KeyInfo, "_2fa"):
		kind = openfortivpn.Code
	default:
		reject()
		return
	}
	human := s.opts.Deadlines.Human
	if human <= 0 {
		human = session.DefaultDeadlines().Human
	}
	if err := conn.SetDeadline(time.Now().Add(human + 5*time.Second)); err != nil {
		return
	}
	pending := &pendingPIN{request: openfortivpn.Request{Kind: kind, KeyInfo: request.KeyInfo, Prompt: request.Prompt}, reply: make(chan pinReply, 1)}
	reply := binding.actor.call(controlInput{op: "ask", attempt: binding.attempt, ask: pending})
	if reply.code != "" {
		reject()
		return
	}
	// The supervisor owns the human deadline and reports expiry as a timeout.
	select {
	case answer := <-pending.reply:
		_ = protocol.Write(conn, answer)
		answer.Secret = ""
	case <-s.ctx.Done():
		reject()
	case <-binding.actor.done:
		reject()
	}
}
