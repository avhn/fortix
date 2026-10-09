package helper

import (
	"github.com/avhn/fortix/internal/openfortivpn"
	"github.com/avhn/fortix/internal/pinentry"
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
