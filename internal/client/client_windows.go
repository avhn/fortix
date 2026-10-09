// Package client provides a cancellable, correlated connection to the local VPN helper.
// Requests and events use bounded protocol framing; credential payloads are never logged.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/avhn/fortix/internal/buildinfo"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/protocol"
)

// Options selects an explicit socket or platform paths and an optional transport for tests.
// A nonempty Socket overrides the environment; Dial must honor context cancellation; server identity is always checked before hello.
type Options struct {
	Socket        string
	Paths         paths.Override
	Dial          func(context.Context, string, string) (net.Conn, error)
	SubscribeLogs bool // Request live diagnostics only when explicitly enabled.
	DiscardLogs   bool // Suppress diagnostic log events when the consumer only needs connection progress.
}

// Client owns one socket, one reader, bounded events, and outstanding request channels.
// Callers must drain Events while subscribing; overflow closes the connection rather than losing challenges.
type Client struct {
	conn          net.Conn
	writes        chan struct{}
	mu            sync.Mutex
	pending       map[string]chan reply
	next          uint64
	err           error
	done          chan struct{}
	events        chan protocol.Event
	stopped       chan struct{}
	discardLogs   bool
	subscribeLogs bool
}

// reply contains either a helper result or a terminal transport failure.
type reply struct {
	result frame
	err    error
}

// frame decodes the shared result and event envelope without changing wire fields.
// Data remains raw JSON so operation callers can select a concrete response type.
type frame struct {
	Type           string          `json:"type"`
	Code           protocol.Code   `json:"code,omitempty"`
	Wanted         bool            `json:"wanted,omitempty"`
	Initiated      bool            `json:"initiated,omitempty"`
	CleanupPending bool            `json:"cleanup_pending,omitempty"`
	ID             string          `json:"id,omitempty"`
	OK             bool            `json:"ok,omitempty"`
	Error          *protocol.Error `json:"error,omitempty"`
	Data           json.RawMessage `json:"data,omitempty"`
	Profile        string          `json:"profile,omitempty"`
	Attempt        uint64          `json:"attempt,omitempty"`
	State          string          `json:"state,omitempty"`
	Detail         string          `json:"detail,omitempty"`
	ChallengeID    string          `json:"challenge_id,omitempty"`
	Kind           string          `json:"kind,omitempty"`
	Prompt         string          `json:"prompt,omitempty"`
	Digest         string          `json:"digest,omitempty"`
	Subject        string          `json:"subject,omitempty"`
	Issuer         string          `json:"issuer,omitempty"`
	Line           string          `json:"line,omitempty"`
}

// OperationError identifies a helper rejection without retaining any request payload.
type OperationError struct {
	Code    protocol.Code
	Message string
}

// Error returns the helper's public diagnostic, adding group repair instructions for authorization failures.
func (e *OperationError) Error() string {
	if e.Code == protocol.Unauthorized {
		return permissionMessage()
	}
	return fmt.Sprintf("helper: %s: %s", e.Code, e.Message)
}

// permissionMessage describes how an administrator can restore socket group access.
func permissionMessage() string {
	return "permission denied: ask an administrator to add your account to the local fortix group (net localgroup fortix <user> /add), then sign out and back in"
}

// socketPath accepts only the installed local pipe, never a remote or user-selected endpoint.
// The fixed pipe is resolved independently of filesystem overrides and cannot be redirected.
func socketPath(o Options) (string, error) {
	socket := o.Socket
	if socket == "" {
		socket = os.Getenv("FORTIX_SOCKET")
	}
	if socket == "" {
		socket = o.Paths.ControlSocket
	}
	o.Paths.ControlSocket = ""
	p, err := paths.Resolve(o.Paths)
	if err != nil {
		return "", err
	}
	if socket != "" && socket != p.ControlSocket {
		return "", errors.New("Windows control endpoint must be the local Fortix pipe")
	}
	return p.ControlSocket, nil
}

// Dial verifies the installed service before sending even the secret-free hello.
// The returned client survives the dial context; Close ends its reader and outstanding calls.
func Dial(ctx context.Context, o Options) (*Client, error) {
	return dialVerified(ctx, o, verifyPipeServer)
}

// dialVerified makes identity checks injectable without allowing production dialers to bypass them.
// No reader or writer starts until verification succeeds, including with an injected transport.
func dialVerified(ctx context.Context, o Options, verify func(context.Context, net.Conn) error) (*Client, error) {
	socket, err := socketPath(o)
	if err != nil {
		return nil, err
	}
	dial := o.Dial
	if dial == nil {
		dial = dialPipe
	}
	handshake, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dial(handshake, "pipe", socket)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("%s: %w", permissionMessage(), os.ErrPermission)
		}
		if handshake.Err() != nil {
			return nil, handshake.Err()
		}
		return nil, errors.New("fortix helper service is not installed or running; run fortix-helper install from an elevated terminal")
	}
	if err := verify(handshake, conn); err != nil {
		_ = conn.Close()
		return nil, errors.New("the Fortix helper service could not be verified")
	}
	if err := handshake.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	c := &Client{conn: conn, writes: make(chan struct{}, 1), pending: make(map[string]chan reply), done: make(chan struct{}), events: make(chan protocol.Event, 256), stopped: make(chan struct{}), discardLogs: o.DiscardLogs, subscribeLogs: o.SubscribeLogs}
	c.writes <- struct{}{}
	go c.read()
	var hello struct {
		HelperVersion string `json:"helper_version"`
		Protocol      int    `json:"protocol"`
	}
	err = c.Call(handshake, protocol.Request{Op: "hello", Version: buildinfo.Version}, &hello)
	if err == nil && hello.Protocol != protocol.Version {
		err = errors.New("helper protocol version is incompatible; update fortix and fortix-helper together")
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// Events returns ordered helper notifications until the connection closes.
// Consumers must inspect Err after the channel closes to distinguish clean close from failure.
func (c *Client) Events() <-chan protocol.Event { return c.events }

// Err returns the terminal connection error, or nil while the connection remains open.
func (c *Client) Err() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

// Close shuts down the socket, wakes outstanding calls, and joins the reader.
// Repeated closes are safe and return nil; pending calls receive net.ErrClosed.
func (c *Client) Close() error { c.fail(net.ErrClosed); <-c.stopped; return nil }

// fail records the first error and closes the socket exactly once, waking every pending call.
func (c *Client) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	c.err = err
	close(c.done)
	_ = c.conn.Close()
	for id, ch := range c.pending {
		ch <- reply{err: err}
		delete(c.pending, id)
	}
}

// Call assigns a unique ID, sends r, and decodes the matching result into dst when non-nil.
// Context cancellation interrupts writes and waits; helper and decode errors never include request secrets.
func (c *Client) Call(ctx context.Context, r protocol.Request, dst any) error {
	if r.Op == "subscribe" {
		r.Logs = (r.Logs || c.subscribeLogs) && !c.discardLogs
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.next++
	r.ID = strconv.FormatUint(c.next, 10)
	ch := make(chan reply, 1)
	c.pending[r.ID] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, r.ID); c.mu.Unlock() }()
	if err := r.Validate(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.Err()
	case <-c.writes:
	}
	// Cancellation moves the deadline instead of spawning a goroutine that could retain a secret.
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	deadline, _ := writeCtx.Deadline()
	err := c.conn.SetWriteDeadline(deadline)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(writeCtx, func() { _ = c.conn.SetWriteDeadline(time.Now()); close(interrupted) })
	if err == nil {
		err = protocol.Write(c.conn, r)
	}
	if !stop() {
		<-interrupted
	}
	cancel()
	if err == nil {
		// The request is already sent, so a peer that replies and closes before the reset
		// must not turn a delivered reply into a write failure. Every write sets its own
		// deadline first, so a failed reset leaves nothing stale behind.
		_ = c.conn.SetWriteDeadline(time.Time{})
	}
	c.writes <- struct{}{}
	if err != nil {
		// A peer may reject authorization before reading hello, then close its socket.
		// Let the sole reader finish any buffered rejection before recording a write failure.
		_ = c.conn.SetReadDeadline(time.Now().Add(time.Second))
		select {
		case <-c.done:
		case <-ctx.Done():
			c.fail(ctx.Err())
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var operation *OperationError
		if errors.As(c.Err(), &operation) {
			return operation
		}
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case response := <-ch:
		if response.err != nil {
			return response.err
		}
		if !response.result.OK {
			return &OperationError{Code: response.result.Error.Code, Message: response.result.Error.Message}
		}
		if dst != nil {
			if err := json.Unmarshal(response.result.Data, dst); err != nil {
				return errors.New("helper returned invalid result data")
			}
		}
		return nil
	}
}

// read dispatches bounded records to pending calls or the event queue until a terminal error.
// Unknown result IDs are ignored because cancelled requests may still receive a late result.
func (c *Client) read() {
	defer close(c.stopped)
	defer close(c.events)
	reader := protocol.NewReader(c.conn)
	for {
		var f frame
		if err := reader.Read(&f); err != nil {
			c.fail(err)
			return
		}
		if f.Type == "result" {
			// Peer authorization can reject the connection before reading any request ID.
			if !f.OK && f.Error != nil && f.Error.Code == protocol.Unauthorized {
				c.fail(&OperationError{Code: f.Error.Code, Message: f.Error.Message})
				return
			}
			if f.ID == "" || (f.OK && f.Error != nil) || (!f.OK && f.Error == nil) {
				c.fail(errors.New("helper returned invalid result"))
				return
			}
			c.mu.Lock()
			if ch := c.pending[f.ID]; ch != nil {
				ch <- reply{result: f}
				delete(c.pending, f.ID)
			}
			c.mu.Unlock()
			continue
		}
		switch f.Type {
		case "state", "challenge", "cert", "log":
		default:
			c.fail(errors.New("helper returned unknown message type"))
			return
		}
		// Logs are optional diagnostics, not credential or state notifications.
		if f.Type == "log" && c.discardLogs {
			continue
		}
		event := protocol.Event{Code: f.Code, Wanted: f.Wanted, Initiated: f.Initiated, CleanupPending: f.CleanupPending, Type: f.Type, Profile: f.Profile, Attempt: f.Attempt, State: f.State, Detail: f.Detail, ChallengeID: f.ChallengeID, Kind: f.Kind, Prompt: f.Prompt, Digest: f.Digest, Subject: f.Subject, Issuer: f.Issuer, Line: f.Line}
		select {
		case c.events <- event:
		case <-c.done:
			return
		default:
			c.fail(errors.New("helper event queue overflow; reconnect and retry"))
			return
		}
	}
}
