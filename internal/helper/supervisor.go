package helper

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync"
	"time"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/openfortivpn"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// Network is the ownership boundary for per-attempt route and DNS transactions.
// Implementations must honor deadlines and persist owned entries in Journal before
// applying changes through Apply's persist callback. The supplied journal is worker-
// owned; the callback rejects changed attempt/process identities. Teardown re-reads
// persisted ownership after Apply finishes. Recover removes only proved owned entries.
type Network interface {
	Apply(context.Context, *profile.Profile, session.Effect, *Journal, func(Journal) error) error
	Teardown(context.Context, Journal) error
	Recover(context.Context, Journal) error
}

// NetworkConflicts reserves profile routing before spawn and negotiated addresses
// before PPP discovery. Optional implementations must serialize checks across profiles.
type NetworkConflicts interface {
	CheckUp(context.Context, *profile.Profile) error
	CheckAddresses(string, netip.Addr) error
}

// NetworkReservations releases unused pre-spawn policy when a reducer cannot start.
// Implementations must leave reservations with live or uncleaned links untouched.
// Release performs no command I/O and must not wait for network transactions.
type NetworkReservations interface {
	Release(string)
}

// NoNetwork leaves host networking unchanged while preserving lifecycle hooks.
// Tests must explicitly select it when no owned-entry adapter is being exercised.
type NoNetwork struct{}

// Apply performs no networking and reports success without consulting the host.
func (NoNetwork) Apply(context.Context, *profile.Profile, session.Effect, *Journal, func(Journal) error) error {
	return nil
}

// Teardown performs no networking and reports success without consulting the host.
func (NoNetwork) Teardown(context.Context, Journal) error { return nil }

// Recover performs no networking and reports success without consulting the host.
func (NoNetwork) Recover(context.Context, Journal) error { return nil }

// controlInput is a serialized client command or private credential request.
// Secret byte slices transfer ownership to the supervisor and are cleared after use.
type controlInput struct {
	op                  string
	origin              *connection
	profile             *profile.Profile
	challengeID, digest string
	secret              []byte
	ask                 *pendingPIN
	attempt             uint64
	reply               chan controlReply
	link                backend.LinkIdentity
	ctx                 context.Context
}

// controlReply acknowledges a client action with public state or a stable failure.
type controlReply struct {
	status Status
	code   protocol.Code
	detail string
	err    error
}

// supervisor owns one reducer, timer, pending challenge, and child process at a time.
// Only its run goroutine mutates lifecycle fields; snapshotMu protects public views.
type supervisor struct {
	id            string
	server        *Server
	profile       *profile.Profile
	state         session.State
	snapshotMu    sync.Mutex
	public        Status
	publicOrigin  *connection
	idleState     bool
	controls      chan controlInput
	events        chan session.Event
	done, stopped chan struct{}
	children      sync.WaitGroup
	timer         *time.Timer
	command       *exec.Cmd
	journal       Journal
	token         string
	pending       *pendingPIN
	origin        *connection
	ownerUID      uint32
	log           *rotatingLog
	networkCancel context.CancelFunc
	networkDone   <-chan struct{}
	tunnel        backend.Tunnel
}

// newSupervisor initializes an idle actor without starting goroutines or children.
func newSupervisor(s *Server, p *profile.Profile) *supervisor {
	a := &supervisor{id: p.ID, server: s, profile: p, state: session.New(p.ID, session.Options{Backend: p.Backend, MFAMode: p.MFA.Mode, Deadlines: s.opts.Deadlines}), controls: make(chan controlInput), events: make(chan session.Event, 128), done: make(chan struct{}), stopped: make(chan struct{})}
	a.publish()
	return a
}

// snapshot returns a copy of non-secret state without blocking on child I/O.
func (a *supervisor) snapshot() Status {
	a.snapshotMu.Lock()
	defer a.snapshotMu.Unlock()
	return a.public
}

// idle reports whether editing/deletion can proceed without a live child or incomplete cleanup.
func (a *supervisor) idle() bool {
	a.snapshotMu.Lock()
	defer a.snapshotMu.Unlock()
	return a.idleState
}

// publish updates the public view after a reducer transition, preserving Since
// while the phase remains unchanged and omitting invalid local addresses.
func (a *supervisor) publish() {
	a.snapshotMu.Lock()
	defer a.snapshotMu.Unlock()
	since := a.public.Since
	if a.public.State != a.state.Phase {
		since = time.Now().UTC()
	}
	ip := ""
	if a.state.LocalIP.IsValid() {
		ip = a.state.LocalIP.String()
	}
	a.publicOrigin = a.origin
	a.public = Status{Wanted: a.state.Wanted, CleanupPending: a.state.Phase == session.Failed && !a.state.Cleaned, Profile: a.state.Profile, State: a.state.Phase, Detail: a.state.Detail, Attempt: a.state.Attempt, Interface: a.state.Interface, LocalIP: ip, Since: since}
	a.idleState = a.state.Phase == session.Disconnected || (a.state.Phase == session.Failed && a.state.Exited && a.state.Cleaned)
}

// call sends one command and waits for acknowledgement or shutdown. Credential
// buffers are cleared if ownership could not be transferred to the actor.
func (a *supervisor) call(input controlInput) controlReply {
	input.reply = make(chan controlReply, 1)
	select {
	case a.controls <- input:
	case <-a.done:
		clear(input.secret)
		return controlReply{code: protocol.Busy}
	}
	select {
	case reply := <-input.reply:
		return reply
	case <-a.done:
		return controlReply{code: protocol.Busy}
	}
}

// send queues attempt-bound observations with bounded backpressure, dropping only
// after actor termination. Shutdown still accepts child-exit and cleanup events.
func (a *supervisor) send(e session.Event) {
	select {
	case a.events <- e:
	case <-a.stopped:
	}
}

// run serializes reducer inputs and executes their effects. Cancellation requests a
// normal stop, including grace escalation and cleanup, before releasing the actor.
func (a *supervisor) run() {
	defer close(a.done)
	defer func() {
		if a.timer != nil {
			a.timer.Stop()
		}
		a.revoke()
		a.cancelPIN()
		close(a.stopped)
		a.children.Wait()
		if a.log != nil {
			_ = a.log.Close()
		}
	}()
	stopping := false
	cancelled := a.server.ctx.Done()
	for {
		if stopping && (a.idle() || (a.state.Exited && a.state.Phase == session.Failed)) {
			return
		}
		select {
		case <-cancelled:
			stopping = true
			cancelled = nil
			a.reduce(a.event(session.Down))
		case input := <-a.controls:
			if stopping {
				clear(input.secret)
				input.reply <- controlReply{code: protocol.Busy}
				continue
			}
			if a.control(input) {
				return
			}
		case event := <-a.events:
			a.reduce(event)
		}
	}
}

// event creates a generation-bound reducer input with fresh retry jitter and no
// credential material. Timing remains entirely in the supervisor and reducer.
func (a *supervisor) event(kind session.EventKind) session.Event {
	return session.Event{Profile: a.state.Profile, Attempt: a.state.Attempt, Kind: kind, Jitter: rand.Float64()}
}

// control handles client actions and relay prompts, replying before slow spawn work
// on Up. It rejects stale prompts and first-answer races inside the actor itself.
func (a *supervisor) control(input controlInput) bool {
	reply := controlReply{}
	defer clear(input.secret)
	if input.op == "answer" || input.op == "cancel" || input.op == "trust" {
		if input.origin == nil || (input.origin.uid != a.ownerUID && input.origin.uid != 0) {
			input.reply <- controlReply{code: protocol.Unauthorized}
			return false
		}
	}
	switch input.op {
	case "up":
		if a.state.Wanted && a.state.Phase != session.Backoff && a.state.Phase != session.Failed && a.state.Phase != session.Stopping {
			input.reply <- controlReply{status: a.snapshot()}
			return false
		}
		queued := a.state.Phase == session.Stopping && a.state.Target == session.Disconnected && a.state.CleanupRetries == 0
		if !a.idle() && a.state.Phase != session.Backoff && !queued {
			input.reply <- controlReply{code: protocol.Busy}
			return false
		}
		if !queued {
			if err := a.checkNetworkUp(); err != nil {
				e := a.networkFailure(err)
				e.Kind = session.UpRefused
				a.reduce(e)
				code := protocol.Internal
				if e.Failure == session.ConflictFailure {
					code = protocol.Conflict
				}
				input.reply <- controlReply{status: a.snapshot(), code: code, detail: e.Detail}
				return false
			}
		}
		a.origin = input.origin
		a.ownerUID = input.origin.uid
		next, effects := session.Next(a.state, a.event(session.Up))
		if !queued && !slices.ContainsFunc(effects, func(e session.Effect) bool { return e.Kind == session.StartProcess }) {
			a.releaseNetworkReservation()
		}
		a.state = next
		a.publish()
		input.reply <- controlReply{status: a.snapshot()}
		a.effects(effects)
		return false
	case "down":
		if a.state.Phase == session.Failed && a.state.Exited && !a.state.Cleaned {
			a.reduce(a.event(session.Reset))
		} else {
			a.reduce(a.event(session.Down))
		}
	case "replace":
		a.releaseNetworkReservation()
		a.profile = input.profile
		attempt := a.state.Attempt
		a.state = session.New(input.profile.ID, session.Options{Backend: input.profile.Backend, MFAMode: input.profile.MFA.Mode, Deadlines: a.server.opts.Deadlines})
		a.state.Attempt = attempt
		a.publish()
	case "retire":
		a.releaseNetworkReservation()
		input.reply <- reply
		return true
	case "trust":
		if a.state.Phase != session.WaitingTrust || input.digest != a.state.Certificate.Digest || input.digest == "" {
			reply.code = protocol.Conflict
			break
		}
		// Persist before telling the reducer to begin another generation.
		p := *a.profile
		p.TrustedCert = input.digest
		data, err := json.Marshal(p)
		if err == nil {
			_, err = a.server.store.Put(data)
		}
		if err != nil {
			reply.code = protocol.Internal
			break
		}
		a.profile = &p
		e := a.event(session.Trust)
		e.Digest = input.digest
		a.reduce(e)
	case "register_link":
		reply.err = a.registerLink(input)
	case "ask":
		if input.attempt != a.state.Attempt || a.pending != nil || (a.state.Phase != session.Starting && a.state.Phase != session.Authenticating) {
			input.ask.reply <- pinReply{Cancel: true}
			reply.code = protocol.Conflict
			break
		}
		id, err := randomToken()
		if err != nil {
			input.ask.reply <- pinReply{Cancel: true}
			reply.code = protocol.Internal
			break
		}
		input.ask.id = id
		a.pending = input.ask
		a.server.mu.Lock()
		a.server.challenges[id] = &challengeRoute{actor: a, uid: a.ownerUID}
		a.server.mu.Unlock()
		e := a.event(session.Challenge)
		e.Request = input.ask.request
		a.reduce(e)
	case "answer", "cancel":
		if a.pending == nil || a.pending.id != input.challengeID || (a.state.Phase != session.WaitingPassword && a.state.Phase != session.WaitingCode) {
			reply.code = protocol.NotFound
			break
		}
		pending := a.pending
		a.server.mu.Lock()
		delete(a.server.challenges, pending.id)
		a.server.mu.Unlock()
		a.pending = nil
		if input.op == "cancel" {
			pending.reply <- pinReply{Cancel: true}
			a.reduce(a.event(session.ChallengeCancelled))
		} else {
			if a.log != nil {
				a.log.protect(input.secret)
			}
			pending.reply <- pinReply{Secret: string(input.secret)}
			a.reduce(a.event(session.CredentialsAnswered))
		}
	}
	reply.status = a.snapshot()
	input.reply <- reply
	return false
}

// reduce feeds an observation through the pure reducer, publishes the resulting
// snapshot, then executes its ordered effects on the same supervisor goroutine.
func (a *supervisor) reduce(event session.Event) {
	if event.Profile == a.state.Profile && event.Attempt == a.state.Attempt && event.Kind == session.Output && a.state.Phase == session.Negotiating {
		if addresses, ok := event.Observation.(openfortivpn.GotAddresses); ok {
			if checks, ok := a.server.opts.Network.(NetworkConflicts); ok {
				if err := checks.CheckAddresses(a.id, addresses.LocalIP); err != nil {
					event = a.networkFailure(err)
				}
			}
		}
	}
	if event.Kind == session.NetworkApplied && event.Profile == a.id && event.Attempt == a.state.Attempt && a.state.Phase == session.Configuring {
		if active, ok := a.tunnel.(interface{ Activate(context.Context) error }); ok {
			ctx, cancel := context.WithTimeout(context.Background(), a.state.Deadlines.Network)
			err := active.Activate(ctx)
			cancel()
			if err != nil {
				event = a.networkFailure(err)
			}
		}
	}
	next, effects := session.Next(a.state, event)
	a.state = next
	a.publish()
	a.effects(effects)
}

// effects executes lifecycle instructions in order. Asynchronous work captures the
// originating generation and reports completion back through the bounded event queue.
func (a *supervisor) effects(effects []session.Effect) {
	for _, e := range effects {
		switch e.Kind {
		case session.StartTimer:
			event := session.Event{Profile: e.Profile, Attempt: e.Attempt, Kind: session.Deadline, TimerID: e.TimerID, Jitter: rand.Float64()}
			a.timer = time.AfterFunc(e.Duration, func() { a.send(event) })
		case session.CancelTimer:
			if a.timer != nil {
				a.timer.Stop()
				a.timer = nil
			}
		case session.StartProcess:
			if err := a.start(); err != nil {
				a.revoke()
				var conflict *network.ConflictError
				if errors.As(err, &conflict) {
					a.reduce(a.networkFailure(err))
				} else {
					message := "openfortivpn start failed"
					if a.profile.Backend == "native" {
						message = "native backend start failed"
					}
					a.server.opts.Logger.Error(message, "profile", a.id, "backend", a.profile.Backend, "error", err)
					detail := "openfortivpn not found or not trusted; see helper log"
					if a.profile.Backend == "native" {
						detail = "native backend could not start; see helper log"
					}
					if a.log != nil {
						if logErr := a.log.write(detail + ": " + a.log.redact(err.Error())); logErr != nil {
							a.server.opts.Logger.Error("profile start log failed", "profile", a.id, "error", logErr)
						}
					}
					event := a.event(session.AttemptFailed)
					event.Failure, event.Detail = session.ProcessFailure, detail
					a.reduce(event)
				}
				a.reduce(a.event(session.ProcessExited))
				return
			}
		case session.StopProcess:
			a.revoke()
			if a.networkCancel != nil {
				a.networkCancel()
			}
			a.stopTunnel(false)
		case session.KillProcess:
			a.stopTunnel(true)
		case session.CancelChallenge:
			a.cancelPIN()
		case session.ApplyNetwork:
			a.network(e, false)
		case session.RemoveNetwork:
			a.revoke()
			a.network(e, true)
		case session.EmitState:
			code := protocol.Code("")
			if e.Phase == session.Failed && a.state.Failure == session.InterfaceFailure {
				code = protocol.InterfaceMismatch
			}
			if e.Phase == session.Failed && a.state.Failure == session.ConflictFailure {
				code = protocol.Conflict
			}
			a.server.emit(protocol.Event{Type: "state", Wanted: a.state.Wanted, CleanupPending: e.Phase == session.Failed && !a.state.Cleaned, Profile: e.Profile, Attempt: e.Attempt, State: string(e.Phase), Detail: e.Detail, Code: code}, a.origin)
		case session.EmitChallenge:
			if a.pending != nil {
				a.server.emit(protocol.Event{Type: "challenge", Profile: e.Profile, Attempt: e.Attempt, ChallengeID: a.pending.id, Kind: string(e.Request.Kind), Prompt: e.Request.Prompt}, a.origin)
			}
		case session.EmitCert:
			a.server.emit(protocol.Event{Type: "cert", Profile: e.Profile, Attempt: e.Attempt, Digest: e.Certificate.Digest, Subject: e.Certificate.Subject, Issuer: e.Certificate.Issuer}, a.origin, a.ownerUID)
		case session.PersistTrust: // The synchronous trust operation already persisted the exact captured digest.
		}
	}
}

// revoke removes the live relay capability before stop or cleanup begins.
func (a *supervisor) revoke() {
	a.server.mu.Lock()
	delete(a.server.tokens, a.token)
	a.server.mu.Unlock()
	a.token = ""
}

// cancelPIN invalidates a pending challenge and wakes its private relay waiter.
// Channels hold a single reply, preventing shutdown from blocking on a lost client.
func (a *supervisor) cancelPIN() {
	if a.pending == nil {
		return
	}
	a.server.mu.Lock()
	delete(a.server.challenges, a.pending.id)
	a.server.mu.Unlock()
	a.pending.reply <- pinReply{Cancel: true}
	a.pending = nil
}

// network serializes bounded route/DNS transactions for this profile. Removal cancels
// preceding work and waits for it to return before teardown, including cleanup retries.
// A failed wait or teardown retains the journal and cannot authorize another child.
// The actor owns cancellation handles; workers capture immutable attempt metadata.
func (a *supervisor) network(effect session.Effect, remove bool) {
	p := a.profile
	journal := a.journal
	tunnel := a.tunnel
	previous := a.networkDone
	if remove && a.networkCancel != nil {
		a.networkCancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.state.Deadlines.Network)
	done := make(chan struct{})
	a.networkCancel, a.networkDone = cancel, done
	a.children.Add(1)
	go func() {
		defer a.children.Done()
		defer close(done)
		defer cancel()
		event := session.Event{Profile: effect.Profile, Attempt: effect.Attempt, Kind: session.NetworkApplied, Failure: session.NetworkFailure}
		if previous != nil {
			// Never remove ownership records while an older transaction can still write.
			select {
			case <-previous:
			case <-ctx.Done():
			}
		}
		err := ctx.Err()
		if remove {
			if err == nil && a.server.stateDir != nil {
				// Apply may have recorded resources after this worker was queued.
				stored, readErr := readJournalAt(a.server.stateDir, journal.Profile)
				switch {
				case readErr == nil:
					if stored.Attempt != journal.Attempt {
						err = errors.New("journal generation changed")
					} else {
						journal = stored
					}
				case !errors.Is(readErr, os.ErrNotExist):
					err = readErr
				case journal.PID > 0:
					err = errors.New("live attempt journal missing")
				}
			}
			if err == nil {
				err = a.server.opts.Network.Teardown(ctx, journal)
			}
			if err == nil {
				if retained, ok := tunnel.(interface{ Release(context.Context) error }); ok {
					err = retained.Release(ctx)
				}
			}
			if err == nil && a.server.stateDir != nil {
				err = removeJournalAt(a.server.stateDir, journal.Profile)
			}
			event.Kind = session.CleanupDone
			if err != nil {
				event.Kind = session.CleanupFailed
			}
		} else {
			identity := journal
			persist := func(updated Journal) error {
				if updated.Profile != identity.Profile || updated.Attempt != identity.Attempt || updated.PID != identity.PID || updated.StartTime != identity.StartTime {
					return errors.New("network changed process identity")
				}
				return writeJournalAt(a.server.stateDir, updated)
			}
			if err == nil {
				journal.Interface = effect.Interface
				err = persist(journal)
			}
			if err == nil {
				if p.Backend == "native" {
					if native, ok := a.server.opts.Network.(NativeNetwork); ok {
						err = native.ConfigureNative(ctx, effect, &journal, persist)
					} else {
						err = errors.New("native network configuration unavailable")
					}
				}
				if err == nil {
					err = a.server.opts.Network.Apply(ctx, p, effect, &journal, persist)
				}
			}
			if err != nil {
				event.Kind = session.AttemptFailed
				event.Detail = "route or split DNS configuration failed; cleanup required"
				var link *network.InterfaceError
				if errors.As(err, &link) {
					event.Failure, event.Detail = session.InterfaceFailure, link.Error()
				}
				var conflict *network.ConflictError
				if errors.As(err, &conflict) {
					event.Failure, event.Detail = session.ConflictFailure, conflict.Detail
				}
			}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			event.Failure = session.TimeoutFailure
		}
		a.send(event)
	}()
}

// checkNetworkUp reserves conflict policy before spawning any explicit or retry child.
// Optional adapters are checked under a finite deadline without holding server locks.
func (a *supervisor) checkNetworkUp() error {
	if checks, ok := a.server.opts.Network.(NetworkConflicts); ok {
		ctx, cancel := context.WithTimeout(a.server.ctx, a.state.Deadlines.Network)
		defer cancel()
		return checks.CheckUp(ctx, a.profile)
	}
	return nil
}

// releaseNetworkReservation discards unused pre-spawn policy after a no-start outcome,
// profile replacement or retirement. Optional adapters preserve live/uncleaned ownership.
func (a *supervisor) releaseNetworkReservation() {
	if reservations, ok := a.server.opts.Network.(NetworkReservations); ok {
		reservations.Release(a.id)
	}
}

// networkFailure converts adapter failures into safe attempt-bound reducer input.
// Only typed conflict explanations are public; operating-system diagnostics stay private.
func (a *supervisor) networkFailure(err error) session.Event {
	e := a.event(session.AttemptFailed)
	e.Failure, e.Detail = session.NetworkFailure, "network conflict checks unavailable"
	var conflict *network.ConflictError
	if errors.As(err, &conflict) {
		e.Failure, e.Detail = session.ConflictFailure, conflict.Detail
	}
	return e
}

// snapshotFor adds connection-local attempt provenance under the public-view lock.
// Ordinary observers see state without gaining prompt ownership of a CLI attempt.
func (a *supervisor) snapshotFor(c *connection) Status {
	a.snapshotMu.Lock()
	defer a.snapshotMu.Unlock()
	status := a.public
	status.Initiated = a.publicOrigin == c
	return status
}
