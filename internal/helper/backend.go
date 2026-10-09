package helper

import (
	"context"
	"errors"
	"net/netip"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/native"
	"github.com/avhn/fortix/internal/session"
)

// NativeNetwork extends owned routing with durable native link registration and
// address configuration. Both callbacks persist intent before privileged mutation.
type NativeNetwork interface {
	RegisterLink(context.Context, string, uint64, backend.LinkIdentity, *Journal, func(Journal) error) error
	ConfigureNative(context.Context, session.Effect, *Journal, func(Journal) error) error
}

// defaultNativeBackend disables kernel device creation in development roots.
// Tests can explicitly inject a fake backend; production uses the kernel allocator.
func defaultNativeBackend(development bool) backend.Backend {
	if development {
		return unavailableNative{}
	}
	return native.NewBackend(native.BackendOptions{})
}

// unavailableNative refuses privileged native setup in isolated development roots.
type unavailableNative struct{}

// Start fails without opening TLS or changing host links when native is disabled.
func (unavailableNative) Start(context.Context, backend.Attempt) (backend.Tunnel, error) {
	return nil, errors.New("native backend requires an owned network adapter")
}

// start selects the resolved profile backend without silently changing transports.
// A native attempt records child-free intent before its asynchronous setup starts.
func (a *supervisor) start() error {
	a.command = nil
	a.tunnel = nil
	a.journal = Journal{Profile: a.id, Attempt: a.state.Attempt, Backend: a.profile.Backend}
	implementation := a.server.opts.Backends[a.profile.Backend]
	if implementation == nil && a.profile.Backend == "openfortivpn" {
		implementation = openfortivpnBackend{actor: a}
	}
	if implementation == nil {
		return errors.New("selected VPN backend is unavailable")
	}
	if a.profile.Backend == "native" {
		log, err := openLogAt(a.server.logDir, a.id)
		if err != nil {
			return err
		}
		if a.log != nil {
			_ = a.log.Close()
		}
		a.log = log
		if err := a.checkNetworkUp(); err != nil {
			return err
		}
		if err := writeJournalAt(a.server.stateDir, a.journal); err != nil {
			return err
		}
	}
	generation := a.state.Attempt
	registrations := make(chan controlInput)
	attempt := backend.Attempt{Profile: a.id, Generation: generation, Config: backend.Config{Profile: *a.profile}}
	attempt.Hooks.RegisterLink = func(ctx context.Context, link backend.LinkIdentity) error {
		input := controlInput{op: "register_link", attempt: generation, link: link, ctx: ctx}
		// Native setup reaches this callback after Start returns its owned tunnel.
		input.reply = make(chan controlReply, 1)
		select {
		case registrations <- input:
		case <-ctx.Done():
			return ctx.Err()
		case <-a.done:
			return errors.New("supervisor stopped")
		}
		select {
		case reply := <-input.reply:
			return reply.err
		case <-ctx.Done():
			return ctx.Err()
		case <-a.done:
			return errors.New("supervisor stopped")
		}
	}
	tunnel, err := implementation.Start(context.Background(), attempt)
	if err != nil {
		return err
	}
	a.tunnel = tunnel
	a.children.Add(1)
	go func() {
		defer a.children.Done()
		forward := func(observation backend.Event) {
			if challenge, ok := observation.(backend.CredentialRequested); ok && challenge.Request.Kind == backend.Password {
				a.obtainPassword(tunnel, generation, challenge.Request)
				return
			}
			a.send(session.Event{Profile: a.id, Attempt: generation, Kind: session.Output, Observation: observation, Jitter: 0.5})
		}
		observations := tunnel.Events()
		for observations != nil {
			select {
			case observation, ok := <-observations:
				if !ok {
					observations = nil
					continue
				}
				forward(observation)
			case input := <-registrations:
				// All previously emitted milestones must precede durable registration.
			drain:
				for {
					select {
					case observation, ok := <-observations:
						if !ok {
							observations = nil
							break drain
						}
						forward(observation)
					default:
						break drain
					}
				}
				reply := a.call(input)
				if reply.code != "" {
					reply.err = errors.New("native registration refused during shutdown")
				}
				input.reply <- reply
			}
		}
		_ = tunnel.Wait()
	}()
	return nil
}

// obtainPassword reuses the authenticated challenge broker without pinentry.
// The reducer owns the human deadline and cancel reply; answers are never logged.
func (a *supervisor) obtainPassword(tunnel backend.Tunnel, generation uint64, request backend.Request) {
	pending := &pendingPIN{request: request, reply: make(chan pinReply, 1)}
	reply := a.call(controlInput{op: "ask", attempt: generation, ask: pending})
	if reply.code != "" {
		_ = tunnel.Stop(context.Background())
		return
	}
	select {
	case answer := <-pending.reply:
		if answer.Cancel {
			_ = tunnel.Stop(context.Background())
			return
		}
		secret := []byte(answer.Secret)
		answer.Secret = ""
		err := tunnel.Answer(context.Background(), request, secret)
		clear(secret)
		if err != nil {
			_ = tunnel.Stop(context.Background())
		}
	case <-a.stopped:
		_ = tunnel.Stop(context.Background())
	}
}

// registerLink serializes ownership registration with actor state and journal writes.
// Stale generations and stopping attempts cannot acquire or configure a new link.
func (a *supervisor) registerLink(input controlInput) error {
	// The bridge queued every setup milestone before requesting this barrier.
drain:
	for {
		select {
		case event := <-a.events:
			a.reduce(event)
		default:
			break drain
		}
	}
	if input.attempt != a.state.Attempt || a.state.Phase != session.Negotiating {
		return errors.New("native registration is no longer active")
	}
	network, ok := a.server.opts.Network.(NativeNetwork)
	if !ok {
		return errors.New("native network registration unavailable")
	}
	ctx, cancel := context.WithTimeout(input.ctx, a.state.Deadlines.Network)
	defer cancel()
	journal := a.journal
	if gateway, ok := a.tunnel.(interface{ GatewayIP() netip.Addr }); ok {
		ip := gateway.GatewayIP()
		if ip.Is4() {
			journal.GatewayIP = ip.String()
		}
	}
	persist := func(updated Journal) error {
		if updated.Profile != journal.Profile || updated.Attempt != journal.Attempt || updated.PID != 0 || updated.StartTime != "" {
			return errors.New("native registration changed attempt identity")
		}
		return writeJournalAt(a.server.stateDir, updated)
	}
	if err := network.RegisterLink(ctx, a.id, input.attempt, input.link, &journal, persist); err != nil {
		return err
	}
	a.journal = journal
	return nil
}

// stopTunnel requests graceful native closure or verified external escalation.
// No native backend ever signals the helper PID or falls back to another transport.
func (a *supervisor) stopTunnel(force bool) {
	if a.tunnel == nil {
		return
	}
	if force {
		if child, ok := a.tunnel.(interface{ Kill() }); ok {
			child.Kill()
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.state.Deadlines.Stop)
	defer cancel()
	_ = a.tunnel.Stop(ctx)
}
