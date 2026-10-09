package native

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/ppp"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/tun"
)

// BackendOptions injects unprivileged transport and device factories for tests.
// Client defaults to the profile's TLS policy, CreateTUN to kernel allocation, and
// StopTimeout to two seconds per termination/logout operation. PPP supplies finite
// protocol budgets; it never carries credentials or privileged network commands.
type BackendOptions struct {
	Client      func(profile.Profile) (*Client, error)
	CreateTUN   func(context.Context, int) (tun.Device, error)
	PPP         ppp.Config
	StopTimeout time.Duration
}

// Backend assembles password login, PPP and a native device without changing routes.
// Each Start creates independent credentials, protocol state and transport resources.
type Backend struct{ options BackendOptions }

// NewBackend returns an inert backend with injected or production resource factories.
// Start validates profiles and TLS settings before obtaining credentials; PPP checks
// its injected protocol budgets when negotiation begins.
func NewBackend(options BackendOptions) *Backend {
	if options.CreateTUN == nil {
		options.CreateTUN = tun.Create
	}
	if options.Client == nil {
		options.Client = func(p profile.Profile) (*Client, error) {
			return NewClient(Options{Host: p.Gateway.Host, Port: p.Gateway.Port, TrustedCert: p.TrustedCert})
		}
	}
	if options.StopTimeout == 0 {
		options.StopTimeout = 2 * time.Second
	}
	return &Backend{options: options}
}

// Start validates the attempt and launches one asynchronous credential/login worker.
// Native MFA is rejected before dialing and never falls back to another backend.
// RegisterLink is mandatory so an allocated device is durably owned before use.
func (b *Backend) Start(ctx context.Context, attempt backend.Attempt) (backend.Tunnel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := attempt.Config.Profile
	p.ApplyDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Backend != "native" || p.MFA.Mode != "none" || attempt.Profile != p.ID || attempt.Generation == 0 || attempt.Hooks.RegisterLink == nil || b.options.StopTimeout <= 0 {
		return nil, errors.New("invalid native attempt")
	}
	client, err := b.options.Client(p)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("native client factory returned no client")
	}
	ctx, cancel := context.WithCancel(ctx)
	t := &Tunnel{ctx: ctx, cancel: cancel, attempt: attempt, profile: p, options: b.options, client: client, events: make(chan backend.Event, 16), answers: make(chan []byte, 1), activate: make(chan struct{}), done: make(chan struct{})}
	go t.run()
	return t, nil
}

// Tunnel owns an attempt's TLS and PPP workers, retaining the device until Release.
// Activate opens the data gate only after helper networking succeeds. Stop cancels
// setup or data forwarding; Wait acknowledges transport shutdown, not device release.
type Tunnel struct {
	ctx                                 context.Context
	cancel                              context.CancelFunc
	attempt                             backend.Attempt
	profile                             profile.Profile
	options                             BackendOptions
	client                              *Client
	events                              chan backend.Event
	answers                             chan []byte
	activate                            chan struct{}
	done                                chan struct{}
	mu                                  sync.Mutex
	answered, ready, activated, closing bool
	device                              tun.Device
	deviceCancel                        context.CancelFunc
	gateway                             netip.Addr
	err                                 error
}

// Events returns ordered, bounded observations without passwords or session cookies.
func (t *Tunnel) Events() <-chan backend.Event { return t.events }

// Answer copies exactly one password while setup is live, rejecting stale requests.
// The caller retains its bytes; the owned copy is cleared after Login or cancellation.
func (t *Tunnel) Answer(ctx context.Context, request backend.Request, secret []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.ctx.Err() != nil || t.answered || request.Kind != backend.Password || len(secret) == 0 || len(secret) > 4096 {
		return errors.New("native password request is no longer pending")
	}
	t.answered = true
	t.answers <- bytes.Clone(secret)
	return nil
}

// Activate enables packet forwarding after durable address, route and DNS application.
// Repeated activation is harmless; cancellation or premature activation fails closed.
func (t *Tunnel) Activate(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.ctx.Err(); err != nil {
		return err
	}
	if !t.ready || t.closing {
		return errors.New("native link is not ready")
	}
	if !t.activated {
		t.activated = true
		close(t.activate)
	}
	return nil
}

// GatewayIP returns the actual TLS peer address, not a DNS guess or PPP endpoint.
// The helper journals this value for full-tunnel physical gateway exceptions.
func (t *Tunnel) GatewayIP() netip.Addr { t.mu.Lock(); defer t.mu.Unlock(); return t.gateway }

// Stop requests idempotent shutdown without blocking the supervisor's event drain.
// ctx limits the request; Wait separately confirms termination and bounded logout.
func (t *Tunnel) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.cancel()
	return nil
}

// Wait returns the terminal transport error after ordered Outcome delivery completes.
func (t *Tunnel) Wait() error { <-t.done; return t.err }

// Release closes the retained TUN only after transport completion and network teardown.
// It waits for transport completion under ctx before closing a still-owned device.
func (t *Tunnel) Release(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.device != nil {
		err := t.device.Close()
		if t.deviceCancel != nil {
			t.deviceCancel()
		}
		return err
	}
	return nil
}

// emit delivers a finite lifecycle record. The supervisor must continuously drain
// Events, including during stop, so terminal outcomes cannot be lost to cancellation.
func (t *Tunnel) emit(event backend.Event) { t.events <- event }

// run owns resource assembly and shutdown. Device lifetime is independent of Stop
// so cleanup can verify link identity before Release removes the kernel interface.
func (t *Tunnel) run() {
	var conn *Connection
	var link *ppp.Link
	var pump *packetPump
	var transport *frameTransport
	var linkFinished chan struct{}
	transportCtx, transportCancel := context.WithCancel(context.Background())
	defer func() {
		t.mu.Lock()
		t.closing = true
		t.mu.Unlock()
		if pump != nil {
			pump.stop()
		}
		if link != nil {
			ctx, cancel := context.WithTimeout(context.Background(), t.options.StopTimeout)
			_ = link.Close(ctx)
			cancel()
			if linkFinished != nil {
				<-linkFinished
			}
		}
		transportCancel()
		if transport != nil {
			transport.close()
		}
		if conn != nil {
			_ = conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), t.options.StopTimeout)
			_ = conn.Logout(ctx)
			cancel()
		}
		t.mu.Lock()
		select {
		case secret := <-t.answers:
			clear(secret)
		default:
		}
		t.cancel()
		t.mu.Unlock()
		outcome := t.outcome(t.err)
		t.emit(outcome)
		close(t.events)
		close(t.done)
	}()
	t.emit(backend.CredentialRequested{Request: backend.Request{Kind: backend.Password, Prompt: "VPN password"}})
	var password []byte
	select {
	case password = <-t.answers:
	case <-t.ctx.Done():
		return
	}
	conn, t.err = t.client.Login(t.ctx, Credentials{Username: t.profile.Username, Password: password, Realm: t.profile.Realm})
	clear(password)
	if t.err != nil {
		return
	}
	t.mu.Lock()
	if addr, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		t.gateway = addr.Addr().Unmap()
	}
	t.mu.Unlock()
	t.emit(backend.ConnectedToGateway{})
	t.emit(backend.Authenticated{})
	t.emit(backend.VPNAllocated{})
	config := t.options.PPP
	// Networking and the pump retain one snapshot, so a new PPP offer needs a retry.
	config.StopOnRenegotiation = true
	if len(conn.Config.DNS) > 0 {
		config.PrimaryDNS = conn.Config.DNS[0]
	}
	if len(conn.Config.DNS) > 1 {
		config.SecondaryDNS = conn.Config.DNS[1]
	}
	// Setup cancellation interrupts PPP; once open it must terminate gracefully.
	interrupt := context.AfterFunc(t.ctx, transportCancel)
	transport = newFrameTransport(transportCtx, conn)
	info, err := ppp.Negotiate(transportCtx, transport, config)
	interrupt()
	if err != nil {
		t.err = err
		return
	}
	link = info.Link
	metadata, err := nativeNegotiated(info, conn.Config)
	if err != nil {
		t.err = err
		return
	}
	mtu := metadata.MTU
	// Allocation can be interrupted, but a created link survives transport shutdown
	// until the helper has removed its owned routes and resolver entries.
	deviceCtx, deviceCancel := context.WithCancel(context.Background())
	allocationDone := make(chan struct{})
	stopAllocation := context.AfterFunc(t.ctx, func() { deviceCancel(); close(allocationDone) })
	device, err := t.options.CreateTUN(deviceCtx, mtu)
	if !stopAllocation() {
		<-allocationDone
	}
	if err != nil || device == nil {
		deviceCancel()
		if device != nil {
			_ = device.Close()
		}
		if err == nil {
			err = errors.New("native device factory returned no device")
		}
		t.err = err
		return
	}
	t.mu.Lock()
	t.device, t.deviceCancel = device, deviceCancel
	t.mu.Unlock()
	if _, ok := device.(contextualDevice); !ok {
		t.err = errors.New("native device lacks cancellable packet I/O")
		return
	}
	identity := backend.LinkIdentity{Interface: device.Name(), Index: device.Index()}
	if err = t.attempt.Hooks.RegisterLink(t.ctx, identity); err != nil {
		t.err = err
		return
	}
	t.emit(metadata)
	t.emit(backend.LinkReady{Link: identity})
	t.mu.Lock()
	t.ready = true
	t.mu.Unlock()
	t.emit(backend.TunnelUp{})
	linkFinished = make(chan struct{})
	go func() { _ = link.Wait(); close(linkFinished) }()
	select {
	case <-t.ctx.Done():
		return
	case <-linkFinished:
		t.err = link.Wait()
		return
	case <-t.activate:
	}
	pump, err = startPump(t.ctx, device, link, mtu)
	if err != nil {
		t.err = err
		return
	}
	select {
	case <-t.ctx.Done():
	case <-linkFinished:
		t.err = link.Wait()
	case <-pump.done:
		t.err = pump.err
	}
}

// nativeNegotiated converts PPP info and XML config into native network metadata.
// A usable negotiated local IPv4 address is mandatory; XML cannot supply a fallback.
// Native links are unnumbered, so PeerIP repeats LocalIP for existing session consumers.
// The advertised PPP peer is ignored, even if absent or invalid, and never reaches host
// configuration. DNS, MTU and pushed policy retain their negotiated sources.
func nativeNegotiated(info ppp.Negotiated, config VPNConfig) (backend.Negotiated, error) {
	if !info.LocalIP.Is4() || !info.LocalIP.IsGlobalUnicast() || info.LocalIP == netip.MustParseAddr("255.255.255.255") {
		return backend.Negotiated{}, errors.New("gateway omitted usable PPP local address")
	}
	dns := make([]netip.Addr, 0, 2)
	for _, ip := range []netip.Addr{info.PrimaryDNS, info.SecondaryDNS} {
		if ip.IsValid() {
			dns = append(dns, ip)
		}
	}
	return backend.Negotiated{LocalIP: info.LocalIP, PeerIP: info.LocalIP, MTU: min(info.MRU, info.PeerMRU), DNS: dns, Suffix: strings.Join(config.Domains, " "), PushedPrefixes: config.SplitRoutes}, nil
}

// outcome translates typed protocol errors without exposing gateway body text.
// Trust/auth observations precede completion so the reducer preserves their target.
// I/O deadlines after activation are transport loss; setup deadlines remain fatal.
func (t *Tunnel) outcome(err error) backend.Outcome {
	if err == nil || t.ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return backend.Outcome{}
	}
	var cert *CertificateRejected
	var mfa *UnsupportedMFA
	if errors.As(err, &cert) {
		t.emit(backend.CertificateRejected{Digest: cert.Digest, Subject: cert.Subject, Issuer: cert.Issuer})
		return backend.Outcome{}
	}
	if errors.As(err, &mfa) {
		t.emit(backend.CredentialRequested{Request: backend.Request{Kind: backend.Code}})
		return backend.Outcome{Failure: backend.AuthFailure}
	}
	if errors.Is(err, ErrAuthentication) {
		t.emit(backend.AuthFailed{})
		return backend.Outcome{Failure: backend.AuthFailure}
	}
	if errors.Is(err, ErrTunnelDenied) {
		t.emit(backend.TunnelModeDenied{})
		return backend.Outcome{Failure: backend.TunnelFailure}
	}
	var conflict *network.ConflictError
	if errors.As(err, &conflict) {
		t.emit(backend.RouteRejected{Reason: backend.RouteConflict})
		return backend.Outcome{Failure: backend.ConflictFailure}
	}
	var mismatch *network.InterfaceError
	if errors.As(err, &mismatch) {
		return backend.Outcome{Failure: backend.InterfaceFailure}
	}
	if errors.Is(err, ppp.ErrRenegotiation) {
		return backend.Outcome{Failure: backend.TransportFailure}
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		t.mu.Lock()
		activated := t.activated
		t.mu.Unlock()
		if activated {
			return backend.Outcome{Failure: backend.TransportFailure}
		}
		return backend.Outcome{Failure: backend.TimeoutFailure}
	}
	return backend.Outcome{ExitCode: 1}
}
