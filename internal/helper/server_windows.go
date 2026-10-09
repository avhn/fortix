package helper

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
	"github.com/avhn/fortix/internal/tun"
	"github.com/avhn/fortix/internal/winfs"
)

// Options configures helper paths and injectable policy. Zero limits use bounded
// defaults. Network must honor context cancellation; nil selects owned host networking.
// Backends overrides native transport for tests; unsupported transports remain refused.
type Options struct {
	Paths          paths.Paths
	Authorize      Authorizer
	Logger         *slog.Logger
	Network        Network
	Backends       map[string]backend.Backend
	Deadlines      session.Deadlines
	MaxConnections int
	IdleTimeout    time.Duration
	RecordTimeout  time.Duration
}

// Server manages a bounded connection registry and independent profile supervisors.
// Serve is called once; cancellation closes the pipe and drains all native attempts.
type Server struct {
	registry   sidRegistry
	fortixSID  string
	opts       Options
	ctx        context.Context
	cancel     context.CancelFunc
	store      *Store
	stateDir   *helperDirectory
	logDir     *helperDirectory
	opMu       sync.Mutex
	mu         sync.Mutex
	clients    map[*connection]bool
	actors     map[string]*supervisor
	tokens     map[string]tokenBinding
	challenges map[string]*challengeRoute
	workers    sync.WaitGroup
}

// challengeRoute retains a pending prompt so disconnects can transfer delivery to
// subscribers. All fields are protected by the server mutex, not the actor goroutine.
type challengeRoute struct {
	actor  *supervisor
	uid    uint32
	origin *connection
	event  protocol.Event
}

// tokenBinding binds an unpredictable relay capability to one live generation.
type tokenBinding struct {
	actor   *supervisor
	attempt uint64
}

// connection serializes result/event writes and bounds slow-reader blocking.
// Subscriptions and the open flag are protected by the server registry mutex.
type connection struct {
	peer             Peer
	uid              uint32
	logs             bool
	socket           net.Conn
	events           chan protocol.Event
	mu               sync.Mutex
	subscribed, open bool
}

// write writes one message under a per-connection lock and a finite deadline.
// Encoding failures and unresponsive clients are surfaced to the caller.
func (c *connection) write(message any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.socket.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	return protocol.Write(c.socket, message)
}

// emit delivers an event to subscribers or exclusively to a still-open initiating
// connection for challenges and certificates. Fallback is restricted to the same SID
// registry handle. Logs require an explicit log subscription. Failed writes close the client
// rather than queueing unbounded data. No caller may hold s.mu while emitting.
func (s *Server) emit(event protocol.Event, origin *connection, owner ...uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	private := event.Type == "challenge" || event.Type == "cert"
	uid := uint32(0)
	if len(owner) > 0 {
		uid = owner[0]
	}
	if event.Type == "challenge" {
		if route := s.challenges[event.ChallengeID]; route != nil {
			uid = route.uid
			route.event = event
			if origin != nil && origin.open {
				route.origin = origin
			}
		}
	}
	if private && origin != nil && origin.open && origin.uid == uid {
		select {
		case origin.events <- event:
			return
		default:
			origin.open = false
			_ = origin.socket.Close()
		}
	}
	if route := s.challenges[event.ChallengeID]; event.Type == "challenge" && route != nil {
		// Delivery already fell back; teardown must not broadcast it a second time.
		route.origin = nil
	}
	for c := range s.clients {
		if !c.subscribed || !c.open || (private && c.uid != uid) || (event.Type == "log" && !c.logs) {
			continue
		}
		if event.Type == "state" {
			event.Initiated = c == origin
		}
		select {
		case c.events <- event:
		default:
			c.open = false
			_ = c.socket.Close()
		}
	}
}

// failure constructs a public result using only helper-controlled error text.
func failure(id string, code protocol.Code, message string) protocol.Result {
	return protocol.Result{Type: "result", ID: id, Error: &protocol.Error{Code: code, Message: message}}
}

// storedFailure maps a missing profile to NOT_FOUND and other storage failures to
// INTERNAL without exposing paths, file contents, or operating-system diagnostics.
func storedFailure(id string, err error) protocol.Result {
	if errors.Is(err, os.ErrNotExist) {
		return failure(id, protocol.NotFound, "profile not found")
	}
	return failure(id, protocol.Internal, "profile storage unavailable")
}

// actor obtains an existing profile supervisor under the registry mutex.
func (s *Server) actor(id string) *supervisor { s.mu.Lock(); defer s.mu.Unlock(); return s.actors[id] }

// profileIDs returns deterministic profile ordering for status and list results.
func (s *Server) profileIDs() ([]string, error) {
	ids, err := s.store.IDs()
	sort.Strings(ids)
	return ids, err
}

// pump drains a bounded event queue without allowing a slow client to stall phase
// timers or process cleanup. Closing the socket wakes both reader and writer.
func (s *Server) pump(c *connection, done <-chan struct{}) {
	defer s.detach(c)
	for {
		select {
		case <-done:
			return
		case event := <-c.events:
			if err := c.write(event); err != nil {
				_ = c.socket.Close()
				return
			}
		}
	}
}

// detach closes the logical connection and transfers all still-pending prompts,
// including prompts already written or queued. The registry is authoritative: answered
// prompts in the abandoned queue are discarded, never rebroadcast as stale challenges.
func (s *Server) detach(c *connection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.open = false
	delete(s.clients, c)
	for _, route := range s.challenges {
		if route.origin != c {
			continue
		}
		route.origin = nil
		for subscriber := range s.clients {
			if !subscriber.subscribed || !subscriber.open || (subscriber.uid != route.uid) {
				continue
			}
			select {
			case subscriber.events <- route.event:
			default:
				subscriber.open = false
				_ = subscriber.socket.Close()
			}
		}
	}
}

// New validates the Windows service surface without opening storage or accepting clients.
func New(opts Options) (*Server, error) {
	if opts.Paths.SkipTrust {
		return nil, errors.New("development helper mode is not available on Windows")
	}
	if opts.Paths.ControlSocket != controlPipe || opts.Paths.PinentrySocket != "" || opts.Paths.Pinentry != "" || len(opts.Paths.OpenFortiVPN) != 0 {
		return nil, errors.New("invalid Windows helper transport paths")
	}
	for _, path := range []string{opts.Paths.State, opts.Paths.Profiles, opts.Paths.Logs} {
		if !winfs.ValidPath(path) {
			return nil, errors.New("helper paths must be canonical local drive paths")
		}
	}
	if opts.MaxConnections == 0 {
		opts.MaxConnections = 15
	}
	if opts.MaxConnections < 1 || opts.MaxConnections > 15 {
		return nil, errors.New("invalid connection limit")
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 5 * time.Minute
	}
	if opts.RecordTimeout == 0 {
		opts.RecordTimeout = 5 * time.Second
	}
	if opts.IdleTimeout < 0 || opts.RecordTimeout < 0 {
		return nil, errors.New("invalid control timeout")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Authorize == nil {
		opts.Authorize = Authorize
	}
	if opts.Network == nil {
		manager, err := network.New(network.Options{Paths: opts.Paths})
		if err != nil {
			return nil, err
		}
		opts.Network = manager
	}
	backends := make(map[string]backend.Backend, len(opts.Backends)+1)
	for name, b := range opts.Backends {
		backends[name] = b
	}
	if backends["native"] == nil {
		backends["native"] = defaultNativeBackend(false)
	}
	backends["openfortivpn"] = openfortivpnBackend{}
	opts.Backends = backends
	return &Server{opts: opts, clients: make(map[*connection]bool), actors: make(map[string]*supervisor), tokens: make(map[string]tokenBinding), challenges: make(map[string]*challengeRoute)}, nil
}

// Serve requires LocalSystem, pins storage, recovers all ownership, then claims the pipe.
// Cancellation closes the listener and clients before waiting for complete actor cleanup.
func (s *Server) Serve(ctx context.Context) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("Windows helper service requires LocalSystem")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()
	s.fortixSID, err = localFortixSID()
	if err != nil {
		return err
	}
	for _, path := range []string{s.opts.Paths.Profiles, s.opts.Paths.State, s.opts.Paths.Logs} {
		if err := secureDir(path, 0); err != nil {
			return err
		}
	}
	s.stateDir, err = openDirectory(s.opts.Paths.State)
	if err != nil {
		return err
	}
	defer s.stateDir.Close()
	lock, err := serviceLockAt(s.stateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	s.logDir, err = openDirectory(s.opts.Paths.Logs)
	if err != nil {
		return err
	}
	defer s.logDir.Close()
	s.store, err = OpenStore(s.opts.Paths.Profiles)
	if err != nil {
		return err
	}
	defer s.store.Close()
	if manager, ok := s.opts.Network.(interface{ AllocationHook(tun.Allocation) error }); ok {
		tun.SetAllocationHook(manager.AllocationHook)
	} else {
		tun.SetAllocationHook(nil)
	}
	defer tun.SetAllocationHook(nil)
	if manager, ok := s.opts.Network.(interface {
		FinalizeRelease(context.Context, Journal) error
	}); ok {
		s.stateDir.finalize = func(j Journal) error {
			budget := s.opts.Deadlines.Network
			if budget <= 0 {
				budget = session.DefaultDeadlines().Network
			}
			cleanup, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			err := manager.FinalizeRelease(cleanup, j)
			// Teardown already verified absent ownership. This also permits retrying
			// helper-file deletion after an earlier successful network finalization.
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
	}
	listener, err := s.recoverAndListen(s.ctx)
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(s.ctx, func() { _ = listener.Close() })
	defer stop()
	err = s.accept(listener)
	s.cancel()
	_ = listener.Close()
	s.mu.Lock()
	clients := make([]*connection, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	actors := make([]*supervisor, 0, len(s.actors))
	for _, a := range s.actors {
		actors = append(actors, a)
	}
	s.mu.Unlock()
	for _, c := range clients {
		_ = c.socket.Close()
	}
	s.workers.Wait()
	// Workers can create actors until cancellation has closed their last request.
	s.mu.Lock()
	actors = actors[:0]
	for _, a := range s.actors {
		actors = append(actors, a)
	}
	s.mu.Unlock()
	for _, a := range actors {
		<-a.done
		if !a.idle() {
			return errors.New("helper stopped with incomplete cleanup")
		}
	}
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// accept reserves a bounded worker slot before connecting the next native instance.
func (s *Server) accept(listener *pipeListener) error {
	slots := make(chan struct{}, s.opts.MaxConnections)
	for {
		select {
		case slots <- struct{}{}:
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
		socket, err := listener.Accept()
		if err != nil {
			<-slots
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// A failed client or replacement allocation must not tear down other users' tunnels.
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return s.ctx.Err()
			case <-timer.C:
			}
			continue
		}
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer func() { _ = socket.Close(); <-slots }()
			stop := context.AfterFunc(s.ctx, func() { _ = socket.Close() })
			defer stop()
			s.control(socket)
		}()
	}
}

// identify revalidates the last reader's token and maps its full SID to a stable handle.
func (s *Server) identify(socket *pipeConn) (Peer, error) {
	peer, err := authenticatePipe(socket.handle, s.fortixSID, pipeImpersonation{}, fatalRevert(s.opts.Logger))
	if err != nil {
		return Peer{}, err
	}
	if err := Authorize(peer); err != nil {
		return Peer{}, err
	}
	peer.UID, err = s.registry.register(peer.SID)
	if err != nil {
		return Peer{}, err
	}
	if err := s.opts.Authorize(peer); err != nil {
		return Peer{}, err
	}
	return peer, nil
}

// control permits only a secret-free hello before token authentication, then revalidates
// identity on every frame so a changed client token cannot inherit earlier authority.
func (s *Server) control(socket *pipeConn) {
	reader := protocol.NewReader(socket)
	if err := socket.SetReadDeadline(time.Now().Add(s.opts.RecordTimeout)); err != nil {
		return
	}
	var hello protocol.Request
	if reader.Read(&hello) != nil || hello.Validate() != nil || hello.Op != "hello" {
		return
	}
	peer, err := s.identify(socket)
	c := &connection{peer: peer, uid: peer.UID, socket: socket, open: true, events: make(chan protocol.Event, 64)}
	if err != nil {
		_ = c.write(failure(hello.ID, protocol.Unauthorized, "peer is not authorized"))
		return
	}
	s.opts.Logger.Info("control connection", "uid", peer.UID)
	s.mu.Lock()
	s.clients[c] = true
	s.mu.Unlock()
	done, pumped := make(chan struct{}), make(chan struct{})
	go func() { defer close(pumped); s.pump(c, done) }()
	defer func() { s.detach(c); close(done); _ = socket.Close(); <-pumped }()
	if err := c.write(s.dispatchWindows(c, hello)); err != nil {
		return
	}
	for {
		deadline := time.Now().Add(s.opts.IdleTimeout)
		s.mu.Lock()
		if c.subscribed {
			deadline = time.Time{}
		}
		s.mu.Unlock()
		if socket.SetReadDeadline(deadline) != nil {
			return
		}
		var request protocol.Request
		if err := reader.ReadStarted(&request, func() error { return socket.SetReadDeadline(time.Now().Add(s.opts.RecordTimeout)) }); err != nil {
			return
		}
		if socket.SetReadDeadline(time.Time{}) != nil {
			return
		}
		current, err := s.identify(socket)
		if err != nil || current.SID != peer.SID {
			_ = c.write(failure(request.ID, protocol.Unauthorized, "peer is not authorized"))
			return
		}
		c.peer = current
		id := request.ID
		if len(id) > 128 {
			id = ""
		}
		result := failure(id, protocol.Invalid, "invalid request arguments")
		if request.Validate() == nil {
			s.opMu.Lock()
			result = s.dispatchWindows(c, request)
			s.opMu.Unlock()
		}
		request.Secret = ""
		clear(request.ProfileJSON)
		if c.write(result) != nil {
			return
		}
	}
}

// dispatchWindows enforces Windows admission before shared reducers can challenge or mutate.
// Private replies require the exact originating SID, including when the caller is an admin.
func (s *Server) dispatchWindows(c *connection, r protocol.Request) protocol.Result {
	if r.Profile != "" && !ValidID(r.Profile) {
		return failure(r.ID, protocol.Invalid, "invalid profile id")
	}
	if r.Op == "up" {
		p, err := s.store.Get(r.Profile)
		if err != nil {
			return storedFailure(r.ID, err)
		}
		if p.MFA.Mode != "none" {
			return failure(r.ID, protocol.Invalid, "MFA profiles are not available on Windows")
		}
		if p.Backend != "native" {
			return failure(r.ID, protocol.Invalid, openfortivpnUnavailable)
		}
	}
	if r.Op == "answer" || r.Op == "cancel" {
		s.mu.Lock()
		route := s.challenges[r.ChallengeID]
		s.mu.Unlock()
		if route != nil && route.uid != c.uid {
			return failure(r.ID, protocol.Unauthorized, "peer is not authorized")
		}
	}
	if r.Op == "trust" {
		if a := s.actor(r.Profile); a != nil {
			a.snapshotMu.Lock()
			origin := a.publicOrigin
			a.snapshotMu.Unlock()
			if origin == nil || origin.uid != c.uid {
				return failure(r.ID, protocol.Unauthorized, "peer is not authorized")
			}
		}
	}
	return s.dispatch(c, r)
}

// recoverAndListen never exposes the control pipe before all startup ownership is reconciled.
func (s *Server) recoverAndListen(ctx context.Context) (*pipeListener, error) {
	if err := s.recover(ctx); err != nil {
		return nil, err
	}
	return listenPipe(s.fortixSID)
}
