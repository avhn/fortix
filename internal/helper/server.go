package helper

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/network"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// Options configures helper paths and injectable policy. Zero limits use bounded
// defaults. Network must honor context cancellation; nil selects owned host networking.
type Options struct {
	Paths          paths.Paths
	Authorize      Authorizer
	Logger         *slog.Logger
	Network        Network
	Deadlines      session.Deadlines
	MaxConnections int
	IdleTimeout    time.Duration
	RecordTimeout  time.Duration
}

// Server manages a bounded connection registry and independent profile supervisors.
// Serve is called once; cancellation closes both listeners and stops every child.
type Server struct {
	opts       Options
	ctx        context.Context
	cancel     context.CancelFunc
	store      *Store
	stateDir   *os.File
	logDir     *os.File
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
	socket           *net.UnixConn
	events           chan protocol.Event
	mu               sync.Mutex
	subscribed, open bool
}

// New initializes an inert server. It performs no filesystem or privileged work.
// Invalid limits and incomplete path configurations fail before any listener opens.
func New(opts Options) (*Server, error) {
	if opts.Authorize == nil {
		opts.Authorize = Authorize
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Network == nil {
		adapter, err := network.New(network.Options{Paths: opts.Paths})
		if err != nil {
			return nil, err
		}
		opts.Network = adapter
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
	if opts.MaxConnections == 0 {
		opts.MaxConnections = 32
	}
	if opts.MaxConnections < 1 || opts.MaxConnections > 256 {
		return nil, errors.New("invalid connection limit")
	}
	for _, p := range []string{opts.Paths.ControlSocket, opts.Paths.PinentrySocket, opts.Paths.Profiles, opts.Paths.State, opts.Paths.Logs, opts.Paths.Pinentry} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, errors.New("helper paths must be clean and absolute")
		}
	}
	if opts.Paths.ControlSocket == opts.Paths.PinentrySocket || filepath.Dir(opts.Paths.ControlSocket) == filepath.Dir(opts.Paths.PinentrySocket) {
		return nil, errors.New("relay requires a separate private directory")
	}
	if opts.Paths.SkipTrust && os.Geteuid() == 0 {
		return nil, errors.New("root cannot use development paths")
	}
	return &Server{opts: opts, clients: make(map[*connection]bool), actors: make(map[string]*supervisor), tokens: make(map[string]tokenBinding), challenges: make(map[string]*challengeRoute)}, nil
}

// Serve initializes trusted storage, recovers journals, and runs both sockets until
// ctx cancellation or an accept failure. It returns only after workers and children
// have stopped; startup failures never leave listeners or private tokens behind.
func (s *Server) Serve(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Dir(s.opts.Paths.ControlSocket), 0755}, {filepath.Dir(s.opts.Paths.PinentrySocket), 0700},
		{s.opts.Paths.Profiles, 0755}, {s.opts.Paths.State, 0700}, {s.opts.Paths.Logs, 0700},
	} {
		if !s.opts.Paths.SkipTrust {
			if err := trustedAncestor(d.path); err != nil {
				return err
			}
		}
		if err := secureDir(d.path, d.mode); err != nil {
			return err
		}
	}
	stateDir, err := openDirectory(s.opts.Paths.State)
	if err != nil {
		return err
	}
	s.stateDir = stateDir
	defer func() { _ = stateDir.Close() }()
	logDir, err := openDirectory(s.opts.Paths.Logs)
	if err != nil {
		return err
	}
	s.logDir = logDir
	defer func() { _ = logDir.Close() }()
	lock, err := serviceLockAt(stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	store, err := OpenStore(s.opts.Paths.Profiles)
	if err != nil {
		return err
	}
	s.store = store
	defer func() { _ = store.Close() }()
	if err := s.recover(s.ctx); err != nil {
		return err
	}
	control, err := s.listen(s.opts.Paths.ControlSocket, false)
	if err != nil {
		return err
	}
	defer func() { _ = control.Close() }()
	relay, err := s.listen(s.opts.Paths.PinentrySocket, true)
	if err != nil {
		return err
	}
	defer func() { _ = relay.Close() }()
	stopped := context.AfterFunc(s.ctx, func() { _ = control.Close(); _ = relay.Close() })
	defer stopped()
	failures := make(chan error, 2)
	go func() { failures <- s.accept(control.AcceptUnix, false) }()
	go func() { failures <- s.accept(relay.AcceptUnix, true) }()
	err = <-failures
	s.cancel()
	_ = control.Close()
	_ = relay.Close()
	<-failures
	s.mu.Lock()
	for c := range s.clients {
		_ = c.socket.Close()
	}
	s.mu.Unlock()
	s.workers.Wait()
	s.mu.Lock()
	actors := make([]*supervisor, 0, len(s.actors))
	for _, a := range s.actors {
		actors = append(actors, a)
	}
	s.mu.Unlock()
	for _, a := range actors {
		<-a.done
	}
	for _, a := range actors {
		if !a.idle() {
			return errors.New("helper stopped with incomplete cleanup")
		}
	}
	if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// listen creates a Unix socket after removing only an owned, disconnected stale
// socket. A live or non-socket entry is never replaced. The service lock is already
// held; production control sockets are root:fortix 0660 and relay sockets are 0600.
func (s *Server) listen(path string, private bool) (*net.UnixListener, error) {
	if err := prepareSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	mode := os.FileMode(0660)
	if private {
		mode = 0600
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if os.Geteuid() == 0 && !private {
		group, err := user.LookupGroup("fortix")
		if err != nil {
			_ = listener.Close()
			return nil, err
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			_ = listener.Close()
			return nil, err
		}
		if err := os.Chown(path, 0, gid); err != nil {
			_ = listener.Close()
			return nil, err
		}
	}
	return listener, nil
}

// accept bounds active handlers independently on each socket. Excess connections
// are closed immediately, before allocating request buffers or starting workers.
func (s *Server) accept(next func() (*net.UnixConn, error), private bool) error {
	slots := make(chan struct{}, s.opts.MaxConnections)
	delay := 5 * time.Millisecond
	for {
		socket, err := next()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.opts.Logger.Warn("socket accept failed", "error", err)
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-s.ctx.Done():
				timer.Stop()
				return s.ctx.Err()
			}
			delay = min(delay*2, time.Second)
			continue
		}
		delay = 5 * time.Millisecond
		select {
		case slots <- struct{}{}:
		default:
			_ = socket.Close()
			continue
		}
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer func() { <-slots; _ = socket.Close() }()
			stop := context.AfterFunc(s.ctx, func() { _ = socket.Close() })
			defer stop()
			if private {
				s.relay(socket)
				return
			}
			s.control(socket)
		}()
	}
}

// control authenticates the kernel peer, logs only its UID, then reads bounded
// requests. Invalid envelopes close the stream after one INVALID result; operation
// errors preserve the stream. Request payloads and credential fields are never logged.
func (s *Server) control(socket *net.UnixConn) {
	peer, err := peerCredentials(socket)
	if err != nil {
		return
	}
	s.opts.Logger.Info("control connection", "uid", peer.UID)
	c := &connection{socket: socket, open: true, events: make(chan protocol.Event, 64)}
	if err := s.opts.Authorize(peer); err != nil {
		_ = c.write(protocol.Result{Type: "result", OK: false, Error: &protocol.Error{Code: protocol.Unauthorized, Message: "peer is not authorized"}})
		return
	}
	s.mu.Lock()
	s.clients[c] = true
	s.mu.Unlock()
	done := make(chan struct{})
	pumped := make(chan struct{})
	go func() { defer close(pumped); s.pump(c, done) }()
	defer func() {
		s.detach(c)
		close(done)
		_ = socket.Close()
		<-pumped
	}()
	reader := protocol.NewReader(socket)
	for {
		deadline := time.Now().Add(s.opts.IdleTimeout)
		s.mu.Lock()
		if c.subscribed {
			deadline = time.Time{}
		}
		s.mu.Unlock()
		if err := socket.SetReadDeadline(deadline); err != nil {
			return
		}
		var request protocol.Request
		if err := reader.ReadStarted(&request, func() error {
			return socket.SetReadDeadline(time.Now().Add(s.opts.RecordTimeout))
		}); err != nil {
			var timeout net.Error
			if !errors.Is(err, io.EOF) && (!errors.As(err, &timeout) || !timeout.Timeout()) {
				_ = c.write(failure("", protocol.Invalid, "invalid request record"))
			}
			return
		}
		if err := socket.SetReadDeadline(time.Time{}); err != nil {
			return
		}
		resultID := request.ID
		if len(resultID) > 128 {
			resultID = ""
		}
		result := failure(resultID, protocol.Invalid, "invalid request arguments")
		if request.Validate() == nil {
			s.opMu.Lock()
			result = s.dispatch(c, request)
			s.opMu.Unlock()
		}
		request.Secret = ""
		clear(request.ProfileJSON)
		if err := c.write(result); err != nil {
			return
		}
	}
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
// connection for a challenge. Failed writes close the client rather than queueing
// unbounded data. No caller may hold s.mu while emitting.
func (s *Server) emit(event protocol.Event, origin *connection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.Type == "challenge" {
		if route := s.challenges[event.ChallengeID]; route != nil {
			route.event = event
			if origin != nil && origin.open {
				route.origin = origin
			}
		}
	}
	if origin != nil && origin.open {
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
		if !c.subscribed || !c.open {
			continue
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
			if !subscriber.subscribed || !subscriber.open {
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

// prepareSocket removes a stale owned socket only after a refused local connection.
// Inode comparison closes the check/remove race; all parent directories are trusted.
func prepareSocket(path string) error {
	var before unix.Stat_t
	err := unix.Lstat(path, &before)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe existing socket entry")
	}
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return errors.New("helper socket is already active")
	}
	if !errors.Is(err, unix.ECONNREFUSED) {
		return errors.New("cannot verify stale socket")
	}
	var after unix.Stat_t
	if err := unix.Lstat(path, &after); err != nil {
		return err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		return errors.New("socket entry changed")
	}
	return os.Remove(path)
}
