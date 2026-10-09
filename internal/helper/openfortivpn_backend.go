//go:build darwin || linux

package helper

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/openfortivpn"
	"github.com/avhn/fortix/internal/session"
)

// openfortivpnBackend preserves the trusted child, relay, parser and reap lifecycle.
// The supervisor continues to own journal persistence and relay capabilities.
type openfortivpnBackend struct{ actor *supervisor }

// Start spawns one verified external process and translates its bounded output.
// Spawn failures release partial pipe resources before returning to the supervisor.
func (b openfortivpnBackend) Start(ctx context.Context, attempt backend.Attempt) (backend.Tunnel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t := &openfortivpnTunnel{actor: b.actor, events: make(chan backend.Event, 128), raw: make(chan session.Event, 128), done: make(chan struct{})}
	if err := b.actor.spawnProcess(t); err != nil {
		return nil, err
	}
	t.journal = b.actor.journal
	go t.observe()
	return t, nil
}

// openfortivpnTunnel exposes typed observations only after parser output is drained.
// Its private raw queue leaves the existing stdout/stderr scanner behavior unchanged.
type openfortivpnTunnel struct {
	actor   *supervisor
	journal Journal
	events  chan backend.Event
	raw     chan session.Event
	done    chan struct{}
	err     error
}

// Events returns the ordered external milestones and final reaped-child Outcome.
func (t *openfortivpnTunnel) Events() <-chan backend.Event { return t.events }

// Answer rejects direct credential delivery; the external child uses its private relay.
func (t *openfortivpnTunnel) Answer(context.Context, backend.Request, []byte) error {
	return errors.New("external credentials require the private relay")
}

// Stop signals only the verified process birth identity, never a reused PID.
func (t *openfortivpnTunnel) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.signal(syscall.SIGTERM)
	return nil
}

// Kill escalates shutdown only for the same verified child process group.
func (t *openfortivpnTunnel) Kill() { t.signal(syscall.SIGKILL) }

// signal authorizes a process-group signal against the kernel birth timestamp.
func (t *openfortivpnTunnel) signal(signal syscall.Signal) {
	start, err := processStart(t.journal.PID)
	if err == nil && start == t.journal.StartTime {
		_ = unix.Kill(-t.journal.PID, signal)
	}
}

// Wait reports child completion only after both pipe drains and the terminal event.
func (t *openfortivpnTunnel) Wait() error { <-t.done; return t.err }

// observe bridges parser observations without interpreting diagnostic strings.
// Pipe/log failures fail closed, but completion is emitted only after actual reaping.
func (t *openfortivpnTunnel) observe() {
	defer close(t.done)
	defer close(t.events)
	for e := range t.raw {
		switch e.Kind {
		case session.Output:
			t.events <- e.Observation
		case session.AttemptFailed:
			t.events <- backend.OutputFailed{}
		case session.ProcessExited:
			if e.ExitCode != 0 {
				t.err = errors.New("external VPN process exited unsuccessfully")
			}
			t.events <- backend.Outcome{ExitCode: e.ExitCode}
			return
		}
	}
}

// spawnProcess verifies programs, constructs the allowlisted command/environment, and starts
// a fresh process group. Pipe draining and reaping are delegated to one owned worker.
// Journal failures kill and reap the child before returning a failure to the reducer.
func (a *supervisor) spawnProcess(t *openfortivpnTunnel) error {
	a.command = nil
	a.journal = Journal{Profile: a.profile.ID, Attempt: a.state.Attempt}
	log, err := openLogAt(a.server.logDir, a.profile.ID)
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
	executable, err := a.server.verifyExecutables()
	if err != nil {
		return err
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	argv, env, err := openfortivpn.BuildCommand(a.profile, openfortivpn.Options{Executable: executable, Pinentry: a.server.opts.Paths.Pinentry, PinentrySocket: a.server.opts.Paths.PinentrySocket, AttemptToken: token})
	if err != nil {
		return err
	}
	log.protect([]byte(token))
	config, err := openfortivpn.Config(a.profile)
	if err != nil {
		return err
	}
	configR, configW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer func() { _ = configR.Close(); _ = configW.Close(); clear(config) }()
	if _, err := configW.Write(config); err != nil {
		return err
	}
	if err := configW.Close(); err != nil {
		return err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer func() { _ = outW.Close() }()
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		return err
	}
	defer func() { _ = errW.Close() }()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.ExtraFiles = []*os.File{configR}
	cmd.Env = env
	cmd.Dir = openfortivpn.WorkingDirectory
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = outW
	cmd.Stderr = errW
	a.token = token
	a.server.mu.Lock()
	a.server.tokens[token] = tokenBinding{a, a.state.Attempt}
	a.server.mu.Unlock()
	// Persist intent before spawning, then replace it with the verified birth identity.
	if err := writeJournalAt(a.server.stateDir, a.journal); err != nil {
		_ = outR.Close()
		_ = errR.Close()
		return err
	}
	if err := cmd.Start(); err != nil {
		_ = outR.Close()
		_ = errR.Close()
		return err
	}
	_ = outW.Close()
	_ = errW.Close()
	start, err := processStart(cmd.Process.Pid)
	a.journal = Journal{Profile: a.profile.ID, Attempt: a.state.Attempt, PID: cmd.Process.Pid, StartTime: start}
	if err == nil {
		err = writeJournalAt(a.server.stateDir, a.journal)
	}
	if err != nil {
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		_ = cmd.Wait()
		_ = outR.Close()
		_ = errR.Close()
		return err
	}
	a.command = cmd
	attempt := a.state.Attempt
	a.children.Add(1)
	sink := &supervisor{id: a.id, server: a.server, events: t.raw, stopped: t.done}
	go func() { defer a.children.Done(); sink.drainAndWait(cmd, outR, errR, attempt, log) }()
	return nil
}
