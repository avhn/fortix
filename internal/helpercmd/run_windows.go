// Package helpercmd dispatches Windows installation commands and the SCM service.
package helpercmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/avhn/fortix/internal/helper"
	"github.com/avhn/fortix/internal/install"
	"github.com/avhn/fortix/internal/paths"
)

// Run permits service execution only through SCM; interactive calls never start a privileged listener.
func Run(ctx context.Context, argv []string, _ io.Reader, out, diagnostics io.Writer) error {
	if len(argv) == 0 {
		return errors.New("missing executable name")
	}
	if strings.Contains(strings.ToLower(filepath.Base(argv[0])), "pinentry") {
		return errors.New("pinentry is not available on Windows")
	}
	args := argv[1:]
	if len(args) == 0 {
		service, err := svc.IsWindowsService()
		if err != nil {
			return err
		}
		if !service {
			_, err = fmt.Fprintln(out, "usage: fortix-helper install [--user NAME] | uninstall [--purge] | status")
			return err
		}
		return svc.Run(paths.HelperServiceName, &serviceHandler{ctx: ctx, run: func(ctx context.Context, ready func()) error {
			p, err := paths.Resolve(paths.Override{Service: true})
			if err != nil {
				return err
			}
			server, err := helper.New(helper.Options{Paths: p, Ready: ready, Logger: slog.New(slog.NewJSONHandler(diagnostics, nil))})
			if err != nil {
				return err
			}
			return server.Serve(ctx)
		}})
	}
	switch args[0] {
	case "install", "uninstall":
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		opts, err := installationOptions(args, executable, diagnostics)
		if err != nil {
			return err
		}
		if args[0] == "install" {
			return install.Install(ctx, opts)
		}
		return install.Uninstall(ctx, opts)
	case "status":
		if len(args) != 1 {
			return errors.New("status accepts no arguments")
		}
		status, err := install.Status(ctx)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, status)
		return err
	default:
		return errors.New("unsupported Windows helper command; pinentry, app bundles, openfortivpn and development service modes are not available")
	}
}

// serviceHandler couples SCM readiness to the actual listener and waits for cancellation cleanup.
// The injected run function owns all service resources and must return only after draining them.
type serviceHandler struct {
	ctx         context.Context
	run         func(context.Context, func()) error
	tick        time.Duration
	stopTimeout time.Duration
}

// Execute reports pending checkpoints throughout initialization and shutdown, never before readiness.
// A failed startup or incomplete drain returns a service-specific nonzero status to SCM.
func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	state := svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 10000}
	changes <- state
	go func() {
		done <- h.run(ctx, func() {
			select {
			case ready <- struct{}{}:
			default:
			}
		})
	}()
	interval := h.tick
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	stopping := false
	parent := ctx.Done()
	var drain <-chan time.Time
	var drainTimer *time.Timer
	defer func() {
		if drainTimer != nil {
			drainTimer.Stop()
		}
	}()
	// StopPending precedes cancellation so a fast drain cannot bypass the SCM transition.
	stop := func() {
		if stopping {
			return
		}
		stopping = true
		parent = nil
		state = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 10000}
		changes <- state
		timeout := h.stopTimeout
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		drainTimer = time.NewTimer(timeout)
		drain = drainTimer.C
		cancel()
	}
	for {
		select {
		case err := <-done:
			if err != nil || !stopping {
				return true, 1
			}
			return false, 0
		case <-drain:
			return true, 1
		case <-ready:
			if !stopping && ctx.Err() == nil {
				state = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				changes <- state
			}
		case request, ok := <-requests:
			if !ok {
				requests = nil
				stop()
			} else {
				switch request.Cmd {
				case svc.Interrogate:
					changes <- state
				case svc.Stop, svc.Shutdown:
					stop()
				}
			}
		case <-parent:
			stop()
		case <-ticker.C:
			if state.State == svc.StartPending || state.State == svc.StopPending {
				state.CheckPoint++
				changes <- state
			}
		}
	}
}
