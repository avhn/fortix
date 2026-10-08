// Package tray coordinates desktop actions with the unprivileged helper client.
// Rendering, credentials, dialogs and filesystem paths are injected for headless tests.
package tray

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/avhn/fortix/internal/client"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/prompt"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
	"github.com/avhn/fortix/internal/session"
	"github.com/avhn/fortix/internal/tray/model"
	"github.com/avhn/fortix/internal/userconfig"
)

// Connection exposes bounded requests and helper events, never privileged execution.
// Close must unblock Events and outstanding Call operations.
type Connection interface {
	Call(context.Context, protocol.Request, any) error
	Events() <-chan protocol.Event
	Close() error
}

// View renders complete snapshots and supplies action identifiers until cancellation.
// Render must not retain or mutate the supplied snapshot. Actions never contains secrets.
type View interface {
	Render(model.Menu)
	Actions() <-chan string
}

// Options supplies desktop and transport dependencies. Dial must respect cancellation;
// Store and Dialog must not log secrets. Report receives only fixed diagnostic messages.
type Options struct {
	Paths       paths.Paths
	View        View
	Dial        func(context.Context) (Connection, error)
	Store       secrets.Store
	Dialog      prompt.Dialog
	Notify      func(context.Context, string, string) error
	OpenLog     func(context.Context, string, []string) error
	Save        func(context.Context, paths.Paths, userconfig.Config) error
	Report      func(string)
	Preferences userconfig.Config
}

// controller owns all mutable UI state in one goroutine; prompt workers send results.
type controller struct {
	options       Options
	profiles      []model.Profile
	attempts      map[string]uint64
	started       map[string]uint64
	keys          map[string]string
	reachable     bool
	bypassKeyring map[string]bool
	helperIssue   string
	lastReport    string
}

// entry decodes the helper's profile-list response without importing root-side code.
type entry struct {
	Profile string `json:"profile"`
	State   string `json:"state"`
}

// status decodes session generations used to reject replies from obsolete attempts.
type status struct {
	Profile        string `json:"profile"`
	State          string `json:"state"`
	Attempt        uint64 `json:"attempt"`
	Wanted         bool   `json:"wanted"`
	Initiated      bool   `json:"initiated"`
	CleanupPending bool   `json:"cleanup_pending"`
}

// task binds a dialog to one connection and attempt. Its context cancels obsolete UI.
type task struct {
	ctx           context.Context
	event         protocol.Event
	bypassKeyring bool
	key           string
}

// response carries a private dialog result back to the controller, never to logs.
type response struct {
	ctx       context.Context
	event     protocol.Event
	secret    string
	confirmed bool
	save      bool
	human     bool
	keyring   bool
	key       string
	err       error
}

// Run maintains snapshots and reconnects with capped backoff after helper restarts.
// Quit and context cancellation close the client and join the prompt worker. Startup
// dependency errors return immediately; runtime errors are sanitized and reported.
func Run(ctx context.Context, options Options) error {
	if options.View == nil || options.Dial == nil || options.Store == nil || options.Dialog == nil {
		return errors.New("tray requires view, client, keyring and dialogs")
	}
	if options.Save == nil {
		options.Save = userconfig.Save
	}
	if options.Report == nil {
		options.Report = func(string) {}
	}
	c := controller{options: options, attempts: make(map[string]uint64), started: make(map[string]uint64), keys: make(map[string]string), bypassKeyring: make(map[string]bool)}
	delay := time.Second
	for ctx.Err() == nil {
		c.reachable = false
		c.render()
		conn, err := c.options.Dial(ctx)
		if err == nil {
			c.reachable = true
			quit, healthy := c.connected(ctx, conn)
			_ = conn.Close()
			if quit {
				return nil
			}
			if healthy {
				delay = time.Second
			}
		}
		if ctx.Err() != nil {
			break
		}
		c.reachable = false
		c.render()
		if err != nil || c.helperIssue == "" {
			c.helperFailure(err)
		}
		timer := time.NewTimer(delay)
		waiting := true
		for waiting {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
				waiting = false
			case action, ok := <-c.options.View.Actions():
				if !ok || action == "quit" {
					timer.Stop()
					return nil
				}
				c.localAction(ctx, action)
			}
		}
		delay = min(delay*2, 30*time.Second)
	}
	return nil
}

// render derives aggregate icon and menu state without exposing private prompt data.
func (c *controller) render() {
	menu := model.Build(c.profiles, c.reachable, model.Preferences{AnimateIcon: c.options.Preferences.AnimateIcon})
	for i := range menu.Items {
		if menu.Items[i].ID == "open_logs" {
			menu.Items[i].Enabled = c.reachable
		}
	}
	if !c.reachable && c.helperIssue != "" {
		menu.Items[0].Title = c.helperIssue
		menu.Tooltip = strings.Replace(menu.Tooltip, "Helper not running", c.helperIssue, 1)
	}
	c.options.View.Render(menu)
}

// helperFailure classifies unavailable versus unauthorized helper connections and
// reports a fixed diagnostic only when that condition changes. Raw errors stay private.
func (c *controller) helperFailure(err error) {
	message := "Helper unavailable; retrying"
	var rejected *client.OperationError
	if errors.Is(err, os.ErrPermission) || (errors.As(err, &rejected) && rejected.Code == protocol.Unauthorized) {
		message = "Not in the fortix group, log out and back in"
	}
	c.helperIssue = message
	if message != c.lastReport {
		c.options.Report(message)
		c.lastReport = message
	}
	c.render()
}

// call bounds one request to ten seconds; transport and helper errors remain internal.
func call(ctx context.Context, conn Connection, request protocol.Request, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Call(ctx, request, out)
}

// refresh loads profile names, endpoint-bound keys and current helper intent.
// Snapshots replace stale wanted state, including sessions started from the CLI.
func (c *controller) refresh(ctx context.Context, conn Connection, pending map[string]context.CancelFunc) error {
	var entries []entry
	if err := call(ctx, conn, protocol.Request{Op: "profile.list"}, &entries); err != nil {
		return err
	}
	var states []status
	if err := call(ctx, conn, protocol.Request{Op: "status"}, &states); err != nil {
		return err
	}
	old := make(map[string]model.Profile, len(c.profiles))
	for _, p := range c.profiles {
		old[p.ID] = p
	}
	next := make([]model.Profile, 0, len(entries))
	for _, e := range entries {
		if !profile.ValidID(e.Profile) {
			return errors.New("invalid helper profile ID")
		}
		p := old[e.Profile]
		p.ID, p.State = e.Profile, session.Phase(e.State)
		var config profile.Profile
		if err := call(ctx, conn, protocol.Request{Op: "profile.get", Profile: e.Profile}, &config); err != nil {
			return err
		}
		p.Name = config.Name
		if c.keys == nil {
			c.keys = make(map[string]string)
		}
		c.keys[p.ID] = secrets.Key(&config)
		p.Wanted = false
		p.CleanupPending = false
		for _, s := range states {
			if s.Profile == p.ID {
				p.State = session.Phase(s.State)
				p.Wanted, p.CleanupPending = s.Wanted, s.CleanupPending
				if s.Initiated && c.started[p.ID] != 0 && s.Attempt > c.started[p.ID] {
					c.started[p.ID] = s.Attempt
				}
				c.attempts[p.ID] = s.Attempt
				if pending[p.ID] == nil {
					p.PendingPassword = p.State == session.WaitingPassword || p.State == session.WaitingCode || p.State == session.WaitingTrust
				}
				break
			}
		}
		next = append(next, p)
	}
	c.profiles = next
	c.render()
	return nil
}

// connected subscribes before fetching snapshots so challenges cannot be lost.
// Prompt work is serialized off the event reader and cancelled on transport loss.
func (c *controller) connected(ctx context.Context, conn Connection) (quit, healthy bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := range c.profiles {
		c.profiles[i].PendingPassword = false
	}
	tasks, replies := make(chan task, 32), make(chan response)
	done := make(chan struct{})
	go func() { defer close(done); c.prompts(ctx, tasks, replies) }()
	defer func() { cancel(); <-done }()
	pending := make(map[string]context.CancelFunc)
	credentials := make(map[string]response)
	defer func() {
		for _, stop := range pending {
			stop()
		}
	}()
	if err := call(ctx, conn, protocol.Request{Op: "subscribe"}, nil); err != nil {
		c.helperFailure(err)
		return false, false
	}
	if err := c.refresh(ctx, conn, pending); err != nil {
		c.helperFailure(err)
		return false, false
	}
	c.helperIssue, c.lastReport = "", ""
	healthy = true
	poll := time.NewTicker(5 * time.Second)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, healthy
		case <-poll.C:
			if err := c.refresh(ctx, conn, pending); err != nil {
				c.helperFailure(err)
				return false, healthy
			}
		case action, ok := <-c.options.View.Actions():
			if !ok || action == "quit" {
				return true, healthy
			}
			if c.localAction(ctx, action) {
				continue
			}
			if err := c.action(ctx, conn, action); err != nil {
				c.options.Report("VPN action failed")
			}
			c.render()
		case e, ok := <-conn.Events():
			if !ok {
				return false, healthy
			}
			p := c.find(e.Profile)
			if p == nil && profile.ValidID(e.Profile) {
				if err := c.refresh(ctx, conn, pending); err != nil {
					c.helperFailure(err)
					return false, healthy
				}
				p = c.find(e.Profile)
			}
			if p == nil || e.Attempt < c.attempts[e.Profile] {
				continue
			}
			if (e.Type == "challenge" || e.Type == "cert") && c.started[e.Profile] != e.Attempt {
				continue
			}
			if e.Type == "state" && e.Initiated && c.started[e.Profile] != 0 && e.Attempt > c.started[e.Profile] {
				c.started[e.Profile] = e.Attempt
			}
			if e.Attempt > c.attempts[e.Profile] {
				if stop := pending[e.Profile]; stop != nil {
					stop()
					delete(pending, e.Profile)
				}
				delete(credentials, e.Profile)
				p.PendingPassword = false
			}
			switch e.Type {
			case "state":
				previous := p.State
				c.attempts[e.Profile], p.State = e.Attempt, session.Phase(e.State)
				p.Wanted = e.Wanted
				p.CleanupPending = e.CleanupPending
				if p.State != session.WaitingPassword && p.State != session.WaitingCode && p.State != session.WaitingTrust {
					if stop := pending[e.Profile]; stop != nil {
						stop()
						delete(pending, e.Profile)
					}
					p.PendingPassword = false
				}
				if p.State == session.Failed {
					if saved, ok := credentials[p.ID]; ok && saved.keyring && saved.event.Attempt == e.Attempt {
						c.bypassKeyring[p.ID] = true
					}
				}
				if p.State == session.Connected {
					if saved, ok := credentials[p.ID]; ok && saved.event.Attempt == e.Attempt && saved.save && c.options.Preferences.RememberPasswords {
						if c.options.Store.Set(saved.key, saved.secret) != nil {
							c.options.Report("Password could not be saved in the keyring")
						} else {
							delete(c.bypassKeyring, p.ID)
						}
					}
				}
				if p.State == session.Connected || p.State == session.Failed || p.State == session.Disconnected {
					delete(credentials, p.ID)
				}
				if p.State == session.Disconnected {
					delete(c.started, p.ID)
				}
				c.render()
				if previous != p.State {
					c.notify(ctx, p)
				}
			case "challenge", "cert":
				c.attempts[e.Profile] = e.Attempt
				if stop := pending[e.Profile]; stop != nil {
					stop()
				}
				taskCtx, stop := context.WithTimeout(ctx, 120*time.Second)
				pending[e.Profile] = stop
				p.PendingPassword = false
				c.render()
				select {
				case tasks <- task{ctx: taskCtx, event: e, bypassKeyring: c.bypassKeyring[e.Profile], key: c.keys[e.Profile]}:
				default:
					stop()
					c.options.Report("Too many pending VPN prompts")
				}
			}
		case r := <-replies:
			p := c.find(r.event.Profile)
			if r.ctx.Err() != nil || p == nil || r.event.Attempt != c.attempts[r.event.Profile] || pending[p.ID] == nil {
				continue
			}
			if r.human {
				p.PendingPassword = true
				c.render()
				continue
			}
			pending[p.ID]()
			delete(pending, p.ID)
			p.PendingPassword = false
			if r.event.Type == "cert" {
				if r.err == nil && r.confirmed && p.State == session.WaitingTrust {
					if call(ctx, conn, protocol.Request{Op: "trust", Profile: p.ID, Digest: r.event.Digest}, nil) == nil {
						if c.up(ctx, conn, p) != nil {
							c.options.Report("VPN connection failed after certificate trust")
						}
					} else {
						c.options.Report("Certificate trust failed")
					}
				}
			} else {
				request := protocol.Request{Op: "cancel", ChallengeID: r.event.ChallengeID}
				if r.err == nil {
					request.Op, request.Secret = "answer", r.secret
				}
				if err := call(ctx, conn, request, nil); err != nil {
					c.options.Report("VPN prompt response was not accepted")
				} else if r.err == nil && (r.save || r.keyring) {
					// Retain password provenance only until this attempt succeeds or ends.
					credentials[p.ID] = r
				}
			}
			c.render()
		}
	}
}

// find returns controller-owned profile state, or nil for unknown menu/event IDs.
func (c *controller) find(id string) *model.Profile {
	for i := range c.profiles {
		if c.profiles[i].ID == id {
			return &c.profiles[i]
		}
	}
	return nil
}

// prompts resolves passwords from the OS keyring before using a hidden native
// dialog. Codes are always prompted and never saved; certificate text is literal.
func (c *controller) prompts(ctx context.Context, tasks <-chan task, replies chan<- response) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-tasks:
			if t.ctx.Err() != nil {
				continue
			}
			e := t.event
			r := response{ctx: t.ctx, event: e, key: t.key}
			if e.Type == "cert" {
				r.confirmed, r.err = c.options.Dialog.Confirm(t.ctx, "fortix certificate", fmt.Sprintf("Profile: %s\nSHA-256: %s\nSubject: %q\nIssuer: %q\nTrust this certificate and connect?", e.Profile, e.Digest, certificateText(e.Subject), certificateText(e.Issuer)))
			} else {
				if e.Kind == "password" && !t.bypassKeyring {
					r.secret, r.err = c.options.Store.Get(t.key)
					r.keyring = r.err == nil
				} else {
					r.err = secrets.ErrNotFound
				}
				if r.err != nil {
					// Only a human dialog needs attention; keyring lookup is not a prompt.
					select {
					case replies <- response{ctx: t.ctx, event: e, human: true}:
					case <-ctx.Done():
						return
					case <-t.ctx.Done():
						continue
					}
					r.secret, r.err = c.options.Dialog.Password(t.ctx, "fortix: "+e.Profile, e.Prompt)
					r.save = e.Kind == "password" && r.err == nil
				}
			}
			if t.ctx.Err() != nil {
				continue
			}
			select {
			case replies <- r:
			case <-ctx.Done():
				return
			case <-t.ctx.Done():
			}
		}
	}
}

// localAction changes user preferences atomically, even while the helper is down.
// A failed save leaves the live preference unchanged and reports a fixed message.
func (c *controller) localAction(ctx context.Context, action string) bool {
	if action != "animate_icon" {
		return false
	}
	next := c.options.Preferences
	next.AnimateIcon = !next.AnimateIcon
	if c.options.Save(ctx, c.options.Paths, next) != nil {
		c.options.Report("Icon preference could not be saved")
	} else {
		c.options.Preferences = next
	}
	c.render()
	return true
}

// up records desired connectivity only after the helper accepts an attempt.
func (c *controller) up(ctx context.Context, conn Connection, p *model.Profile) error {
	var result struct {
		Attempt        uint64 `json:"attempt"`
		Wanted         bool   `json:"wanted"`
		Initiated      bool   `json:"initiated"`
		CleanupPending bool   `json:"cleanup_pending"`
	}
	if err := call(ctx, conn, protocol.Request{Op: "up", Profile: p.ID}, &result); err != nil {
		return err
	}
	p.Wanted, p.State = true, session.Starting
	c.attempts[p.ID] = result.Attempt
	if c.started == nil {
		c.started = make(map[string]uint64)
	}
	c.started[p.ID] = result.Attempt
	return nil
}

// action toggles individual profiles or all eligible profiles and opens only
// known profile logs. No desktop action can supply a command or arbitrary path.
func (c *controller) action(ctx context.Context, conn Connection, action string) error {
	if strings.HasPrefix(action, "forget:") {
		id := strings.TrimPrefix(action, "forget:")
		if c.find(id) == nil || !profile.ValidID(id) {
			return errors.New("unknown password profile")
		}
		err := c.options.Store.Delete(c.keys[id])
		if errors.Is(err, secrets.ErrNotFound) {
			err = nil
		}
		if err == nil {
			c.bypassKeyring[id] = true
		}
		return err
	}
	if strings.HasPrefix(action, "logs:") {
		id := strings.TrimPrefix(action, "logs:")
		if c.find(id) == nil || !profile.ValidID(id) {
			return errors.New("unknown log profile")
		}
		if c.options.OpenLog != nil {
			var lines []string
			if err := call(ctx, conn, protocol.Request{Op: "logs", Profile: id, Lines: 500}, &lines); err != nil {
				return err
			}
			return c.options.OpenLog(ctx, id, lines)
		}
		return nil
	}
	if action == "disconnect_all" {
		if err := call(ctx, conn, protocol.Request{Op: "down", All: true}, nil); err != nil {
			return err
		}
		for i := range c.profiles {
			c.profiles[i].Wanted = false
		}
		return nil
	}
	if action == "connect_all" {
		var failures []error
		for i := range c.profiles {
			p := &c.profiles[i]
			if p.State == session.Disconnected || p.State == session.Failed {
				failures = append(failures, c.up(ctx, conn, p))
			}
		}
		return errors.Join(failures...)
	}
	if strings.HasPrefix(action, "profile:") {
		p := c.find(strings.TrimPrefix(action, "profile:"))
		if p == nil {
			return errors.New("unknown profile")
		}
		if p.State == session.Disconnected || (p.State == session.Failed && !p.CleanupPending) {
			return c.up(ctx, conn, p)
		}
		if err := call(ctx, conn, protocol.Request{Op: "down", Profile: p.ID}, nil); err != nil {
			return err
		}
		p.Wanted = false
	}
	return nil
}

// notify emits only profile/state messages, never helper diagnostics or secrets.
// Notification failures are optional desktop failures and do not stop the tunnel.
func (c *controller) notify(ctx context.Context, p *model.Profile) {
	if !c.options.Preferences.Notifications || c.options.Notify == nil {
		return
	}
	if p.State != session.Connected && p.State != session.Disconnected && p.State != session.Failed {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if c.options.Notify(ctx, "fortix", p.Name+": "+string(p.State)) != nil {
		c.options.Report("Desktop notification unavailable")
	}
}

// certificateText caps untrusted certificate identities before quoting for display.
// A rune boundary preserves valid text while keeping oversized subjects readable.
func certificateText(text string) string {
	const limit = 256
	runes := []rune(text)
	if len(runes) > limit {
		return string(runes[:limit]) + "..."
	}
	return text
}
