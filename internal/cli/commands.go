// Package cli implements helper-backed commands with secure, attempt-bound credential handling.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/client"
	"github.com/avhn/fortix/internal/importer"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/prompt"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
	"github.com/avhn/fortix/internal/userconfig"
)

// Prompter obtains credentials and explicit consent without exposing secret responses.
// Password must hide input unless stdinLine is explicitly enabled by the caller.
type Prompter interface {
	Password(context.Context, string, bool) (string, error)
	Confirm(context.Context, string) (bool, error)
}

// Options injects socket, preferences, keyring, prompts, and plist conversion for unprivileged tests.
// Nil dependencies use platform implementations; Config bypasses preference loading when supplied.
type Options struct {
	Client    client.Options
	Paths     paths.Override
	Secrets   secrets.Store
	Prompt    Prompter
	Config    *userconfig.Config
	Converter importer.Converter
	Input     *os.File // Input supplies shared JSON and completion fields; nil uses stdin.
}

// command holds validated CLI syntax and non-secret option values for one invocation.
type command struct {
	name                                      string
	ids                                       []string
	all, json, save, yes, apply               bool
	plist                                     string
	output, username, id, nameOverride, merge string
	force                                     bool
	lines                                     int
}

// errFlagParse marks syntax errors already diagnosed by the command flag set.
var errFlagParse = errors.New("flags already diagnosed")

// credential holds a password only for the generation that accepted its answer.
// Keyring passwords are tracked for recovery hints; prompted values wait for connection success.
type credential struct {
	attempt uint64
	secret  string
	keyring bool
	key     string
}

// runner carries invocation-local context, streams, dependencies, and socket ownership.
type runner struct {
	ctx         context.Context
	out, errout io.Writer
	options     Options
	conn        *client.Client
	credentials map[string]credential
}

// RunContext executes one command, returning 0 for success/help, 1 for failure, or 2 for usage.
// It never starts a privileged subprocess; all VPN mutations are typed helper operations.
func RunContext(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	if len(args) > 0 && (args[0] == "version" || (len(args) > 1 && args[0] == "profile" && args[1] == "validate")) {
		code := runLocal(args, stdout, stderr)
		if code == -1 {
			return 0
		}
		return code
	}
	cmd, err := parseCommand(args, stderr, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		if !errors.Is(err, errFlagParse) {
			_, _ = fmt.Fprintln(stderr, err)
			_ = usage(stderr)
		}
		return 2
	}
	r := runner{ctx: ctx, out: stdout, errout: stderr, options: options}
	if r.options.Secrets == nil {
		r.options.Secrets = secrets.Keyring{}
	}
	if r.options.Prompt == nil {
		r.options.Prompt = prompt.Terminal{Input: options.Input, Output: stderr}
	}
	if err := r.execute(cmd); err != nil {
		return diagnostic(stderr, err)
	}
	return 0
}

// parseCommand validates each command's flags and argument count before any side effects.
// Unknown flags, missing operands, and mutually exclusive selectors are usage errors.
func parseCommand(args []string, output, helpOutput io.Writer) (command, error) {
	c := command{lines: 100}
	if len(args) == 0 {
		return c, errors.New("missing command")
	}
	c.name = args[0]
	rest := args[1:]
	if c.name == "profile" || c.name == "password" || c.name == "import" {
		if len(rest) == 0 {
			return c, errors.New("missing subcommand")
		}
		if rest[0] == "-h" || rest[0] == "--help" {
			_ = usage(helpOutput)
			return c, flag.ErrHelp
		}
		c.name += " " + rest[0]
		rest = rest[1:]
	}
	if c.name == "profile remove" {
		c.name = "profile rm"
	}
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(output)
	count := 1
	syntax := "<id>"
	switch c.name {
	case "up", "down":
		count = -1
		syntax = "<id>... | --all"
		fs.BoolVar(&c.all, "all", false, "select all stored profiles")
		if c.name == "up" {
			fs.BoolVar(&c.save, "save", false, "save prompted passwords in the secure keyring")
		}
	case "status":
		count = 0
		syntax = "[--json]"
		fs.BoolVar(&c.json, "json", false, "print the helper snapshot as JSON")
	case "profile list":
		count = 0
		syntax = ""
	case "profile show", "profile rm", "password set", "password clear":
	case "profile add":
		syntax = "<file>"
	case "profile export":
		count = -1
		syntax = "<id>... [-o FILE] [--force]"
		fs.StringVar(&c.output, "o", "", "write shared JSON to FILE instead of stdout")
		fs.BoolVar(&c.force, "force", false, "replace an existing export file")
	case "profile import":
		syntax = "FILE [--username NAME] [--id ID] [--name NAME] [--merge ID] [--yes]"
		fs.StringVar(&c.username, "username", "", "personal username for new profiles")
		fs.StringVar(&c.id, "id", "", "override the single shared profile id")
		fs.StringVar(&c.nameOverride, "name", "", "override the single shared profile name")
		fs.StringVar(&c.merge, "merge", "", "merge into an existing profile, keeping its username")
		fs.BoolVar(&c.yes, "yes", false, "confirm displayed shared certificate pins without prompting")
	case "logs":
		fs.IntVar(&c.lines, "lines", 100, "number of redacted lines (1 to 500)")
	case "trust":
		fs.BoolVar(&c.yes, "yes", false, "confirm the displayed certificate without prompting")
	case "import forticlient":
		count = 0
		syntax = "[--plist path] [--apply]"
		fs.StringVar(&c.plist, "plist", importer.DefaultPath, "FortiClient plist to read without changing it")
		fs.BoolVar(&c.apply, "apply", false, "install the displayed drafts through the helper")
	case "-h", "--help":
		_ = usage(helpOutput)
		return c, flag.ErrHelp
	default:
		return c, errors.New("unknown command")
	}
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(&flagOutput, "usage: fortix %s %s\n", c.name, syntax)
		fs.PrintDefaults()
		if c.name == "trust" {
			_, _ = fmt.Fprintln(&flagOutput, "Capture a fresh certificate rejection, display its identity, and confirm the pin. A rejected attempt is restarted; active tunnels are not interrupted.")
		}
	}
	ordered, err := orderFlags(rest, fs)
	if err != nil {
		return c, err
	}
	if err := fs.Parse(ordered); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(helpOutput, &flagOutput)
			return c, err
		}
		_, _ = io.Copy(output, &flagOutput)
		return c, errors.Join(errFlagParse, err)
	}
	c.ids = fs.Args()
	if count >= 0 && len(c.ids) != count {
		return c, errors.New("incorrect argument count")
	}
	if count == -1 && ((c.all && len(c.ids) != 0) || (!c.all && len(c.ids) == 0)) {
		return c, errors.New("choose ids or --all")
	}
	if (c.id != "" && !profile.ValidID(c.id)) || (c.merge != "" && !profile.ValidID(c.merge)) {
		return c, errors.New("invalid import profile id")
	}
	if c.merge != "" && c.id != "" && c.id != c.merge {
		return c, errors.New("--id must match --merge")
	}
	if c.lines < 1 || c.lines > 500 {
		return c, errors.New("lines must be between 1 and 500")
	}
	if count == -1 || strings.HasSuffix(c.name, " show") || strings.HasSuffix(c.name, " rm") || strings.HasPrefix(c.name, "password ") || c.name == "trust" || c.name == "logs" {
		seen := make(map[string]bool)
		for _, id := range c.ids {
			if !profile.ValidID(id) {
				return c, fmt.Errorf("invalid profile id %q", id)
			}
			if seen[id] {
				return c, fmt.Errorf("duplicate profile id %q", id)
			}
			seen[id] = true
		}
	}
	return c, nil
}

// orderFlags permits documented flags before or after operands while preserving -- semantics.
// Value flags consume exactly one following argument; unknown flags are left for flag diagnostics.
func orderFlags(args []string, fs *flag.FlagSet) ([]string, error) {
	var flags, operands []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			operands = append(operands, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			operands = append(operands, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		f := fs.Lookup(name)
		if f == nil || hasValue {
			continue
		}
		boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
		if ok && boolean.IsBoolFlag() {
			continue
		}
		i++
		if i == len(args) {
			return nil, errors.New("missing flag value")
		}
		flags = append(flags, args[i])
	}
	return append(append(flags, "--"), operands...), nil
}

// connect opens one authenticated helper connection with a bounded handshake.
func (r *runner) connect() error {
	options := r.options.Client
	options.DiscardLogs = true
	conn, err := client.Dial(r.ctx, options)
	if err != nil {
		return err
	}
	r.conn = conn
	return nil
}

// call bounds each helper response wait to ten seconds and preserves the invocation context.
func (r *runner) call(request protocol.Request, dst any) error {
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	return r.conn.Call(ctx, request, dst)
}

// execute routes local secrets/import previews separately from helper-backed operations.
// The connection is closed on all paths; output and storage failures propagate as failure status.
func (r *runner) execute(c command) error {
	if strings.HasPrefix(c.name, "password ") {
		return r.password(c)
	}
	if c.name == "import forticlient" {
		return r.importProfiles(c)
	}
	if c.name == "profile import" {
		return r.importShared(c)
	}
	// Decode before dialing so malformed local files are reported even when the helper is offline.
	var data json.RawMessage
	if c.name == "profile add" {
		p, err := readProfile(c.ids[0])
		if err != nil {
			return err
		}
		data, err = json.Marshal(p)
		if err != nil {
			return err
		}
	}
	if err := r.connect(); err != nil {
		return err
	}
	defer func() { _ = r.conn.Close() }()
	switch c.name {
	case "status":
		return r.status(c.json)
	case "profile list":
		var entries []profileState
		if err := r.call(protocol.Request{Op: "profile.list"}, &entries); err != nil {
			return err
		}
		if len(entries) == 0 {
			_, err := fmt.Fprintln(r.errout, "no profiles")
			return err
		}
		for _, entry := range entries {
			if _, err := fmt.Fprintf(r.out, "%s\t%s\n", entry.Profile, entry.State); err != nil {
				return err
			}
		}
		return nil
	case "profile export":
		return r.exportShared(c)
	case "profile show":
		var p json.RawMessage
		if err := r.call(protocol.Request{Op: "profile.get", Profile: c.ids[0]}, &p); err != nil {
			return err
		}
		return writeJSON(r.out, p)
	case "profile add":
		return r.call(protocol.Request{Op: "profile.put", ProfileJSON: data}, nil)
	case "profile rm":
		return r.call(protocol.Request{Op: "profile.delete", Profile: c.ids[0]}, nil)
	case "down":
		return r.down(c)
	case "logs":
		var lines []string
		if err := r.call(protocol.Request{Op: "logs", Profile: c.ids[0], Lines: c.lines}, &lines); err != nil {
			return err
		}
		for _, line := range lines {
			if _, err := fmt.Fprintln(r.out, line); err != nil {
				return err
			}
		}
		return nil
	case "up", "trust":
		return r.up(c)
	}
	return errors.New("unknown command")
}

// readProfile decodes a strict profile from a file and propagates open, read, and close failures.
func readProfile(path string) (*profile.Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	p, err := profile.Decode(f)
	return p, errors.Join(err, f.Close())
}

// writeJSON emits an indented non-secret value, reporting serialization and output errors.
func writeJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

// profileState is the helper's public profile-list entry, not a full stored profile.
type profileState struct {
	Profile string `json:"profile"`
	State   string `json:"state"`
}

// statusEntry decodes every status field without importing privileged helper implementation.
type statusEntry struct {
	Wanted         bool      `json:"wanted"`
	Initiated      bool      `json:"initiated"`
	CleanupPending bool      `json:"cleanup_pending"`
	Profile        string    `json:"profile"`
	State          string    `json:"state"`
	Detail         string    `json:"detail"`
	Attempt        uint64    `json:"attempt"`
	Interface      string    `json:"interface"`
	LocalIP        string    `json:"local_ip"`
	Since          time.Time `json:"since"`
}

// status prints the full snapshot as JSON or the requested human-readable table.
func (r *runner) status(asJSON bool) error {
	var entries []statusEntry
	if err := r.call(protocol.Request{Op: "status"}, &entries); err != nil {
		return err
	}
	if asJSON {
		return writeJSON(r.out, entries)
	}
	table := tabwriter.NewWriter(r.out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "PROFILE\tSTATE\tINTERFACE\tLOCAL IP\tSINCE\tDETAIL"); err != nil {
		return err
	}
	for _, entry := range entries {
		since := "-"
		if !entry.Since.IsZero() {
			since = entry.Since.Format(time.RFC3339)
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", entry.Profile, entry.State, entry.Interface, entry.LocalIP, since, entry.Detail); err != nil {
			return err
		}
	}
	return table.Flush()
}

// password sets or clears only an OS keyring entry, never a profile file or helper secret.
// Setting requires a hidden terminal prompt; clearing a missing entry is idempotent.
func (r *runner) password(c command) error {
	id := c.ids[0]
	if err := r.connect(); err != nil {
		return err
	}
	defer func() { _ = r.conn.Close() }()
	key, err := r.credentialKey(id)
	if err != nil {
		return err
	}
	if c.name == "password clear" {
		err := r.options.Secrets.Delete(key)
		if errors.Is(err, secrets.ErrNotFound) {
			return nil
		}
		return err
	}
	password, err := r.options.Prompt.Password(r.ctx, "Password for "+id+": ", false)
	if err != nil {
		if errors.Is(err, prompt.ErrUnavailable) {
			return fmt.Errorf("password set needs an interactive terminal: %w", err)
		}
		return err
	}
	return r.options.Secrets.Set(key, password)
}

// importProfiles prints secret-free drafts and optionally installs them over the socket.
// Conversion and validation finish before any mutation; helper rejection stops further writes.
func (r *runner) importProfiles(c command) error {
	drafts, warnings, err := importer.Import(r.ctx, c.plist, r.options.Converter)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		if _, err := fmt.Fprintln(r.errout, warning); err != nil {
			return err
		}
	}
	if err := writeJSON(r.out, drafts); err != nil {
		return err
	}
	if !c.apply || len(drafts) == 0 {
		return nil
	}
	if err := r.connect(); err != nil {
		return err
	}
	defer func() { _ = r.conn.Close() }()
	for _, draft := range drafts {
		data, err := json.Marshal(draft)
		if err != nil {
			return err
		}
		if err := r.call(protocol.Request{Op: "profile.put", ProfileJSON: data}, nil); err != nil {
			return err
		}
	}
	return nil
}

// preferences resolves secure user configuration only when credentials could be prompted.
// Malformed or insecure preferences are errors rather than silently enabling password storage.
func (r *runner) preferences() (userconfig.Config, error) {
	if r.options.Config != nil {
		return *r.options.Config, nil
	}
	p, err := paths.Resolve(r.options.Paths)
	if err != nil {
		return userconfig.Config{}, err
	}
	return userconfig.Load(r.ctx, p)
}

// answer uses the keyring only for password challenges; codes always require hidden input.
// Prompt cancellation stops the challenge and attempt; passwords are saved only after connection success.
func (r *runner) answer(event protocol.Event, save bool) error {
	var secret string
	var err error
	prompted := false
	key := ""
	switch event.Kind {
	case "password":
		key, err = r.credentialKey(event.Profile)
		if err != nil {
			return err
		}
		secret, err = r.options.Secrets.Get(key)
		if err != nil && !errors.Is(err, secrets.ErrNotFound) && !errors.Is(err, secrets.ErrUnavailable) {
			return err
		}
		if err == nil {
			break
		}
		fallthrough
	case "code":
		prompted = true
		secret, err = r.options.Prompt.Password(r.ctx, event.Kind+" for "+event.Profile+": ", false)
	default:
		return errors.New("helper sent an unknown credential challenge")
	}
	if err != nil {
		r.cancelAttempt(event)
		return err
	}
	if err := r.call(protocol.Request{Op: "answer", ChallengeID: event.ChallengeID, Secret: secret}, nil); err != nil {
		return err
	}
	if event.Kind == "password" {
		if r.credentials == nil {
			r.credentials = make(map[string]credential)
		}
		value := credential{attempt: event.Attempt, keyring: !prompted, key: key}
		if prompted && save {
			value.secret = secret
		}
		r.credentials[event.Profile] = value
	}
	return nil
}

// cancelAttempt sends challenge cancellation and stops the profile even after invocation cancellation.
// Cleanup has its own short deadline; failures warn that the helper may still be running the attempt.
func (r *runner) cancelAttempt(event protocol.Event) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 2*time.Second)
	defer cancel()
	cancelErr := r.conn.Call(ctx, protocol.Request{Op: "cancel", ChallengeID: event.ChallengeID}, nil)
	downErr := r.conn.Call(ctx, protocol.Request{Op: "down", Profile: event.Profile}, nil)
	if downErr != nil {
		_, _ = fmt.Fprintf(r.errout, "%s: attempt left running; use fortix down %s (%v)\n", event.Profile, event.Profile, errors.Join(cancelErr, downErr))
	}
}

// finishCredential releases an attempt's retained password on its terminal state.
// Only a matching connected generation is saved; failed keyring authentication gets a recovery hint.
func (r *runner) finishCredential(event protocol.Event) error {
	value, ok := r.credentials[event.Profile]
	if !ok || value.attempt != event.Attempt {
		return nil
	}
	delete(r.credentials, event.Profile)
	if event.State == "connected" && value.secret != "" {
		if err := r.options.Secrets.Set(value.key, value.secret); err != nil {
			_, outputErr := fmt.Fprintf(r.errout, "password not saved: %s\n", err)
			return outputErr
		}
	}
	if event.State == "failed" && event.Code == backend.AuthenticationFailedCode && value.keyring {
		_, err := fmt.Fprintf(r.errout, "%s: saved password may be incorrect; run fortix password clear %s before retrying\n", event.Profile, event.Profile)
		return err
	}
	return nil
}

// certificate prints the rejected certificate and sends only explicitly confirmed trust.
// Declining returns a failure and leaves the stored pin unchanged.
func (r *runner) certificate(event protocol.Event, trust, yes bool) error {
	if _, err := fmt.Fprintf(r.out, "%s: certificate rejected\nSHA256: %q\nSubject: %q\nIssuer: %q\n", event.Profile, event.Digest, event.Subject, event.Issuer); err != nil {
		return err
	}
	if !trust {
		return fmt.Errorf("%s: certificate requires confirmation; run fortix trust %s", event.Profile, event.Profile)
	}
	if !yes {
		confirmed, err := r.options.Prompt.Confirm(r.ctx, "Trust this certificate for "+event.Profile+"?")
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("certificate trust declined")
		}
	}
	return r.call(protocol.Request{Op: "trust", Profile: event.Profile, Digest: event.Digest}, nil)
}

// up subscribes before starting selected attempts and waits for their terminal outcomes.
// Generations filter unrelated events; an initial status snapshot covers already-connected profiles.
// Trust recaptures a rejected certificate because the protocol has no certificate snapshot operation.
func (r *runner) up(c command) error {
	cfg, err := r.preferences()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Minute)
	defer cancel()
	r.ctx = ctx
	if err := r.call(protocol.Request{Op: "subscribe"}, nil); err != nil {
		return err
	}
	ids := c.ids
	if c.all {
		var list []profileState
		if err := r.call(protocol.Request{Op: "profile.list"}, &list); err != nil {
			return err
		}
		for _, entry := range list {
			ids = append(ids, entry.Profile)
		}
	}
	if len(ids) == 0 {
		_, err := fmt.Fprintln(r.errout, "no profiles")
		return err
	}
	if c.name == "trust" {
		var entries []statusEntry
		if err := r.call(protocol.Request{Op: "status"}, &entries); err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Profile != ids[0] {
				continue
			}
			if entry.State == "waiting_trust" {
				if err := r.call(protocol.Request{Op: "down", Profile: ids[0]}, nil); err != nil {
					return err
				}
			} else if entry.State != "disconnected" && entry.State != "failed" {
				return errors.New("trust requires a disconnected, failed, or certificate-rejected profile")
			}
		}
	}
	rejected := make(map[string]bool)
	if c.name == "up" && len(ids) != 0 {
		var entries []statusEntry
		if err := r.call(protocol.Request{Op: "status"}, &entries); err != nil {
			return err
		}
		for _, entry := range entries {
			rejected[entry.Profile] = entry.State == "waiting_trust"
		}
	}
	pending := make(map[string]uint64)
	var failures []error
	for _, id := range ids {
		if rejected[id] {
			failures = append(failures, fmt.Errorf("%s: certificate requires confirmation; run fortix trust %s", id, id))
			continue
		}
		var result struct {
			Attempt uint64 `json:"attempt"`
		}
		if err := r.call(protocol.Request{Op: "up", Profile: id}, &result); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", id, err))
			continue
		}
		pending[id] = result.Attempt
	}
	var snapshot []statusEntry
	if len(pending) != 0 {
		if err := r.call(protocol.Request{Op: "status"}, &snapshot); err != nil {
			return err
		}
	}
	last := make(map[string]string)
	for _, entry := range snapshot {
		if attempt, ok := pending[entry.Profile]; ok && entry.Attempt == attempt && (entry.State == "connected" || entry.State == "failed" || entry.State == "disconnected") {
			if err := r.transition(protocol.Event{Profile: entry.Profile, State: entry.State, Detail: entry.Detail}, last); err != nil {
				return err
			}
			delete(pending, entry.Profile)
			if entry.State != "connected" {
				failures = append(failures, fmt.Errorf("%s: %s", entry.Profile, entry.State))
			}
		}
	}
	for len(pending) != 0 {
		select {
		case <-ctx.Done():
			return errors.Join(append(failures, ctx.Err())...)
		case event, ok := <-r.conn.Events():
			if !ok {
				return errors.Join(append(failures, r.conn.Err())...)
			}
			attempt, wanted := pending[event.Profile]
			if !wanted || event.Attempt < attempt {
				continue
			}
			// A trust operation starts the next generation; other unsolicited generations are ignored.
			if event.Attempt != attempt {
				continue
			}
			switch event.Type {
			case "challenge":
				if err := r.answer(event, c.save || cfg.RememberPasswords); err != nil {
					failures = append(failures, fmt.Errorf("%s: %w", event.Profile, err))
					delete(pending, event.Profile)
				}
			case "cert":
				err := r.certificate(event, c.name == "trust", c.yes)
				if err != nil {
					failures = append(failures, err)
					delete(pending, event.Profile)
				} else {
					pending[event.Profile] = event.Attempt + 1
				}
			case "state":
				if err := r.transition(event, last); err != nil {
					return err
				}
				if event.State == "connected" || event.State == "failed" || event.State == "disconnected" {
					if err := r.finishCredential(event); err != nil {
						return err
					}
					delete(pending, event.Profile)
					if event.State != "connected" {
						failures = append(failures, fmt.Errorf("%s: %s", event.Profile, event.State))
					}
				}
			}
		}
	}
	return errors.Join(failures...)
}

// transition prints each distinct state once, quoting helper detail to avoid terminal control sequences.
func (r *runner) transition(event protocol.Event, last map[string]string) error {
	if last[event.Profile] == event.State {
		return nil
	}
	last[event.Profile] = event.State
	if event.Detail == "" {
		_, err := fmt.Fprintf(r.out, "%s: %s\n", event.Profile, event.State)
		return err
	}
	_, err := fmt.Fprintf(r.out, "%s: %s (%q)\n", event.Profile, event.State, event.Detail)
	return err
}

// credentialKey reads the helper-owned profile identity before accessing a password.
// Active profiles cannot be edited; retained credentials keep this exact key until saved.
func (r *runner) credentialKey(id string) (string, error) {
	var p profile.Profile
	if err := r.call(protocol.Request{Op: "profile.get", Profile: id}, &p); err != nil {
		return "", err
	}
	if p.ID != id {
		return "", errors.New("helper returned incorrect credential profile")
	}
	return secrets.Key(&p), nil
}
