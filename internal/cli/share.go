// Package cli exchanges shared configuration without importing personal credentials.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
)

// exportShared fetches ordered profiles through the helper and exports only shareable fields.
// File creation is exclusive unless force is explicit; encoding and output failures propagate.
func (r *runner) exportShared(c command) error {
	profiles := make([]profile.Profile, 0, len(c.ids))
	for _, id := range c.ids {
		var p profile.Profile
		if err := r.call(protocol.Request{Op: "profile.get", Profile: id}, &p); err != nil {
			return err
		}
		if p.ID != id {
			return errors.New("helper returned incorrect export profile")
		}
		profiles = append(profiles, p)
	}
	data, err := profile.Export(profiles...)
	if err != nil {
		return err
	}
	if c.output == "" {
		_, err = r.out.Write(data)
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if c.force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(c.output, flags, 0o644)
	if errors.Is(err, os.ErrExist) {
		return errors.New("export file already exists; use --force to replace it")
	}
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return errors.Join(err, file.Close())
}

// sharedInput resolves the caller-owned input stream without consuming it.
// The default is stdin; only a terminal can supply interactive completion and pin consent.
func (r *runner) sharedInput() *os.File {
	if r.options.Input != nil {
		return r.options.Input
	}
	return os.Stdin
}

// readShared reads at most the parser's 1 MiB limit plus one rejection byte.
// A dash uses stdin without closing it; file read and close errors remain inspectable.
func (r *runner) readShared(path string) ([]profile.Draft, error) {
	var source io.Reader = r.sharedInput()
	var file *os.File
	if path != "-" {
		var err error
		file, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		source = file
	}
	data, err := io.ReadAll(io.LimitReader(source, (1<<20)+1))
	if file != nil {
		err = errors.Join(err, file.Close())
	}
	if err != nil {
		return nil, err
	}
	return profile.Parse(data)
}

// importShared parses and preflights every draft before writing through profile.put.
// Existing IDs require merge, which targets the selected ID and retains its personal username.
// Shared pins require explicit consent but remain subject to the helper's trust policy.
func (r *runner) importShared(c command) error {
	drafts, err := r.readShared(c.ids[0])
	if err != nil {
		return err
	}
	if len(drafts) != 1 && (c.id != "" || c.nameOverride != "" || c.merge != "") {
		return errors.New("--id, --name, and --merge require a single-profile file")
	}
	interactive := c.ids[0] != "-" && term.IsTerminal(int(r.sharedInput().Fd()))
	input := r.sharedInput()
	profiles := make([]profile.Profile, 0, len(drafts))
	// Finish local validation and consent before dialing when no stored base is needed.
	for i, draft := range drafts {
		if c.nameOverride != "" {
			draft.Name = new(c.nameOverride)
		}
		if c.id != "" {
			draft.ID = new(c.id)
		}
		if c.merge != "" {
			// The source ID describes the sender's profile, never a second destination.
			draft.ID = new(c.merge)
		} else {
			p, err := r.completeShared(draft, c.username, interactive, input)
			if err != nil {
				return err
			}
			profiles = append(profiles, p)
		}
		if err := r.showSharedPin(draft); err != nil {
			return err
		}
		drafts[i] = draft
	}
	if err := r.connect(); err != nil {
		return err
	}
	defer func() { _ = r.conn.Close() }()
	if c.merge != "" {
		var base profile.Profile
		if err := r.call(protocol.Request{Op: "profile.get", Profile: c.merge}, &base); err != nil {
			return err
		}
		if base.ID != c.merge {
			return errors.New("helper returned incorrect merge profile")
		}
		p := drafts[0].Apply(base)
		if err := p.Validate(); err != nil {
			return err
		}
		if err := r.confirmGatewayChange(base, p, c.yes, interactive); err != nil {
			return err
		}
		profiles = append(profiles, p)
	}
	var entries []profileState
	if err := r.call(protocol.Request{Op: "profile.list"}, &entries); err != nil {
		return err
	}
	seen := make(map[string]bool, len(entries)+len(profiles))
	for _, entry := range entries {
		seen[entry.Profile] = true
	}
	for _, p := range profiles {
		if seen[p.ID] && c.merge == "" {
			return fmt.Errorf("profile %q already exists; use --merge %s", p.ID, p.ID)
		}
		seen[p.ID] = true
	}
	for _, p := range profiles {
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if err := r.call(protocol.Request{Op: "profile.put", ProfileJSON: data}, nil); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(r.out, "imported: %s\nfortix up %s will ask for the password and can save it to the keychain with --save.\n", p.ID, p.ID); err != nil {
			return err
		}
	}
	return nil
}

// completeShared fills missing required fields with visible terminal input, never a password.
// Noninteractive omissions produce an ordered field list; Complete supplies defaults and validation.
func (r *runner) completeShared(d profile.Draft, username string, interactive bool, input io.Reader) (profile.Profile, error) {
	missing := d.Missing()
	if username != "" {
		missing = removeUsername(missing)
	}
	if len(missing) != 0 && !interactive {
		return profile.Profile{}, fmt.Errorf("missing required fields: %s (supply --username or use an interactive terminal)", strings.Join(missing, ", "))
	}
	for _, field := range missing {
		if err := r.ctx.Err(); err != nil {
			return profile.Profile{}, err
		}
		if _, err := fmt.Fprintf(r.errout, "%s: ", field); err != nil {
			return profile.Profile{}, err
		}
		value, err := r.readSharedField(input)
		if err != nil {
			return profile.Profile{}, err
		}
		value = strings.TrimSpace(value)
		switch field {
		case "id":
			d.ID = new(value)
		case "name":
			d.Name = new(value)
		case "username":
			username = value
		case "gateway.host":
			if d.Gateway == nil {
				d.Gateway = &profile.DraftGateway{}
			}
			d.Gateway.Host = new(value)
		case "routes.include":
			d.Routes.Include = new(strings.Split(value, ","))
		case "dns.domains":
			d.DNS.Domains = new(strings.Split(value, ","))
		}
	}
	if err := r.ctx.Err(); err != nil {
		return profile.Profile{}, err
	}
	return profile.Complete(d, username, "")
}

// readSharedField consumes one bounded visible line without buffering later consent responses.
// Cancellation, EOF, oversized input, and reader failures stop completion without echoing input.
func (r *runner) readSharedField(input io.Reader) (string, error) {
	var data []byte
	var one [1]byte
	for len(data) <= 64*1024 {
		if err := r.ctx.Err(); err != nil {
			return "", err
		}
		n, err := input.Read(one[:])
		if n > 0 {
			if one[0] == '\n' {
				return string(data), nil
			}
			data = append(data, one[0])
		}
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", io.ErrNoProgress
		}
	}
	return "", errors.New("completion field exceeds 64 KiB limit")
}

// removeUsername filters only the locally supplied personal field from draft omissions.
// It preserves the schema order of all other missing fields without changing the draft.
func removeUsername(fields []string) []string {
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if field != "username" {
			result = append(result, field)
		}
	}
	return result
}

// showSharedPin prints a fingerprint carried by the file as unverified information.
// The helper never stores a submitted pin, so there is nothing to accept here; a gateway
// certificate is only trusted through `fortix trust` after independent verification.
func (r *runner) showSharedPin(d profile.Draft) error {
	if d.TrustedCert == nil || *d.TrustedCert == "" {
		return nil
	}
	_, err := fmt.Fprintf(r.errout, "The file carries an unverified certificate fingerprint, which is not saved:\nSHA256: %s\nIf the gateway certificate is rejected, confirm its fingerprint with your administrator\nover a separate channel before running fortix trust.\n", *d.TrustedCert)
	return err
}

// confirmGatewayChange stops a merge that would point an existing profile at another
// gateway unless the user confirms it, because the next connection sends the password
// there. Noninteractive input requires --yes; declining prevents every write.
func (r *runner) confirmGatewayChange(base, merged profile.Profile, yes, interactive bool) error {
	if base.Gateway.Host == merged.Gateway.Host && base.Gateway.Port == merged.Gateway.Port {
		return nil
	}
	if _, err := fmt.Fprintf(r.errout, "This file changes the gateway of %q from %s:%d to %s:%d.\nYour password would be sent to the new gateway.\n", base.ID, base.Gateway.Host, base.Gateway.Port, merged.Gateway.Host, merged.Gateway.Port); err != nil {
		return err
	}
	if yes {
		return nil
	}
	if !interactive {
		return errors.New("merge changes the gateway; use --yes after confirming the change")
	}
	confirmed, err := r.options.Prompt.Confirm(r.ctx, "Change the gateway?")
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("gateway change declined")
	}
	return nil
}
