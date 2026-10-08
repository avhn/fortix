// Package model derives accessible tray presentation from immutable session snapshots.
package model

import (
	"strings"

	"github.com/avhn/fortix/internal/session"
)

// Status names aggregate connectivity independently of icon color and animation.
type Status string

// Aggregate statuses are ordered by explicit precedence in Build, not by value.
const (
	NotConnected Status = "NotConnected"
	Connecting   Status = "Connecting"
	Connected    Status = "Connected"
	Partial      Status = "Partial"
	Attention    Status = "Attention"
)

// Profile contains a display name, session phase, desired connectivity, and prompt flag.
// PendingPassword distinguishes a prompt needing human attention from keychain lookup.
type Profile struct {
	ID              string
	Name            string
	State           session.Phase
	Wanted          bool
	PendingPassword bool
	CleanupPending  bool
}

// Preferences contains user-controlled presentation settings; false disables motion.
type Preferences struct{ AnimateIcon bool }

// Item is a toolkit-neutral menu entry. IDs identify actions, never executable commands.
type Item struct {
	ID      string
	Title   string
	Enabled bool
	Checked bool
}

// Menu contains menu entries, aggregate status, and an always informative tooltip.
type Menu struct {
	Items   []Item
	Status  Status
	Tooltip string
}

// Build returns a fresh menu for profiles, helper reachability, and preferences.
// It preserves input order, performs no I/O, and cannot fail. Mixed wanted connectivity
// is Partial; all wanted connected is Connected. Otherwise attention outranks progress.
// Unreachable snapshots are stale,
// so profiles are unchecked and the tooltip reports no verified connections.
func Build(profiles []Profile, reachable bool, preferences Preferences) Menu {
	menu := Menu{Status: NotConnected, Items: make([]Item, 0, len(profiles)+7)}
	names := make([]string, 0, len(profiles))
	wanted, wantedUp := 0, 0
	attention, progress, connectable, stoppable := false, false, false, false
	if !reachable {
		menu.Items = append(menu.Items, Item{ID: "helper", Title: "Helper not running"})
	}
	for _, p := range profiles {
		name := p.Name
		if name == "" {
			name = p.ID
		}
		connected := reachable && p.State == session.Connected
		text := phaseTitle(p.State)
		if !reachable {
			text = "Helper unavailable"
		}
		menu.Items = append(menu.Items, Item{ID: "profile:" + p.ID, Title: name + " (" + text + ")", Enabled: reachable, Checked: connected},
			Item{ID: "forget:" + p.ID, Title: "Forget saved password: " + name, Enabled: reachable})
		if !reachable {
			continue
		}
		if p.Wanted {
			wanted++
			if connected {
				wantedUp++
			}
		}
		if connected {
			names = append(names, name)
		}
		attention = attention || p.PendingPassword || p.State == session.Failed || p.State == session.WaitingTrust
		progress = progress || inProgress(p.State)
		connectable = connectable || p.State == session.Disconnected || p.State == session.Failed
		stoppable = stoppable || p.State != session.Disconnected
	}
	switch {
	case wantedUp > 0 && wantedUp < wanted:
		menu.Status = Partial
	case wanted > 0 && wantedUp == wanted:
		menu.Status = Connected
	case attention:
		menu.Status = Attention
	case progress:
		menu.Status = Connecting
	}
	menu.Items = append(menu.Items,
		Item{ID: "connect_all", Title: "Connect all", Enabled: reachable && connectable},
		Item{ID: "disconnect_all", Title: "Disconnect all", Enabled: reachable && stoppable},
		Item{ID: "open_logs", Title: "Open logs", Enabled: true},
		Item{ID: "animate_icon", Title: "Animate icon", Enabled: true, Checked: preferences.AnimateIcon},
		Item{ID: "quit", Title: "Quit", Enabled: true},
	)
	connectedNames := "none"
	if len(names) > 0 {
		connectedNames = strings.Join(names, ", ")
	}
	menu.Tooltip = string(menu.Status) + "; connected profiles: " + connectedNames
	if !reachable {
		menu.Tooltip += "; Helper not running"
	}
	return menu
}

// phaseTitle returns a readable label for a session phase without I/O or errors.
// Unknown phases retain their original text so unexpected helper states stay visible.
func phaseTitle(state session.Phase) string {
	switch state {
	case session.Disconnected:
		return "Disconnected"
	case session.Starting:
		return "Starting"
	case session.WaitingPassword:
		return "Waiting for password"
	case session.WaitingCode:
		return "Waiting for code"
	case session.Authenticating:
		return "Authenticating"
	case session.Negotiating:
		return "Negotiating"
	case session.Configuring:
		return "Configuring"
	case session.Connected:
		return "Connected"
	case session.WaitingTrust:
		return "Waiting for certificate trust"
	case session.Backoff:
		return "Waiting to retry"
	case session.Stopping:
		return "Stopping"
	case session.Failed:
		return "Failed"
	default:
		return string(state)
	}
}

// inProgress recognizes all transitional phases, including stop and retry wait.
// Unknown values are not progress and are preserved as text by Build.
func inProgress(state session.Phase) bool {
	switch state {
	case session.Starting, session.WaitingPassword, session.WaitingCode, session.Authenticating,
		session.Negotiating, session.Configuring, session.Stopping, session.Backoff:
		return true
	default:
		return false
	}
}
