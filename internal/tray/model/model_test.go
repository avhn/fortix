// Package model tests accessible presentation without any desktop toolkit.
package model

import (
	"reflect"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/session"
)

// TestBuild checks precedence, wanted counts, stale snapshots, and action availability.
func TestBuild(t *testing.T) {
	up := Profile{ID: "work", Name: "Work", State: session.Connected, Wanted: true}
	idle := Profile{ID: "other", State: session.Disconnected, Wanted: true}
	for _, tc := range []struct {
		name      string
		profiles  []Profile
		reachable bool
		status    Status
		names     string
	}{
		{"empty", nil, true, NotConnected, "none"},
		{"idle", []Profile{idle}, true, NotConnected, "none"},
		{"connected", []Profile{up}, true, Connected, "Work"},
		{"unwanted idle", []Profile{up, {ID: "unused", State: session.Disconnected}}, true, Connected, "Work"},
		{"partial", []Profile{up, idle}, true, Partial, "Work"},
		{"externally connected", []Profile{{ID: "work", State: session.Connected}}, true, Connected, "work"},
		{"external up with wanted down", []Profile{{ID: "work", State: session.Connected}, idle}, true, Partial, "work"},
		{"failed", []Profile{up, {State: session.Failed}}, true, Attention, "Work"},
		{"trust", []Profile{{State: session.WaitingTrust}}, true, Attention, "none"},
		{"password", []Profile{{State: session.WaitingPassword, PendingPassword: true}}, true, Attention, "none"},
		{"attention beats progress", []Profile{{State: session.Starting}, {State: session.Failed}}, true, Attention, "none"},
		{"unreachable", []Profile{up}, false, NotConnected, "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]Profile(nil), tc.profiles...)
			menu := Build(tc.profiles, tc.reachable, Preferences{AnimateIcon: true})
			if menu.Status != tc.status {
				t.Fatalf("status = %s, want %s", menu.Status, tc.status)
			}
			if !strings.Contains(menu.Tooltip, string(tc.status)+"; connected profiles: "+tc.names) {
				t.Fatal(menu.Tooltip)
			}
			if !reflect.DeepEqual(before, tc.profiles) {
				t.Fatal("input changed")
			}
			actions := menu.Items[len(menu.Items)-5:]
			for i, id := range []string{"connect_all", "disconnect_all", "open_logs", "animate_icon", "quit"} {
				if actions[i].ID != id {
					t.Fatalf("action %d: %+v", i, actions[i])
				}
			}
			if !actions[3].Checked {
				t.Fatal("animation preference lost")
			}
			if !tc.reachable {
				if menu.Items[0].Enabled || menu.Items[0].Title != "Helper not running" {
					t.Fatal(menu.Items[0])
				}
				for _, item := range menu.Items[1 : len(menu.Items)-3] {
					if item.Enabled || item.Checked {
						t.Fatal(item)
					}
				}
			}
		})
	}
}

// TestProgressPhases checks every transitional contract phase and enabled bulk actions.
func TestProgressPhases(t *testing.T) {
	for _, phase := range []session.Phase{session.Starting, session.WaitingPassword, session.WaitingCode, session.Authenticating, session.Negotiating, session.Configuring, session.Stopping, session.Backoff} {
		menu := Build([]Profile{{ID: "work", State: phase, Wanted: true}}, true, Preferences{})
		if menu.Status != Connecting || !strings.Contains(menu.Items[0].Title, phaseTitle(phase)) {
			t.Fatal(menu)
		}
		if menu.Items[1].Enabled || !menu.Items[2].Enabled {
			t.Fatal("incorrect progress actions", menu.Items)
		}
	}
	menu := Build([]Profile{{ID: "work", State: session.Disconnected}}, true, Preferences{})
	if !menu.Items[1].Enabled || menu.Items[2].Enabled || menu.Items[4].Checked {
		t.Fatal(menu.Items)
	}
	menu = Build([]Profile{{ID: "work", State: session.Connected, Wanted: true}, {ID: "other", State: session.Connected, Wanted: true}}, true, Preferences{})
	if menu.Status != Connected || menu.Tooltip != "Connected; connected profiles: work, other" {
		t.Fatal(menu)
	}
}

// TestPhaseTitles checks readable labels for every known phase and unknown fallbacks.
func TestPhaseTitles(t *testing.T) {
	for _, tc := range []struct {
		phase session.Phase
		title string
	}{
		{session.Disconnected, "Disconnected"}, {session.Starting, "Starting"},
		{session.WaitingPassword, "Waiting for password"}, {session.WaitingCode, "Waiting for code"},
		{session.Authenticating, "Authenticating"}, {session.Negotiating, "Negotiating"},
		{session.Configuring, "Configuring"}, {session.Connected, "Connected"},
		{session.WaitingTrust, "Waiting for certificate trust"}, {session.Backoff, "Waiting to retry"},
		{session.Stopping, "Stopping"}, {session.Failed, "Failed"}, {"future_phase", "future_phase"},
	} {
		menu := Build([]Profile{{ID: "work", Name: "Work", State: tc.phase}}, true, Preferences{})
		if menu.Items[0].Title != "Work ("+tc.title+")" {
			t.Fatalf("%s: %s", tc.phase, menu.Items[0].Title)
		}
	}
}
