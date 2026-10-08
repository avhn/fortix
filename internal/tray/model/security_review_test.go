package model

import (
	"testing"

	"github.com/avhn/fortix/internal/session"
)

// TestPartialPrecedesWantedProgress covers all mixed wanted states, including
// failures and trust attention, while explicitly stopped idle profiles stay ignored.
func TestPartialPrecedesWantedProgress(t *testing.T) {
	up := Profile{ID: "work", State: session.Connected, Wanted: true}
	for _, phase := range []session.Phase{session.Starting, session.WaitingPassword, session.WaitingTrust, session.Backoff, session.Failed} {
		menu := Build([]Profile{up, {ID: "other", State: phase, Wanted: true, PendingPassword: phase == session.WaitingPassword}}, true, Preferences{})
		if menu.Status != Partial {
			t.Fatalf("mixed %s connectivity reported %s", phase, menu.Status)
		}
	}
	if menu := Build([]Profile{up, {ID: "stopped", State: session.Disconnected}}, true, Preferences{}); menu.Status != Connected {
		t.Fatal("unwanted idle profile made connectivity partial")
	}
	if menu := Build([]Profile{{ID: "work", State: session.Failed, Wanted: true}}, true, Preferences{}); menu.Status != Attention {
		t.Fatal("failed-only wanted set did not need attention")
	}
}
