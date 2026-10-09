package tray

import (
	"context"
	"testing"
)

// TestWindowsTrayRefusal preserves pure grammar coverage without POSIX log-mode assertions.
func TestWindowsTrayRefusal(t *testing.T) {
	if runDesktop(context.Background(), Options{}) == nil {
		t.Fatal("Windows accepted Unix desktop")
	}
	for _, args := range [][]string{nil, {"autostart", "enable"}, {"autostart", "disable"}} {
		if _, err := autostartAction(args); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"autostart"}, {"autostart", "start"}, {"autostart", "enable", "extra"}, {"other", "enable"}} {
		if _, err := autostartAction(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
