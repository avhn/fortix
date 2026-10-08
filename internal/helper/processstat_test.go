package helper

import (
	"strings"
	"testing"
)

// TestProcessStat handles nested command parentheses and refuses truncated records.
func TestProcessStat(t *testing.T) {
	for _, state := range []string{"R", "Z", "X"} {
		raw := "123 (command ) with spaces) " + state + strings.Repeat(" 0", 18) + " 12345"
		start, exited, err := parseProcessStat([]byte(raw))
		if err != nil || start != "12345" || exited != (state != "R") {
			t.Fatalf("state %s: %q %v %v", state, start, exited, err)
		}
	}
	for _, raw := range []string{"", "123 (name) R 1", "123 (name) R" + strings.Repeat(" 0", 18) + " invalid"} {
		if _, _, err := parseProcessStat([]byte(raw)); err == nil {
			t.Fatal("accepted invalid procfs record")
		}
	}
}

// FuzzProcessStat checks kernel-record parsing without accessing procfs or signalling.
func FuzzProcessStat(f *testing.F) {
	f.Add([]byte("123 (command) R" + strings.Repeat(" 0", 18) + " 12345"))
	f.Add([]byte("123 ((command)) Z" + strings.Repeat(" 0", 18) + " 1"))
	f.Fuzz(func(_ *testing.T, data []byte) { _, _, _ = parseProcessStat(data) })
}
