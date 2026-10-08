// Package profile tests the shared profile identifier boundary without filesystem access.
package profile

import (
	"strings"
	"testing"
)

// TestValidID checks the public identifier validator at alphabet and length boundaries.
// It returns false rather than normalizing unsafe, non-ASCII, or overlong input.
func TestValidID(t *testing.T) {
	for _, tc := range []struct {
		id    string
		valid bool
	}{
		{"work", true}, {"0-work", true}, {"a-", true}, {strings.Repeat("a", 63), true},
		{"", false}, {"-work", false}, {"Work", false}, {"../work", false},
		{"work_1", false}, {"work\n", false}, {"wörk", false}, {strings.Repeat("a", 64), false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			if got := ValidID(tc.id); got != tc.valid {
				t.Fatalf("ValidID(%q) = %v, want %v", tc.id, got, tc.valid)
			}
		})
	}
}
