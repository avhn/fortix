package network

import (
	"slices"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/session"
)

// TestExcludeRoutes drops pushed routes inside an excluded range, splits broader ones
// around it, and leaves the full-tunnel default halves alone.
func TestExcludeRoutes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		pushed  []string
		exclude []string
		want    []string
	}{
		{"exact range dropped", "gateway", []string{"10.40.3.0/24", "10.40.4.0/24"}, []string{"10.40.3.0/24"}, []string{"10.40.4.0/24"}},
		{"broader route split", "gateway", []string{"10.40.0.0/22"}, []string{"10.40.3.0/24"}, []string{"10.40.0.0/23", "10.40.2.0/24"}},
		{"covered by wider exclude", "gateway", []string{"10.40.3.0/24"}, []string{"10.40.0.0/16"}, nil},
		{"no exclude unchanged", "gateway", []string{"10.40.3.0/24"}, nil, []string{"10.40.3.0/24"}},
		{"full keeps halves", "full", []string{"10.40.3.0/24", "10.40.4.0/24"}, []string{"10.40.3.0/24"}, []string{"10.40.4.0/24"}},
		{"full with pushed default", "full", []string{"0.0.0.0/0", "10.40.3.0/24"}, []string{"10.40.3.0/24"}, []string{"0.0.0.0/1", "128.0.0.0/1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &profile.Profile{Routes: profile.Routes{Mode: tc.mode, Exclude: tc.exclude}}
			got, err := negotiatedPrefixes(p, session.Effect{PushedPrefixes: prefixes(tc.pushed...)})
			if err != nil || !slices.Equal(got, prefixes(tc.want...)) {
				t.Fatalf("got %v, want %v (%v)", got, tc.want, err)
			}
		})
	}
}

// TestConflictWording names the profile holding the range and the action that frees
// it, so the app can show the reason to the user unchanged.
func TestConflictWording(t *testing.T) {
	other := profile.Profile{ID: "first", Name: "First VPN"}
	p := profile.Profile{ID: "second", Name: "Second VPN"}
	got := profileConflict(other, p, prefixes("198.51.100.0/24")[0])
	if got != "First VPN is already using 198.51.100.0/24. Disconnect First VPN to connect Second VPN, or exclude 198.51.100.0/24 in Second VPN." {
		t.Fatalf("profile conflict: %q", got)
	}
	if got := profileConflict(other, profile.Profile{ID: "second"}, prefixes("0.0.0.0/1")[0]); !strings.HasPrefix(got, "First VPN is already sending all traffic") || !strings.HasSuffix(got, "to connect second.") {
		t.Fatalf("default half conflict: %q", got)
	}
	if got := lanConflict(prefixes("198.18.0.0/24")[0], prefixes("198.18.0.0/16")[0], "en0"); !strings.Contains(got, "overlaps your local network 198.18.0.0/16 on en0") {
		t.Fatalf("lan conflict: %q", got)
	}
}
