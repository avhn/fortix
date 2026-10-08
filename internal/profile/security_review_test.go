package profile

import (
	"os"
	"strings"
	"testing"
)

// TestSplitDNSRequiresMultipleLabels rejects global single-label search suffixes
// without forbidding a single-label gateway hostname or valid scoped split DNS.
func TestSplitDNSRequiresMultipleLabels(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"com", "local", "corp", "corp.example.com"} {
		p, err := Decode(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		p.Gateway.Host = "gateway"
		p.DNS.Domains = []string{domain}
		err = p.Validate()
		if (err == nil) != strings.Contains(domain, ".") {
			t.Fatalf("domain %s: %v", domain, err)
		}
	}
}
