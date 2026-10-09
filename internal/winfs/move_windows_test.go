package winfs

import "testing"

// TestSameVolume uses pinned volume identities rather than caller-controlled drive letters.
func TestSameVolume(t *testing.T) {
	first := &Root{volume: 1}
	if !first.SameVolume(&Root{volume: 1}) || first.SameVolume(&Root{volume: 2}) {
		t.Fatal("running-image staging volume comparison is wrong")
	}
}
