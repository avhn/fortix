package helper

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// TestLocalFortixSID checks the NetBIOS lookup, local alias boundary and absent-group fallback.
func TestLocalFortixSID(t *testing.T) {
	computerName, lookupSID := nativeComputerName, nativeLookupSID
	t.Cleanup(func() { nativeComputerName, nativeLookupSID = computerName, lookupSID })
	nativeComputerName = func() (string, error) { return "LONG-COMPUTER-N", nil }
	sid, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, domain string
		kind         uint32
		lookupErr    error
		wantErr      bool
	}{
		{"local", "LONG-COMPUTER-N", windows.SidTypeAlias, nil, false},
		{"case insensitive", "long-computer-n", windows.SidTypeAlias, nil, false},
		{"DNS hostname", "long-computer-name", windows.SidTypeAlias, nil, true},
		{"foreign domain", "OTHER", windows.SidTypeAlias, nil, true},
		{"user", "LONG-COMPUTER-N", windows.SidTypeUser, nil, true},
		{"absent", "", 0, windows.ERROR_NONE_MAPPED, false},
		{"lookup failure", "", 0, windows.ERROR_ACCESS_DENIED, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nativeLookupSID = func(system, account string) (*windows.SID, string, uint32, error) {
				if system != "" || account != `LONG-COMPUTER-N\fortix` {
					t.Fatalf("wrong local account lookup: %q %q", system, account)
				}
				return sid, tc.domain, tc.kind, tc.lookupErr
			}
			got, err := localFortixSID()
			if (err != nil) != tc.wantErr {
				t.Fatalf("SID=%q error=%v", got, err)
			}
			if tc.wantErr || errors.Is(tc.lookupErr, windows.ERROR_NONE_MAPPED) {
				if got != "" {
					t.Fatal("invalid or absent local group received a grant")
				}
			} else if got != sid.String() {
				t.Fatal("local group SID lost")
			}
		})
	}
	nativeComputerName = func() (string, error) { return "", windows.ERROR_ACCESS_DENIED }
	if _, err := localFortixSID(); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("computer-name lookup failure lost: %v", err)
	}
}
