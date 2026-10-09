package secrets

import (
	"testing"

	"github.com/avhn/fortix/internal/profile"
)

// TestWindowsCredentialTargetProvider confirms every keyring operation selects the same target.
// go-keyring's Windows wincred backend joins service and account with ':' and stores UTF-8 blobs.
// Golden office/alice/vpn.example.com:443 -> fortix:office:1e37db253af678a3c9010637555e6a96fb5a3a71ed566bc4abf79ce423186bc7:password.
func TestWindowsCredentialTargetProvider(t *testing.T) {
	for _, vector := range credentialVectors() {
		t.Run(vector.Name, func(t *testing.T) {
			calls := 0
			check := func(service, account string) {
				t.Helper()
				calls++
				if target := service + ":" + account; target != vector.Target {
					t.Fatalf("target %q, want %q", target, vector.Target)
				}
			}
			store := Keyring{backend: &provider{
				get: func(service, account string) (string, error) {
					check(service, account)
					return "synthetic-password", nil
				},
				set: func(service, account, password string) error {
					check(service, account)
					if password != "synthetic-password" {
						t.Fatal("provider password changed")
					}
					return nil
				},
				delete: func(service, account string) error { check(service, account); return nil },
			}}
			key := Key(&profile.Profile{ID: vector.ID, Gateway: profile.Gateway{Host: vector.Host, Port: vector.Port}, Username: vector.Username})
			if err := store.Set(key, "synthetic-password"); err != nil {
				t.Fatal(err)
			}
			if password, err := store.Get(key); err != nil || password != "synthetic-password" {
				t.Fatalf("get: %q %v", password, err)
			}
			if err := store.Delete(key); err != nil || calls != 3 {
				t.Fatalf("delete: calls=%d err=%v", calls, err)
			}
		})
	}
}
