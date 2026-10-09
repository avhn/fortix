//go:build darwin || linux

package openfortivpn

import (
	"strings"
	"testing"
)

// TestInheritedAccountConfig keeps usernames and realms out of process arguments
// and ensures both allowed config keys are encoded without accepting line injection.
func TestInheritedAccountConfig(t *testing.T) {
	p := commandProfile()
	p.Realm = "corp"
	argv, env, err := BuildCommand(p, commandOptions())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(argv, " "), p.Username) || strings.Contains(strings.Join(argv, " "), "corp") || !strings.Contains(strings.Join(argv, " "), "-c /dev/fd/3") {
		t.Fatal(argv)
	}
	if strings.Contains(strings.Join(env, " "), p.Username) {
		t.Fatal("username entered environment")
	}
	config, err := Config(p)
	if err != nil || string(config) != "username = jane.doe\nrealm = corp\n" {
		t.Fatalf("config: %q %v", config, err)
	}
	for _, control := range []string{"\n", "\r", "\x00"} {
		p.Username = "user" + control + "set-routes = 1"
		if config, err := Config(p); err == nil || config != nil {
			t.Fatal("config accepted username injection")
		}
		p.Username, p.Realm = "jane.doe", "realm"+control
		if config, err := Config(p); err == nil || config != nil {
			t.Fatal("config accepted realm injection")
		}
	}
}
