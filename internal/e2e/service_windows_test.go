package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/client"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
)

const profileID = "windows-e2e"

// networkSnapshot records actual OS state, not helper-reported ownership or connection status.
type networkSnapshot struct {
	Adapters []struct {
		Index       uint32 `json:"index"`
		Description string `json:"description"`
	} `json:"adapters"`
	Addresses []uint32 `json:"addresses"`
	Routes    []uint32 `json:"routes"`
	Rules     []struct {
		Comment string   `json:"comment"`
		Servers []string `json:"servers"`
	} `json:"rules"`
}

// powershell invokes only the fixed system binary with bounded execution and fixed test scripts.
func powershell(ctx context.Context, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	image := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, image, "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("system query: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

// snapshot queries adapters, address, route interface identity and the exact split-DNS namespace.
func snapshot(ctx context.Context) (networkSnapshot, error) {
	const script = `$ErrorActionPreference = 'Stop'
$adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -like 'fortix-*' } | ForEach-Object { @{index=[uint32]$_.ifIndex; description=$_.InterfaceDescription} })
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq '198.51.100.10' } | ForEach-Object { [uint32]$_.InterfaceIndex })
$routes = @(Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '203.0.113.0/24' } | ForEach-Object { [uint32]$_.InterfaceIndex })
$rules = @(Get-DnsClientNrptRule | Where-Object { @($_.Namespace) -contains '.example.test' } | ForEach-Object { @{comment=$_.Comment; servers=@($_.NameServers | ForEach-Object { [string]$_ })} })
@{adapters=$adapters; addresses=$addresses; routes=$routes; rules=$rules} | ConvertTo-Json -Depth 6 -Compress`
	var state networkSnapshot
	output, err := powershell(ctx, script)
	if err != nil {
		return state, err
	}
	err = json.Unmarshal([]byte(strings.TrimSpace(string(output))), &state)
	return state, err
}

// connected requires one Fortix adapter and ties both its IP and VPN route to the same index.
func (s networkSnapshot) connected() bool {
	if len(s.Adapters) != 1 || len(s.Addresses) != 1 || len(s.Routes) != 1 || len(s.Rules) != 1 {
		return false
	}
	adapter := s.Adapters[0]
	rule := s.Rules[0]
	return adapter.Index != 0 && s.Addresses[0] == adapter.Index && s.Routes[0] == adapter.Index &&
		(strings.Contains(adapter.Description, "Fortix") || strings.Contains(adapter.Description, "Wintun")) &&
		strings.HasPrefix(rule.Comment, "fortix:") && strings.Contains(rule.Comment, ":"+profileID+":") &&
		len(rule.Servers) == 1 && rule.Servers[0] == "198.51.100.53"
}

// empty requires all target resources gone, including leftover addresses and unmarked NRPT rules.
func (s networkSnapshot) empty() bool {
	return len(s.Adapters) == 0 && len(s.Addresses) == 0 && len(s.Routes) == 0 && len(s.Rules) == 0
}

// waitNetwork bounds OS convergence and reports the final observed resources on failure.
func waitNetwork(t *testing.T, ctx context.Context, present bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var last networkSnapshot
	var lastErr error
	for {
		last, lastErr = snapshot(ctx)
		if lastErr == nil && (present && last.connected() || !present && last.empty()) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("network present=%v: %v; last query=%v; state=%+v", present, ctx.Err(), lastErr, last)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// call bounds one real pipe request and never includes request secrets in failure diagnostics.
func call(t *testing.T, ctx context.Context, c *client.Client, request protocol.Request) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := c.Call(ctx, request, nil); err != nil {
		t.Fatalf("operation %s: %v", request.Op, err)
	}
}

// bringUp answers only password challenges and pins the independently measured fake certificate.
func bringUp(t *testing.T, ctx context.Context, c *client.Client, fingerprint string, requireTrust bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	call(t, ctx, c, protocol.Request{Op: "up", Profile: profileID})
	trusted := false
	for {
		select {
		case <-ctx.Done():
			t.Fatal("VPN connection did not become ready before deadline")
		case event, ok := <-c.Events():
			if !ok {
				t.Fatalf("helper events closed: %v", c.Err())
			}
			if event.Profile != profileID {
				continue
			}
			switch event.Type {
			case "cert":
				if event.Digest != fingerprint {
					t.Fatal("helper certificate fingerprint does not match fake gateway")
				}
				call(t, ctx, c, protocol.Request{Op: "trust", Profile: profileID, Digest: event.Digest})
				trusted = true
			case "challenge":
				if event.Kind != "password" {
					t.Fatalf("unexpected challenge kind: %s", event.Kind)
				}
				call(t, ctx, c, protocol.Request{Op: "answer", ChallengeID: event.ChallengeID, Secret: "fixture-password"})
			case "state":
				if event.State == "failed" {
					t.Fatalf("VPN failed: %s: %s", event.Code, event.Detail)
				}
				if event.State == "connected" {
					if requireTrust && !trusted {
						t.Fatal("initial connection bypassed certificate trust operation")
					}
					return
				}
			}
		}
	}
}

// dialService waits for the real verified pipe after SCM startup and crash recovery.
func dialService(t *testing.T, ctx context.Context) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var last error
	for {
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		c, err := client.Dial(attempt, client.Options{DiscardLogs: true})
		stop()
		if err == nil {
			return c
		}
		last = err
		select {
		case <-ctx.Done():
			t.Fatalf("service did not become ready: %v", last)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// crashService kills the SCM-reported process, never a guessed PID or unrelated helper instance.
func crashService(t *testing.T, ctx context.Context) {
	t.Helper()
	output, err := powershell(ctx, `$ErrorActionPreference = 'Stop'; $s = Get-CimInstance Win32_Service -Filter "Name='fortix-helper'"; if (!$s -or $s.ProcessId -eq 0) { throw 'Service has no process' }; [uint32]$s.ProcessId`)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 32)
	if err != nil || pid == 0 {
		t.Fatal("invalid SCM service PID")
	}
	kill, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	image := filepath.Join(os.Getenv("SystemRoot"), "System32", "taskkill.exe")
	if output, err := exec.CommandContext(kill, image, "/F", "/PID", strconv.FormatUint(pid, 10)).CombinedOutput(); err != nil {
		t.Fatalf("force service crash: %v: %s", err, output)
	}
	// SCM also has a five-second recovery action, so accept a verified replacement process.
	// Only the parsed unsigned PID is substituted, never user-supplied shell text.
	const restart = `$ErrorActionPreference = 'Stop'
$crashed = __CRASHED_PID__
$deadline = [DateTime]::UtcNow.AddSeconds(10)
do {
  $s = Get-Service fortix-helper
  if ($s.Status -eq 'Stopped') { Start-Service fortix-helper; return }
  $current = Get-CimInstance Win32_Service -Filter "Name='fortix-helper'"
  if ($s.Status -eq 'Running' -and $current.ProcessId -ne 0 -and $current.ProcessId -ne $crashed) { return }
  Start-Sleep -Milliseconds 200
} while ([DateTime]::UtcNow -lt $deadline)
throw 'Service did not restart after crash'`
	_, err = powershell(ctx, strings.Replace(restart, "__CRASHED_PID__", strconv.FormatUint(pid, 10), 1))
	if err != nil {
		t.Fatal(err)
	}
}

// TestInstalledService exercises real Wintun, route, NRPT and persisted crash recovery boundaries.
// It is destructive only on disposable Windows hosts whose operator explicitly sets FORTIX_E2E=1.
func TestInstalledService(t *testing.T) {
	if os.Getenv("FORTIX_E2E") != "1" {
		t.Skip("set FORTIX_E2E=1 on a disposable Windows host with the helper installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	waitNetwork(t, ctx, false)
	server, fingerprint := fakeGateway(t)
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	c := dialService(t, ctx)
	t.Cleanup(func() {
		if c != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			if err := c.Call(cleanup, protocol.Request{Op: "down", Profile: profileID}, nil); err != nil {
				t.Errorf("cleanup down: %v", err)
			}
			_ = c.Close()
		}
	})
	p := profile.Profile{SchemaVersion: 1, ID: profileID, Name: "Windows integration fixture", Backend: "native", Gateway: profile.Gateway{Host: host, Port: port}, Username: "fixture-user", MFA: profile.MFA{Mode: "none"}, Routes: profile.Routes{Mode: "custom", Include: []string{"203.0.113.0/24"}}, DNS: profile.DNS{Mode: "split", Domains: []string{"example.test"}}}
	p.ApplyDefaults()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	call(t, ctx, c, protocol.Request{Op: "profile.put", ProfileJSON: data})
	call(t, ctx, c, protocol.Request{Op: "subscribe"})
	bringUp(t, ctx, c, fingerprint, true)
	waitNetwork(t, ctx, true)
	call(t, ctx, c, protocol.Request{Op: "down", Profile: profileID})
	waitNetwork(t, ctx, false)
	bringUp(t, ctx, c, fingerprint, false)
	waitNetwork(t, ctx, true)
	crashService(t, ctx)
	_ = c.Close()
	c = nil
	c = dialService(t, ctx)
	waitNetwork(t, ctx, false)
}

// TestNetworkSnapshotAssertions rejects wrong interface identities, unowned DNS and residual resources.
func TestNetworkSnapshotAssertions(t *testing.T) {
	const fixture = `{"adapters":[{"index":42,"description":"Fortix Tunnel"}],"addresses":[42],"routes":[42],"rules":[{"comment":"fortix:installation:windows-e2e:nonce","servers":["198.51.100.53"]}]}`
	var state networkSnapshot
	if err := json.Unmarshal([]byte(fixture), &state); err != nil {
		t.Fatal(err)
	}
	if !state.connected() || state.empty() || !(networkSnapshot{}).empty() {
		t.Fatal("baseline state assertions are wrong")
	}
	state.Routes[0]++
	if state.connected() {
		t.Fatal("route on the wrong adapter accepted")
	}
	state.Routes[0]--
	state.Rules[0].Comment = "unowned"
	if state.connected() {
		t.Fatal("unmarked DNS rule accepted")
	}
	state.Rules[0].Comment = "fortix:installation:windows-e2e:nonce"
	state.Rules[0].Servers[0] = "192.0.2.53"
	if state.connected() {
		t.Fatal("wrong DNS server accepted")
	}
}
