package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/avhn/fortix/internal/session"
	"golang.org/x/sys/windows"
)

// fakeNRPTRunner models the typed script contract, including the final ownership recheck.
type fakeNRPTRunner struct {
	rules    []nrptRule
	policies []nrptRule
	requests []nrptRequest
	events   *[]string
	before   func(nrptRequest) error
}

// Run snapshots detached JSON values and never launches a process or changes real DNS policy.
func (f *fakeNRPTRunner) Run(ctx context.Context, request nrptRequest) (nrptResponse, error) {
	if err := ctx.Err(); err != nil {
		return nrptResponse{}, err
	}
	f.requests = append(f.requests, request)
	if f.events != nil {
		*f.events = append(*f.events, "nrpt:"+request.Operation)
	}
	if f.before != nil {
		if err := f.before(request); err != nil {
			return nrptResponse{}, err
		}
	}
	response := nrptResponse{OK: true}
	switch request.Operation {
	case "snapshot":
		response.Rules, response.Policies = f.rules, f.policies
		if f.policies == nil {
			// Local rules are effective unless the fixture supplies overriding policy.
			response.Policies = f.rules
		}
	case "add":
		rule := request.Rule
		rule.Name = "{00000009-0000-0000-0000-000000000009}"
		f.rules = append(f.rules, rule)
		response.Name = rule.Name
	case "remove":
		index := slices.IndexFunc(f.rules, func(rule nrptRule) bool { return rule.Name == request.Rule.Name })
		if index < 0 {
			return nrptResponse{}, errors.New("DNS rule identity changed; journal retained")
		}
		intent := &resolverIntent{Domains: request.Rule.Namespaces, Servers: request.Rule.Servers, Marker: request.Rule.Comment}
		if !sameNRPTValues(f.rules[index], intent) {
			return nrptResponse{}, errors.New("DNS rule identity changed; journal retained")
		}
		f.rules = slices.Delete(f.rules, index, index+1)
	default:
		return nrptResponse{}, errors.New("unexpected fake DNS operation")
	}
	data, _ := json.Marshal(response)
	var copy nrptResponse
	if err := json.Unmarshal(data, &copy); err != nil {
		return copy, err
	}
	return copy, nil
}

// nrptFixtureIntent provides canonical, secret-free durable ownership for recovery tests.
func nrptFixtureIntent(j Journal, named bool) *resolverIntent {
	nonce := strings.Repeat("a", 32)
	intent := &resolverIntent{Mode: "split", Domains: []string{".example.com"}, Servers: []string{"192.0.2.53"}, Installation: j.Installation, Profile: j.Profile, Nonce: nonce, Marker: "fortix:" + j.Installation + ":" + j.Profile + ":" + nonce, State: mutationIntent}
	if named {
		intent.Name, intent.State = "{00000009-0000-0000-0000-000000000009}", mutationApplied
	}
	return intent
}

// fakeResolver attaches nonfatal flush instrumentation to the same event stream as routes.
func fakeResolver(f *fakeNRPTRunner) *nrptResolver {
	return &nrptResolver{runner: f, sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }, flush: func() error {
		if f.events != nil {
			*f.events = append(*f.events, "dns-flush")
		}
		return nil
	}}
}

// TestNRPTEnvironment keeps LocalSystem startup variables explicit without inheriting process state.
func TestNRPTEnvironment(t *testing.T) {
	for _, drive := range []string{"C:", "D:"} {
		system := drive + `\Windows\System32`
		data := []byte(`{"operation":"snapshot","rule":{}}`)
		got := strings.Split(string(utf16.Decode(nrptEnvironment(system, data))), "\x00")
		want := []string{
			"FORTIX_NRPT_REQUEST=" + string(data),
			"FORTIX_SYSTEM_DIRECTORY=" + system,
			"PSModulePath=" + system + `\WindowsPowerShell\v1.0\Modules`,
			"SystemDrive=" + drive,
			"SystemRoot=" + drive + `\Windows`,
			"TEMP=" + drive + `\Windows\Temp`,
			"TMP=" + drive + `\Windows\Temp`,
			"WINDIR=" + drive + `\Windows`,
			"", "",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("environment for %s: got %q, want %q", drive, got, want)
		}
	}
}

// TestNRPTCreatedPolicyLag bounds retries after Add and interrupted creation without real waits.
func TestNRPTCreatedPolicyLag(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		for _, scenario := range []string{"second-snapshot", "never", "identity", "identity-race", "cancel"} {
			t.Run(fmt.Sprintf("interrupted=%v/%s", interrupted, scenario), func(t *testing.T) {
				_, _, _, j := windowsFixture(t)
				intent := nrptFixtureIntent(j, false)
				runner := &fakeNRPTRunner{policies: []nrptRule{}}
				if interrupted {
					rule := intentRule(intent)
					rule.Name = "{00000009-0000-0000-0000-000000000009}"
					runner.rules = []nrptRule{rule}
				}
				verificationSnapshots := 0
				runner.before = func(request nrptRequest) error {
					if request.Operation == "snapshot" && intent.Name != "" {
						verificationSnapshots++
						if scenario == "second-snapshot" && verificationSnapshots == 2 {
							runner.policies = runner.rules
						}
						if scenario == "identity" || scenario == "identity-race" && verificationSnapshots == 2 {
							runner.rules[0].Comment += "changed"
						}
					}
					return nil
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				resolver := fakeResolver(runner)
				waits := 0
				resolver.sleep = func(ctx context.Context, delay time.Duration) error {
					waits++
					if delay != 200*time.Millisecond {
						t.Fatalf("retry delay: %v", delay)
					}
					if scenario == "cancel" {
						cancel()
					}
					return ctx.Err()
				}
				err := resolver.Apply(ctx, intent, func() error { return nil })
				wantSnapshots, wantWaits := 2, 1
				switch scenario {
				case "second-snapshot":
					if err != nil {
						t.Fatal(err)
					}
				case "never":
					wantSnapshots, wantWaits = 6, 5
					if !errors.Is(err, errNRPTPolicy) {
						t.Fatalf("policy failure not preserved: %v", err)
					}
				case "identity", "identity-race":
					if scenario == "identity" {
						wantSnapshots, wantWaits = 1, 0
					}
					if err == nil || !strings.Contains(err.Error(), "DNS rule identity changed") {
						t.Fatalf("identity failure not preserved: %v", err)
					}
				case "cancel":
					wantSnapshots = 1
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation not preserved: %v", err)
					}
				}
				if verificationSnapshots != wantSnapshots || waits != wantWaits {
					t.Fatalf("snapshots=%d waits=%d, want %d/%d", verificationSnapshots, waits, wantSnapshots, wantWaits)
				}
			})
		}
	}
}

// TestNRPTConstantScript verifies code remains a literal and hostile values remain JSON data.
func TestNRPTConstantScript(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "nrpt_process_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	literal := false
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if ok && len(value.Names) == 1 && value.Names[0].Name == "nrptScript" {
			_, literal = value.Values[0].(*ast.BasicLit)
		}
		return true
	})
	if !literal || strings.Contains(nrptScript, "%") || strings.Contains(nrptScript, "Invoke-Expression") {
		t.Fatal("DNS script must be literal code without format verbs or data evaluation")
	}
	for _, required := range []string{"Import-Module", "Modules\\DnsClient\\DnsClient.psd1", "Get-DnsClientNrptRule", "Get-DnsClientNrptPolicy -Effective", "Add-DnsClientNrptRule -Namespace", "-PassThru", "Remove-DnsClientNrptRule -Name", "-Force", "$env:FORTIX_NRPT_REQUEST"} {
		if !strings.Contains(nrptScript, required) {
			t.Fatalf("missing script contract %q", required)
		}
	}
	hostile := `example.com'); Remove-Item C:\\*; #"` + "\n$env:SECRET"
	request := nrptRequest{Operation: "add", Rule: nrptRule{Namespaces: []string{hostile}}}
	data, err := encodeNRPTRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded nrptRequest
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.Rule.Namespaces[0] != hostile || strings.Contains(nrptScript, hostile) {
		t.Fatalf("data entered code: %v", err)
	}
	request.Rule.Comment = strings.Repeat("x", nrptRequestLimit)
	if _, err := encodeNRPTRequest(request); err == nil {
		t.Fatal("unbounded request accepted")
	}
	if _, err := normalizeNamespaces([]string{hostile}); err == nil {
		t.Fatal("hostile namespace passed validation")
	}
}

// TestNRPTResponseBounds preserves JSON failures and rejects oversized or trailing output.
func TestNRPTResponseBounds(t *testing.T) {
	response, err := decodeNRPTResponse([]byte(`{"ok":false,"error":"injected script failure"}`), 1)
	if err != nil || response.OK || response.Error != "injected script failure" {
		t.Fatalf("script error not preserved: %+v %v", response, err)
	}
	for _, data := range [][]byte{[]byte("not JSON"), []byte(`{"ok":true}{"ok":true}`), []byte(`{"ok":true,"unexpected":1}`), []byte(strings.Repeat(" ", nrptOutputLimit+1))} {
		if _, err := decodeNRPTResponse(data, 0); err == nil {
			t.Fatalf("invalid output accepted: bytes=%d", len(data))
		}
	}
	if _, err := decodeNRPTResponse([]byte(`{"ok":true}`), 1); err == nil {
		t.Fatal("failed process accepted a success envelope")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (powershellNRPTRunner{}).Run(ctx, nrptRequest{Operation: "snapshot"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled runner launched: %v", err)
	}
}

// TestNRPTInputValidation checks DNS label boundaries, literal addresses and cardinality limits.
func TestNRPTInputValidation(t *testing.T) {
	for _, domain := range []string{"", "a..example.com", "-a.example.com", "a-.example.com", "é.example.com", "a_b.example.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com"} {
		if _, err := normalizeNamespaces([]string{domain}); err == nil {
			t.Errorf("invalid domain accepted: %q", domain)
		}
	}
	for _, domain := range []string{"Example.COM", ".example.com", "xn--bcher-kva.example", strings.Repeat("a", 63) + ".example.com"} {
		if _, err := normalizeNamespaces([]string{domain}); err != nil {
			t.Errorf("valid domain refused: %q: %v", domain, err)
		}
	}
	if _, err := normalizeNamespaces(make([]string, 33)); err == nil {
		t.Fatal("too many namespaces accepted")
	}
	for _, server := range []string{"example.com", "192.0.2.53:53", "[2001:db8::53]", "fe80::1%3", "0.0.0.0", "ff02::1"} {
		if _, err := normalizeServers([]string{server}); err == nil {
			t.Errorf("invalid server accepted: %q", server)
		}
	}
	if _, err := normalizeServers([]string{"192.0.2.53", "2001:db8::53"}); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeServers(make([]string, 9)); err == nil {
		t.Fatal("too many servers accepted")
	}
}

// TestNRPTIntentPublication verifies nonce, intent and returned Name surround the Add operation.
func TestNRPTIntentPublication(t *testing.T) {
	m, f, _, j := windowsFixture(t)
	runner := &fakeNRPTRunner{events: &f.events}
	resolver := fakeResolver(runner)
	j.Resolver = &resolverIntent{Mode: "split", Installation: j.Installation, Profile: j.Profile, Domains: []string{"Example.COM"}, Servers: []string{"192.0.2.53"}}
	runner.before = func(request nrptRequest) error {
		if request.Operation == "add" {
			stored, err := m.loadJournal(j.Profile, j.Attempt)
			if err != nil || stored.Resolver == nil || stored.Resolver.Name != "" || len(stored.Resolver.Nonce) != 32 || stored.Resolver.Marker != request.Rule.Comment || !slices.Equal(stored.Resolver.Domains, []string{".example.com"}) {
				t.Fatalf("Add preceded durable intent: %+v, %v", stored.Resolver, err)
			}
		}
		return nil
	}
	if err := resolver.Apply(context.Background(), j.Resolver, func() error { return m.save(context.Background(), &j, nil) }); err != nil {
		t.Fatal(err)
	}
	stored, err := m.loadJournal(j.Profile, j.Attempt)
	if err != nil || stored.Resolver.Name == "" || stored.Resolver.State != mutationApplied {
		t.Fatalf("Name not recorded: %+v %v", stored.Resolver, err)
	}
	add := slices.Index(f.events, "nrpt:add")
	if add < 1 || f.events[add-1] != "write:"+journalName(j) || f.events[add+1] != "write:"+journalName(j) || f.events[len(f.events)-1] != "dns-flush" {
		t.Fatalf("publication order: %v", f.events)
	}
	if err := resolver.Apply(context.Background(), j.Resolver, nil); err != nil {
		t.Fatalf("idempotent preflight failed: %v", err)
	}
}

// TestNRPTEffectivePolicy retains ownership when local rules are absent from effective policy.
func TestNRPTEffectivePolicy(t *testing.T) {
	for _, scenario := range []string{"local", "unrelated-gpo", "absent", "wrong-server", "partial", "separate-entries"} {
		t.Run(scenario, func(t *testing.T) {
			m, _, _, j := windowsFixture(t)
			runner := &fakeNRPTRunner{}
			resolver := fakeResolver(runner)
			j.Resolver = &resolverIntent{Mode: "split", Installation: j.Installation, Profile: j.Profile, Domains: []string{"example.com", "example.net"}, Servers: []string{"192.0.2.53"}}
			if scenario == "unrelated-gpo" {
				runner.policies = []nrptRule{{Namespaces: []string{".other.example.org"}, Servers: []string{"192.0.2.54"}}}
			}
			runner.before = func(request nrptRequest) error {
				if request.Operation == "add" {
					switch scenario {
					case "absent":
						runner.policies = []nrptRule{}
					case "wrong-server":
						runner.policies = []nrptRule{{Namespaces: request.Rule.Namespaces, Servers: []string{"192.0.2.54"}}}
					case "partial":
						runner.policies = []nrptRule{{Namespaces: []string{".example.com"}, Servers: request.Rule.Servers}}
					case "separate-entries":
						runner.policies = []nrptRule{
							{Namespaces: []string{".EXAMPLE.COM."}, Servers: request.Rule.Servers},
							{Namespaces: []string{".example.net"}, Servers: request.Rule.Servers},
						}
					}
				}
				return nil
			}
			err := resolver.Apply(context.Background(), j.Resolver, func() error { return m.save(context.Background(), &j, nil) })
			wantSuccess := scenario == "local" || scenario == "separate-entries"
			if wantSuccess && err != nil || !wantSuccess && (err == nil || !strings.Contains(err.Error(), "overrides local split DNS rules; journal retained")) {
				t.Fatalf("effective policy result: %v", err)
			}
			stored, err := m.loadJournal(j.Profile, j.Attempt)
			if err != nil || stored.Resolver == nil || stored.Resolver.Name == "" || len(runner.rules) != 1 {
				t.Fatalf("ownership lost after verification: %+v, %v", stored.Resolver, err)
			}
			for _, preflight := range []bool{true, false} {
				var persist func() error
				if !preflight {
					persist = func() error { t.Fatal("acknowledged retry wrote metadata"); return nil }
				}
				err := resolver.Apply(context.Background(), stored.Resolver, persist)
				if (err == nil) != wantSuccess {
					t.Fatalf("retry preflight=%v hid effective policy: %v", preflight, err)
				}
			}
			m.resolver = resolver
			if err := m.Teardown(context.Background(), j); err != nil || len(runner.rules) != 0 {
				t.Fatalf("ineffective local rule was not cleaned up: %v", err)
			}
		})
	}
}

// TestNRPTApplyInterruptedCreation adopts only a single exact marked rule after no-write preflight.
func TestNRPTApplyInterruptedCreation(t *testing.T) {
	for _, scenario := range []string{"zero", "one", "many", "namespace", "server", "invalid-name", "foreign-marker", "overridden", "persist-failure", "verify-race"} {
		t.Run(scenario, func(t *testing.T) {
			m, _, _, j := windowsFixture(t)
			j.Resolver = nrptFixtureIntent(j, false)
			runner := &fakeNRPTRunner{}
			if scenario != "zero" {
				rule := intentRule(j.Resolver)
				rule.Name = "{00000008-0000-0000-0000-000000000008}"
				switch scenario {
				case "namespace":
					rule.Namespaces = []string{".child.example.com"}
				case "server":
					rule.Servers = []string{"192.0.2.54"}
				case "invalid-name":
					rule.Name = "invalid"
				case "foreign-marker":
					rule.Comment += "changed"
				}
				runner.rules = []nrptRule{rule}
				if scenario == "many" {
					rule.Name = "{00000007-0000-0000-0000-000000000007}"
					runner.rules = append(runner.rules, rule)
				}
			}
			if scenario == "overridden" {
				runner.policies = []nrptRule{{Namespaces: []string{".other.example.org"}, Servers: []string{"192.0.2.54"}}}
			}
			if err := m.save(context.Background(), &j, nil); err != nil {
				t.Fatal(err)
			}
			resolver := fakeResolver(runner)
			err := resolver.Apply(context.Background(), j.Resolver, nil)
			preflightOK := scenario == "zero" || scenario == "one" || scenario == "persist-failure" || scenario == "verify-race"
			if (err == nil) != preflightOK || j.Resolver.Name != "" || j.Resolver.State != mutationIntent || len(runner.requests) != 1 {
				t.Fatalf("no-write preflight: %+v, %v", j.Resolver, err)
			}
			writes, snapshots := 0, 0
			runner.before = func(request nrptRequest) error {
				if request.Operation == "snapshot" {
					snapshots++
					if scenario == "verify-race" && snapshots == 2 {
						runner.rules[0].Servers = []string{"192.0.2.54"}
					}
				}
				return nil
			}
			err = resolver.Apply(context.Background(), j.Resolver, func() error {
				writes++
				if scenario == "persist-failure" {
					return errors.New("injected reconciliation write failure")
				}
				return m.save(context.Background(), &j, nil)
			})
			wantSuccess := scenario == "zero" || scenario == "one"
			if (err == nil) != wantSuccess {
				t.Fatalf("reconciliation result: %v", err)
			}
			adds := 0
			for _, request := range runner.requests {
				if request.Operation == "add" {
					adds++
				}
			}
			if scenario == "zero" {
				if adds != 1 || writes != 2 {
					t.Fatalf("missing intent did not fall through to Add: adds=%d writes=%d", adds, writes)
				}
			} else if adds != 0 {
				t.Fatal("interrupted creation added another rule")
			}
			stored, loadErr := m.loadJournal(j.Profile, j.Attempt)
			if loadErr != nil || stored.Resolver == nil {
				t.Fatalf("interrupted journal lost: %v", loadErr)
			}
			adopted := scenario == "zero" || scenario == "one" || scenario == "overridden" || scenario == "verify-race"
			if (stored.Resolver.Name != "") != adopted {
				t.Fatalf("durable reconciliation: %+v", stored.Resolver)
			}
			if scenario == "one" && (writes != 1 || stored.Resolver.Name != runner.rules[0].Name || stored.Resolver.State != mutationApplied || snapshots != 2) {
				t.Fatalf("adoption not persisted and reverified: writes=%d snapshots=%d %+v", writes, snapshots, stored.Resolver)
			}
			if !preflightOK && scenario != "overridden" {
				var conflict *ConflictError
				if scenario == "foreign-marker" {
					if !errors.As(err, &conflict) {
						t.Fatalf("foreign marker exempted: %v", err)
					}
				} else if errors.As(err, &conflict) || !strings.Contains(err.Error(), "journal retained") {
					t.Fatalf("ownership uncertainty reported as overlap: %v", err)
				}
			}
		})
	}
}

// TestNRPTWriteFailures keeps durable intent after a failed result or helper publication.
func TestNRPTWriteFailures(t *testing.T) {
	for boundary := 1; boundary <= 2; boundary++ {
		t.Run(string(rune('0'+boundary)), func(t *testing.T) {
			m, _, s, j := windowsFixture(t)
			runner := &fakeNRPTRunner{}
			resolver := fakeResolver(runner)
			j.Resolver = &resolverIntent{Mode: "split", Installation: j.Installation, Profile: j.Profile, Domains: []string{"example.com"}, Servers: []string{"192.0.2.53"}}
			s.failAt = boundary
			if err := resolver.Apply(context.Background(), j.Resolver, func() error { return m.save(context.Background(), &j, nil) }); err == nil {
				t.Fatal("publication failure hidden")
			}
			stored, err := m.loadJournal(j.Profile, j.Attempt)
			if err != nil {
				t.Fatal(err)
			}
			if boundary == 1 {
				if len(runner.rules) != 0 || stored.Resolver != nil {
					t.Fatal("Add preceded failed intent write")
				}
			} else {
				if stored.Resolver == nil || stored.Resolver.Name != "" || len(runner.rules) != 1 {
					t.Fatal("failed result lost interrupted creation")
				}
				if err := resolver.Recover(context.Background(), stored.Resolver); err != nil || len(runner.rules) != 0 {
					t.Fatalf("interrupted creation not recovered: %v", err)
				}
			}
		})
	}
}

// TestNRPTRemoveIdentity preserves changed names, namespaces, servers and comments.
func TestNRPTRemoveIdentity(t *testing.T) {
	for _, field := range []string{"exact", "namespace", "server", "comment", "name", "host-not-suffix", "remove-race"} {
		t.Run(field, func(t *testing.T) {
			_, _, _, j := windowsFixture(t)
			intent := nrptFixtureIntent(j, true)
			rule := intentRule(intent)
			switch field {
			case "namespace":
				rule.Namespaces = []string{".other.example.com"}
			case "server":
				rule.Servers = []string{"192.0.2.54"}
			case "comment":
				rule.Comment += "changed"
			case "name":
				rule.Name = "{00000008-0000-0000-0000-000000000008}"
			case "host-not-suffix":
				rule.Namespaces = []string{"example.com"}
			}
			runner := &fakeNRPTRunner{rules: []nrptRule{rule}}
			if field == "remove-race" {
				runner.before = func(request nrptRequest) error {
					if request.Operation == "remove" {
						runner.rules[0].Comment = "changed concurrently"
					}
					return nil
				}
			}
			err := fakeResolver(runner).Remove(context.Background(), intent)
			if field == "exact" {
				if err != nil || len(runner.rules) != 0 {
					t.Fatalf("unchanged owned rule retained: %v", err)
				}
			} else if len(runner.rules) != 1 || field != "name" && err == nil {
				t.Fatalf("changed rule discarded: %v %v", runner.rules, err)
			}
		})
	}
}

// TestNRPTInterruptedCreation reconciles zero, one and multiple exact marker matches.
func TestNRPTInterruptedCreation(t *testing.T) {
	for count := 0; count <= 2; count++ {
		m, _, _, j := windowsFixture(t)
		intent := nrptFixtureIntent(j, false)
		runner := &fakeNRPTRunner{}
		for i := 0; i < count; i++ {
			rule := intentRule(intent)
			rule.Name = windows.GUID{Data1: uint32(i + 1)}.String()
			runner.rules = append(runner.rules, rule)
		}
		j.Resolver = intent
		if err := m.save(context.Background(), &j, nil); err != nil {
			t.Fatal(err)
		}
		m.resolver = fakeResolver(runner)
		err := m.Teardown(context.Background(), j)
		if count == 2 {
			if err == nil || len(runner.rules) != 2 {
				t.Fatalf("ambiguous marker removed: %v", err)
			}
			stored, _ := m.loadJournal(j.Profile, j.Attempt)
			if stored.Resolver == nil {
				t.Fatal("ambiguous metadata discarded")
			}
		} else if err != nil || len(runner.rules) != 0 {
			t.Fatalf("count %d: %v, rules=%v", count, err, runner.rules)
		}
	}
}

// TestNRPTConflicts refuses equal, parent, child and effective GPO namespaces before writes.
func TestNRPTConflicts(t *testing.T) {
	for _, namespace := range []string{".example.com", ".com", ".child.example.com", "example.com", ".", "*.example.com", ".EXAMPLE.COM"} {
		for _, policy := range []bool{false, true} {
			runner := &fakeNRPTRunner{}
			rule := nrptRule{Namespaces: []string{namespace}}
			if policy {
				runner.policies = []nrptRule{rule}
			} else {
				runner.rules = []nrptRule{rule}
			}
			intent := &resolverIntent{Mode: "split", Domains: []string{"example.com"}}
			var conflict *ConflictError
			if err := fakeResolver(runner).Apply(context.Background(), intent, nil); !errors.As(err, &conflict) || len(runner.requests) != 1 {
				t.Fatalf("namespace %s policy=%v: %v", namespace, policy, err)
			}
		}
	}
	if namespacesOverlap(".notexample.com", ".example.com") || namespacesOverlap(".example.com.evil", ".example.com") {
		t.Fatal("nonoverlapping label boundaries refused")
	}
}

// TestNRPTConflictOwnership exempts only exact marked values, never a reused Name alone.
func TestNRPTConflictOwnership(t *testing.T) {
	for _, scenario := range []string{"exact", "comment", "server", "namespace", "no-nonce"} {
		t.Run(scenario, func(t *testing.T) {
			_, _, _, j := windowsFixture(t)
			intent := nrptFixtureIntent(j, false)
			rule := intentRule(intent)
			rule.Name = "{00000008-0000-0000-0000-000000000008}"
			switch scenario {
			case "comment":
				rule.Comment += "changed"
			case "server":
				rule.Servers = []string{"192.0.2.54"}
			case "namespace":
				rule.Namespaces = []string{".child.example.com"}
			case "no-nonce":
				intent.Nonce = ""
			}
			if scenario != "exact" {
				intent.Name = rule.Name
			}
			err := checkNRPTConflicts(nrptResponse{Rules: []nrptRule{rule}}, intent)
			var conflict *ConflictError
			if scenario == "exact" {
				if err != nil {
					t.Fatalf("exact marker was not exempted: %v", err)
				}
			} else if !errors.As(err, &conflict) {
				t.Fatalf("unowned rule was exempted: %v", err)
			}
		})
	}
}

// TestNRPTFlushFailureNonfatal does not retain metadata merely because the cache API failed.
func TestNRPTFlushFailureNonfatal(t *testing.T) {
	m, _, _, j := windowsFixture(t)
	runner := &fakeNRPTRunner{}
	resolver := fakeResolver(runner)
	warnings := 0
	resolver.flush = func() error { return errors.New("injected flush failure") }
	resolver.warn = func(error) { warnings++ }
	j.Resolver = &resolverIntent{Mode: "split", Installation: j.Installation, Profile: j.Profile, Domains: []string{"example.com"}, Servers: []string{"192.0.2.53"}}
	if err := resolver.Apply(context.Background(), j.Resolver, func() error { return m.save(context.Background(), &j, nil) }); err != nil {
		t.Fatal(err)
	}
	m.resolver = resolver
	if err := m.Teardown(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	stored, err := m.loadJournal(j.Profile, j.Attempt)
	if err != nil || stored.Resolver != nil || !stored.CleanupComplete || warnings != 2 {
		t.Fatalf("nonfatal flush: %+v, warnings=%d, err=%v", stored, warnings, err)
	}
}

// TestNRPTTeardownPartialFailure persists DNS removal even when a later route cannot be removed.
func TestNRPTTeardownPartialFailure(t *testing.T) {
	m, f, _, j := windowsFixture(t)
	j.Resolver = nrptFixtureIntent(j, true)
	route := JournalRoute{CIDR: "198.51.100.0/24", Interface: j.Interface, LUID: 22, Index: 22, Metric: 5, Protocol: windows.MIB_IPPROTO_NETMGMT, State: mutationApplied}
	j.Routes = []JournalRoute{route}
	changed := route
	changed.Metric++
	f.table = append(f.table, changed)
	if err := m.save(context.Background(), &j, nil); err != nil {
		t.Fatal(err)
	}
	runner := &fakeNRPTRunner{rules: []nrptRule{intentRule(j.Resolver)}}
	m.resolver = fakeResolver(runner)
	if err := m.Teardown(context.Background(), j); err == nil {
		t.Fatal("changed route failure hidden")
	}
	stored, err := m.loadJournal(j.Profile, j.Attempt)
	if err != nil || stored.Resolver != nil || stored.CleanupComplete || len(stored.Routes) != 1 || len(runner.rules) != 0 {
		t.Fatalf("partial cleanup lost durable progress: %+v, %v", stored, err)
	}
}

// TestNRPTRecoveryValidation rejects forged resolver ownership before any batch mutation.
func TestNRPTRecoveryValidation(t *testing.T) {
	m, f, s, j := windowsFixture(t)
	j.Resolver = nrptFixtureIntent(j, true)
	j.Resolver.Marker += ":forged"
	data, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	s.files[journalName(j)] = data
	runner := &fakeNRPTRunner{events: &f.events}
	m.resolver = fakeResolver(runner)
	if err := m.RecoverAll(context.Background(), nil); err == nil || len(runner.requests) != 0 || len(f.events) != 0 {
		t.Fatalf("forged resolver reached mutation: %v, %v", err, f.events)
	}
}

// TestNRPTRecoveryMissingAdapter removes DNS and flushes before physical gateway or ledger cleanup.
func TestNRPTRecoveryMissingAdapter(t *testing.T) {
	m, f, s, j := windowsFixture(t)
	if err := m.acquireGateway(context.Background(), &j, nil); err != nil {
		t.Fatal(err)
	}
	j.Resolver = nrptFixtureIntent(j, true)
	if err := m.save(context.Background(), &j, nil); err != nil {
		t.Fatal(err)
	}
	f.links = slices.DeleteFunc(f.links, func(a adapter) bool { return a.row.InterfaceGuid == j.Allocation.GUID })
	runner := &fakeNRPTRunner{rules: []nrptRule{intentRule(j.Resolver)}, events: &f.events}
	m.resolver = fakeResolver(runner)
	f.events = nil
	if err := m.RecoverAll(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	remove := slices.Index(f.events, "nrpt:remove")
	flush := slices.Index(f.events, "dns-flush")
	gateway := slices.Index(f.events, "delete-route:"+j.GatewayIP+"/32")
	adapter := slices.Index(f.events, "remove-adapter")
	if remove < 0 || flush <= remove || gateway <= flush || adapter <= gateway || len(runner.rules) != 0 {
		t.Fatalf("missing-adapter recovery order: %v", f.events)
	}
	if _, err := s.read(journalName(j)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovered journal retained")
	}
}

// TestNRPTSplitLifecycle covers negotiated DNS, durable ownership and public teardown.
func TestNRPTSplitLifecycle(t *testing.T) {
	m, f, _, j := windowsFixture(t)
	runner := &fakeNRPTRunner{events: &f.events}
	m.resolver = fakeResolver(runner)
	p := windowsProfile()
	p.DNS.Mode, p.DNS.Domains = "split", []string{"example.com"}
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterLink(context.Background(), p.ID, j.Attempt, *j.Link, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	effect := session.Effect{Profile: p.ID, Attempt: j.Attempt, Interface: j.Interface, Link: *j.Link, LocalIP: netip.MustParseAddr("198.51.100.10"), MTU: 1400, DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}
	if err := m.ConfigureNative(context.Background(), effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background(), p, effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(runner.rules) != 1 || j.Resolver == nil || j.Resolver.Name == "" || j.DNSConfigured {
		t.Fatal("split DNS ownership missing or adapter DNS changed")
	}
	runner.policies = []nrptRule{{Namespaces: []string{".example.com"}, Servers: []string{"192.0.2.53"}}}
	if err := m.CheckUp(context.Background(), p); err != nil {
		t.Fatalf("owned rule blocked active profile: %v", err)
	}
	if err := m.Apply(context.Background(), p, effect, &j, func(Journal) error { return nil }); err != nil {
		t.Fatalf("idempotent Apply: %v", err)
	}
	if err := m.Teardown(context.Background(), j); err != nil || len(runner.rules) != 0 {
		t.Fatalf("split lifecycle: %v", err)
	}
}

// TestWindowsGatewaySharerCallbackFailure preserves a durable sharer despite helper failure.
func TestWindowsGatewaySharerCallbackFailure(t *testing.T) {
	m, f, s, first := windowsFixture(t)
	if err := m.acquireGateway(context.Background(), &first, nil); err != nil {
		t.Fatal(err)
	}
	second := recoveryNeighbor(t, m, f, s, 44, false)
	second.GatewayIP = first.GatewayIP
	if err := m.acquireGateway(context.Background(), &second, func(Journal) error { return errors.New("injected helper callback failure") }); err == nil {
		t.Fatal("helper failure hidden")
	}
	if err := m.Teardown(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(f.table, func(row JournalRoute) bool { return row.CIDR == first.GatewayIP+"/32" }) {
		t.Fatal("durably referenced shared route deleted early")
	}
	if err := m.Teardown(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(f.table, func(row JournalRoute) bool { return row.CIDR == first.GatewayIP+"/32" }) {
		t.Fatal("last shared owner did not release gateway")
	}
}
