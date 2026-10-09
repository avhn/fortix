package openfortivpn

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

// transcript reads a fixture into events using a fresh parser and an EOF flush.
// Fixture I/O or scan failures fail t; all output stays inside the test process.
func transcript(t testing.TB, name string) []Event {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	var parser Parser
	var events []Event
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		events = append(events, parser.Parse(scanner.Text())...)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return append(events, parser.Flush()...)
}

// TestTranscripts asserts every event and payload in six complete or failed exchanges.
// The fixtures are synthetic and contain only public placeholder addresses and names.
func TestTranscripts(t *testing.T) {
	addresses := GotAddresses{LocalIP: netip.MustParseAddr("10.20.0.10"), DNS: []netip.Addr{netip.MustParseAddr("10.20.0.1"), netip.MustParseAddr("10.20.0.2")}, Suffix: "corp.example.com"}
	success := []Event{ConnectedToGateway{}, Authenticated{}, VPNAllocated{}, addresses, NegotiationComplete{}, InterfaceUp{Name: "ppp0"}, TunnelUp{}}
	dropAddresses := addresses
	dropAddresses.DNS, dropAddresses.Suffix = dropAddresses.DNS[:1], ""
	cases := []struct {
		name string
		want []Event
	}{
		{"success", success},
		{"auth_failure", []Event{ConnectedToGateway{}, AuthFailed{}, Teardown{Message: "Closed connection to gateway."}, LoggedOut{}}},
		{"cert_rejection", []Event{CertRejected{Digest: strings.Repeat("0123456789abcdef", 4), Subject: "CN=vpn.example.com\nO=Example", Issuer: "CN=Example CA"}, Teardown{Message: "Closed connection to gateway."}, Unknown{Line: "INFO:   Could not log out."}}},
		{"pppd_failure", []Event{ConnectedToGateway{}, Authenticated{}, VPNAllocated{}, PPPFailure{Message: "pppd: The PPP negotiation failed, that is, it didn't reach the point where at least one network protocol (e.g. IP) was running."}, Teardown{Message: "Terminated pppd."}, Teardown{Message: "Closed connection to gateway."}, LoggedOut{}}},
		{"gateway_drop", []Event{ConnectedToGateway{}, Authenticated{}, VPNAllocated{}, dropAddresses, NegotiationComplete{}, InterfaceUp{Name: "ppp0"}, TunnelUp{}, PPPFailure{Message: "pppd: The link was terminated because the peer is not responding to echo requests."}, Teardown{Message: "Terminated pppd."}, Teardown{Message: "Closed connection to gateway."}, Unknown{Line: "INFO:   Could not log out."}}},
		{"early_exit", []Event{ConnectedToGateway{}, Authenticated{}, Teardown{Message: "Closed connection to gateway."}, LoggedOut{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := transcript(t, tc.name); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestLineClassification tests exact prefixes, recognized messages, and malformed data.
// Similar-looking diagnostics must not advance the connection or imply failure.
func TestLineClassification(t *testing.T) {
	cases := make([]struct {
		line string
		want Event
	}, 0, 24)
	cases = append(cases, []struct {
		line string
		want Event
	}{
		{"INFO:   Connected to gateway.\r\n", ConnectedToGateway{}},
		{"ERROR:  " + tunnelDenied, TunnelModeDenied{}},
		{"ERROR:  ppp: Returned an unknown exit status code: 1", PPPFailure{Message: "ppp: Returned an unknown exit status code: 1"}},
		{"INFO:   Terminated ppp.", Teardown{Message: "Terminated ppp."}},
		{"INFO:   Interface ppp-1 is UP.", InterfaceUp{Name: "ppp-1"}},
		{"INFO:   Got addresses: [10.20.0.10], ns []", GotAddresses{LocalIP: netip.MustParseAddr("10.20.0.10")}},
	}...)
	for _, line := range []string{
		"INFO:  Authenticated.", "INFO:    Authenticated.", "WARN:   Authenticated.", "DEBUG:  Authenticated.",
		"ERROR:  unknown failure", "Authenticated.", "\x1b[31mINFO:   Authenticated.",
		"INFO:   Got addresses: [bad], ns [10.20.0.1]", "INFO:   Got addresses: [0.0.0.0], ns []",
		"INFO:   Got addresses: [2001:db8::1], ns []", "INFO:   Got addresses: [10.20.0.10], ns [bad]",
		"INFO:   Got addresses: [10.20.0.10], ns [10.20.0.1,10.20.0.2]",
		"INFO:   Interface  is UP.", "INFO:   Interface -ppp0 is UP.", "INFO:   Interface ppp;false is UP.",
		"INFO:   Interface " + strings.Repeat("p", 16) + " is UP.", "DEBUG:  ", strings.Repeat("x", maxOutputLine+1),
	} {
		cases = append(cases, struct {
			line string
			want Event
		}{line, Unknown{Line: line}})
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var parser Parser
			if got := parser.Parse(tc.line); !reflect.DeepEqual(got, []Event{tc.want}) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestRouteRejections distinguishes route collisions, ordinary installation errors,
// successful adds, unrelated diagnostics, and the benign VPN server host exception.
func TestRouteRejections(t *testing.T) {
	cases := []struct {
		line   string
		reason RouteRejectReason
		prefix string
	}{
		{"INFO:   Route to gateway exists already.", RouteConflict, ""},
		{"WARN:   Route to gateway exists already.", RouteConflict, ""},
		{"route: writing to routing socket: File exists", "", ""},
		{"WARN:   route: writing to routing socket: File exists", "", ""},
		{"add net 10.20.0.0/16: gateway ppp0: File exists", RouteConflict, "10.20.0.0/16"},
		{"add host 203.0.113.5: gateway 192.0.2.1: File exists", "", ""},
		{"add net 203.0.113.5: gateway ppp0: File exists", RouteConflict, ""},
		{"RTNETLINK answers: File exists", RouteConflict, ""},
		{"SIOCADDRT: File exists", RouteConflict, ""},
		{"SIOCADDRT: Network is unreachable", RouteFailed, ""},
		{"ERROR:  /sbin/route: No such file or directory.", RouteFailed, ""},
		{"WARN:   Could not set route to tunnel gateway (File exists).", RouteConflict, ""},
		{"WARN:   Could not set route to tunnel gateway (Permission denied).", RouteFailed, ""},
		{"WARN:   Could not set route to vpn server (Network is unreachable).", "", ""},
		{"WARN:   Could not set route to vpn server (File exists).", "", ""},
		{"ERROR:  Failed to add route 10.20.1.0/16: Network is unreachable", RouteFailed, "10.20.0.0/16"},
		{"ERROR:  Could not add route 10.20.0.0/16: Operation not permitted", RouteFailed, "10.20.0.0/16"},
		{"route: writing to routing socket: Network is unreachable", "", ""},
		{"add net 10.20.0.0/16: gateway ppp0: Network is unreachable", RouteFailed, "10.20.0.0/16"},
		{"WARN:   Default route exists already.", RouteConflict, ""},
		{"WARN:   0.0.0.0/1 route exists already.", RouteConflict, "0.0.0.0/1"},
		{"WARN:   Could not set the new 128.0.0.0/1 route (Permission denied).", RouteFailed, "128.0.0.0/1"},
		{"WARN:   Could not set the new default route (Permission denied).", RouteFailed, ""},
		{"WARN:   Route to vpn server exists already.", "", ""},
		{"INFO:   Route to vpn server exists already.", "", ""},
		{"add net 10.20.0.0: gateway ppp0", "", ""},
		{"delete net 10.20.0.0: gateway ppp0: File exists", "", ""},
		{"SIOCDELRT: No such process", "", ""},
		{"WARN:   Could not delete route to vpn server (No such process).", "", ""},
		{"DEBUG:  /sbin/route -n add -net 10.20.0.0 -netmask 255.255.0.0 -interface ppp0", "", ""},
		{"ERROR:  File exists", "", ""},
		{"pppd: File exists", "", ""},
		{"File exists", "", ""},
		{"INFO:  Route to gateway exists already.", "", ""},
		{"WARN:   Could not set route " + strings.Repeat("x", maxOutputLine), "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.line[:min(len(tc.line), 100)], func(t *testing.T) {
			var parser Parser
			events := parser.Parse(tc.line + "\r\n")
			if len(events) != 1 {
				t.Fatalf("observations: %#v", events)
			}
			if tc.reason == "" {
				if got, ok := events[0].(Unknown); !ok || got.Line != tc.line {
					t.Fatalf("diagnostic became a failure: %#v", events)
				}
				return
			}
			got, ok := events[0].(RouteRejected)
			_, text := splitPrefix(tc.line)
			var prefix netip.Prefix
			if tc.prefix != "" {
				prefix = netip.MustParsePrefix(tc.prefix)
			}
			if !ok || got.Reason != tc.reason || got.Prefix != prefix || got.Message != text {
				t.Fatalf("rejection: %#v", events)
			}
		})
	}
}

// TestGatewaySuffixes preserves tunnel addresses when an unvalidated gateway suffix
// contains brackets, controls, or invalid DNS text. Valid suffixes retain their spelling;
// controls are stripped and invalid names degrade to an empty suffix without failure.
func TestGatewaySuffixes(t *testing.T) {
	cases := []struct {
		suffix string
		want   string
	}{
		{"corp.example.com", "corp.example.com"}, {"Corp.Example.com", "Corp.Example.com"},
		{"", ""}, {"corp[example].com", ""}, {"corp]example[.com", ""},
		{"corp\x00\r\n.example.com", "corp.example.com"}, {"corp\t.example.com", "corp.example.com"},
		{"not a domain", ""}, {"-corp.example.com", ""}, {"corp-.example.com", ""},
		{"corp..example.com", ""}, {strings.Repeat("a", 64) + ".example.com", ""},
		{strings.Repeat("example.", 40) + "com", ""}, {"é.example.com", ""},
	}
	for _, tc := range cases {
		t.Run(tc.suffix, func(t *testing.T) {
			var parser Parser
			line := "INFO:   Got addresses: [10.20.0.10], ns [10.20.0.1, 0.0.0.0], ns_suffix [" + tc.suffix + "]"
			want := []Event{GotAddresses{LocalIP: netip.MustParseAddr("10.20.0.10"), DNS: []netip.Addr{netip.MustParseAddr("10.20.0.1")}, Suffix: tc.want}}
			if got := parser.Parse(line); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		})
	}
}

// TestCertificateBoundaries proves only final digests become trust data and pending
// blocks flush at EOF, unknown lines, malformed digests, and metadata size bounds.
func TestCertificateBoundaries(t *testing.T) {
	for _, ending := range []string{"", "INFO:   Authenticated.", "ERROR:          bad", "ERROR:          " + strings.Repeat("g", 64)} {
		var parser Parser
		for _, line := range []string{"ERROR:  " + certStart, "ERROR:      --trusted-cert " + strings.Repeat("a", 64), "ERROR:      subject:", "ERROR:          CN=vpn.example.com", "ERROR:      issuer:", "ERROR:          CN=Example CA", "ERROR:      sha256 digest:"} {
			if got := parser.Parse(line); len(got) != 0 {
				t.Fatalf("premature event: %#v", got)
			}
		}
		var got []Event
		if ending != "" {
			got = parser.Parse(ending)
		}
		got = append(got, parser.Flush()...)
		if len(got) == 0 {
			t.Fatal("missing rejection")
		}
		cert, ok := got[0].(CertRejected)
		if !ok || cert.Digest != "" || cert.Subject != "CN=vpn.example.com" || cert.Issuer != "CN=Example CA" {
			t.Fatalf("incorrect incomplete rejection: %#v", got)
		}
		if parser.Flush() != nil {
			t.Fatal("duplicate EOF rejection")
		}
	}
	var parser Parser
	parser.Parse("ERROR:  " + certStart)
	parser.Parse("ERROR:      subject:")
	got := parser.Parse("ERROR:          " + strings.Repeat("a", maxCertText))
	if len(got) != 2 || parser.cert != nil {
		t.Fatalf("unbounded metadata or swallowed line: %#v", got)
	}
	parser.Parse("ERROR:  " + certStart)
	if got := parser.Parse("ERROR:      issuer:"); len(got) != 2 {
		t.Fatalf("invalid section order accepted: %#v", got)
	}
}

// FuzzParser checks arbitrary line streams for panics, bounded certificate storage,
// and valid emitted address and digest payloads. It seeds all synthetic transcripts.
func FuzzParser(f *testing.F) {
	for _, name := range []string{"success", "auth_failure", "cert_rejection", "pppd_failure", "gateway_drop", "early_exit"} {
		data, err := os.ReadFile("testdata/" + name + ".txt")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(data))
	}
	f.Add("INFO:   Route to gateway exists already.")
	f.Add("route: writing to routing socket: File exists\nadd net 10.20.0.0/16: gateway ppp0: File exists")
	f.Add("WARN:   Could not set route to tunnel gateway (Permission denied).")
	f.Add("INFO:   Got addresses: [bad], ns [bad]")
	f.Add("INFO:   Got addresses: [10.20.0.10], ns [10.20.0.1, 0.0.0.0], ns_suffix [corp[example].com]")
	f.Add("INFO:   Got addresses: [10.20.0.10], ns [], ns_suffix [corp\x00\r.example.com]")
	f.Fuzz(func(t *testing.T, input string) {
		var parser Parser
		var events []Event
		for line := range strings.SplitSeq(input, "\n") {
			events = append(events, parser.Parse(line)...)
			if parser.cert != nil && len(parser.cert.Subject)+len(parser.cert.Issuer) > maxCertText {
				t.Fatal("unbounded certificate metadata")
			}
		}
		events = append(events, parser.Flush()...)
		for _, event := range events {
			switch event := event.(type) {
			case GotAddresses:
				if !event.LocalIP.Is4() || event.LocalIP.IsUnspecified() {
					t.Fatal("invalid local address")
				}
			case CertRejected:
				if event.Digest != "" && (len(event.Digest) != 64 || strings.ToLower(event.Digest) != event.Digest) {
					t.Fatal("invalid digest")
				}
			}
		}
	})
}
