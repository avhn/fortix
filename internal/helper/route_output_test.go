package helper

import (
	"os"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/openfortivpn"
	"github.com/avhn/fortix/internal/session"
)

// TestRouteOutputStreams verifies route-tool failures become attempt-bound
// observations from both pipes, while unrelated stderr stays diagnostic only.
func TestRouteOutputStreams(t *testing.T) {
	for _, stdout := range []bool{true, false} {
		name := "stderr"
		if stdout {
			name = "stdout"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			log, err := openLog(dir, "work")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = log.Close() }()
			a := &supervisor{id: "work", server: &Server{}, events: make(chan session.Event, 16), stopped: make(chan struct{})}
			a.scanOutput(strings.NewReader("INFO:   Route to gateway exists already.\nadd net 10.20.0.0: gateway ppp0: File exists\nWARN:   Could not set route to tunnel gateway (Permission denied).\nroute: writing to routing socket: File exists\nadd host 203.0.113.5: gateway 192.0.2.1: File exists\nWARN:   Could not set route to vpn server (File exists).\nWARN:   Route to vpn server exists already.\nINFO:   Authenticated.\n"), 7, log, stdout)
			for _, reason := range []openfortivpn.RouteRejectReason{openfortivpn.RouteConflict, openfortivpn.RouteConflict, openfortivpn.RouteFailed} {
				select {
				case event := <-a.events:
					rejection, ok := event.Observation.(openfortivpn.RouteRejected)
					if !ok || rejection.Reason != reason || event.Profile != "work" || event.Attempt != 7 || event.Kind != session.Output {
						t.Fatalf("observation: %#v", event)
					}
				default:
					t.Fatal("route rejection was not emitted")
				}
			}
			wantRemaining := 0
			if stdout {
				wantRemaining = 5
			}
			if len(a.events) != wantRemaining {
				t.Fatalf("remaining observations %d, want %d", len(a.events), wantRemaining)
			}
		})
	}
}
