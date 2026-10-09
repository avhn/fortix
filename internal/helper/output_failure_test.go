//go:build darwin || linux

package helper

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// failedOutputReader injects a scanner I/O failure without opening a process pipe.
type failedOutputReader struct{}

// Read returns a fixed synthetic stream failure without exposing input bytes.
func (failedOutputReader) Read([]byte) (int, error) {
	return 0, errors.New("injected stream failure")
}

// TestExternalOutputFailure separates log writes, oversized lines and scanner errors
// from pushed-route failures. The adapter emits a terminal Outcome only after reaping.
func TestExternalOutputFailure(t *testing.T) {
	for _, scenario := range []string{"log write", "overlong line", "scanner error"} {
		t.Run(scenario, func(t *testing.T) {
			log, err := openLog(t.TempDir(), "work")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = log.Close() }()
			var reader io.Reader = strings.NewReader("INFO:   Authenticated.\n")
			switch scenario {
			case "log write":
				if err := log.file.Close(); err != nil {
					t.Fatal(err)
				}
			case "overlong line":
				reader = strings.NewReader(strings.Repeat("x", protocol.MaxLine+2))
			case "scanner error":
				reader = failedOutputReader{}
			}
			tunnel := &openfortivpnTunnel{raw: make(chan session.Event, 8), events: make(chan backend.Event, 8), done: make(chan struct{})}
			sink := &supervisor{id: "work", server: &Server{}, events: tunnel.raw, stopped: tunnel.done}
			sink.scanOutput(reader, 7, log, true)
			tunnel.raw <- session.Event{Profile: "work", Attempt: 7, Kind: session.ProcessExited}
			close(tunnel.raw)
			tunnel.observe()
			if event := <-tunnel.events; event != (backend.OutputFailed{}) {
				t.Fatalf("stream failure mislabeled: %T", event)
			}
			if event := <-tunnel.events; event != (backend.Outcome{}) {
				t.Fatalf("reaped outcome missing: %T", event)
			}
			if _, open := <-tunnel.events; open {
				t.Fatal("unexpected extra event")
			}
			if err := tunnel.Wait(); err != nil {
				t.Fatalf("successful child exit changed: %v", err)
			}
		})
	}
}
