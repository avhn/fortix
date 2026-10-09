//go:build darwin || linux

package pinentry

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/protocol"
)

// TestRelayAssuan exercises the actual Unix relay bridge and Assuan escaping for
// success and cancellation without exposing fixture secrets to a process argv.
func TestRelayAssuan(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "answer", true: "cancel"}[cancelled], func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "px-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.RemoveAll(dir) }()
			path := filepath.Join(dir, "relay.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			token := strings.Repeat("a", 64)
			finished := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					finished <- err
					return
				}
				defer func() { _ = conn.Close() }()
				if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
					finished <- err
					return
				}
				var request Request
				if err := protocol.NewReader(conn).Read(&request); err != nil {
					finished <- err
					return
				}
				if request.Token != token || request.KeyInfo != "example_password" || request.Prompt != "Password:" {
					finished <- context.Canceled
					return
				}
				finished <- protocol.Write(conn, Response{Secret: "a%\nb", Cancel: cancelled})
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var output bytes.Buffer
			err = Run(ctx, Config{Socket: path, Token: token}, strings.NewReader("SETKEYINFO example_password\nSETPROMPT Password:\nGETPIN\nBYE\n"), &output)
			if err != nil {
				t.Fatal(err)
			}
			if cancelled {
				if !strings.Contains(output.String(), "ERR 83886179 Operation cancelled") {
					t.Fatal("cancellation not relayed")
				}
			} else {
				if !strings.Contains(output.String(), "D a%25%0Ab\nOK\n") {
					t.Fatal("credential escaping failed")
				}
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestInvalidConfig rejects relative socket paths and malformed capabilities before
// any relay connection is attempted or Assuan response is written.
func TestInvalidConfig(t *testing.T) {
	for _, config := range []Config{{Socket: "relative", Token: strings.Repeat("a", 64)}, {Socket: "/tmp/pinentry.sock", Token: "bad"}, {Socket: "/tmp/pinentry.sock", Token: strings.Repeat("z", 64)}} {
		var output bytes.Buffer
		if Run(context.Background(), config, strings.NewReader("GETPIN\n"), &output) == nil || output.Len() != 0 {
			t.Fatal("accepted invalid relay configuration")
		}
	}
}

// FuzzRelayRequest checks the relay's strict bounded envelope independently from
// the Assuan parser, which has its own fragmentation and escaping fuzz coverage.
func FuzzRelayRequest(f *testing.F) {
	f.Add([]byte(`{"token":"abc","keyinfo":"example_password","prompt":"Password:"}`))
	f.Add([]byte(`{"token":"a","token":"b"}`))
	f.Fuzz(func(_ *testing.T, data []byte) { var request Request; _ = protocol.Decode(data, &request) })
}
