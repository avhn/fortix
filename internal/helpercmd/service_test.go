package helpercmd

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/protocol"
)

// TestDevelopmentService exercises both default and explicit serve dispatch in the
// current process. All helper directories are under an isolated non-root root;
// cancellation must close its listeners and return success without privileged work.
func TestDevelopmentService(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("development service requires a non-root user")
	}
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "serve"}[explicit], func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "fortix-command-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.RemoveAll(root) }()
			argv := []string{"fortix-helper"}
			if explicit {
				argv = append(argv, "serve")
			}
			argv = append(argv, "--dev-root", root)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Run(ctx, argv, nil, io.Discard, io.Discard) }()
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("development service did not stop")
				}
			}()
			var conn net.Conn
			tick := time.NewTicker(5 * time.Millisecond)
			defer tick.Stop()
			for {
				conn, err = net.DialTimeout("unix", filepath.Join(root, "run/fortix.sock"), 50*time.Millisecond)
				if err == nil {
					break
				}
				select {
				case err := <-done:
					done <- err
					t.Fatalf("service startup failed: %v", err)
				case <-ctx.Done():
					t.Fatal("development socket did not open")
				case <-tick.C:
				}
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := protocol.Write(conn, protocol.Request{ID: "hello", Op: "hello", Version: "dev"}); err != nil {
				t.Fatal(err)
			}
			var result protocol.Result
			if err := protocol.NewReader(conn).Read(&result); err != nil || !result.OK || result.ID != "hello" {
				t.Fatalf("development authorization/hello failed: %+v, %v", result, err)
			}
		})
	}
}
