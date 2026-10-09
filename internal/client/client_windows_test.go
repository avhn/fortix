package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/protocol"
)

// observedConn records transport use so failed verification cannot hide a hello write or read.
type observedConn struct {
	net.Conn
	writes, reads int
	closed        bool
}

// Write records even an empty attempted write without retaining credentials.
func (c *observedConn) Write(data []byte) (int, error) { c.writes++; return len(data), nil }

// Read records reader startup and terminates rather than blocking a failed-verification test.
func (c *observedConn) Read([]byte) (int, error) { c.reads++; return 0, io.EOF }

// Close records resource release without requiring a native pipe handle.
func (c *observedConn) Close() error { c.closed = true; return nil }

// installedIdentity supplies a synthetic running own-process service under protected binaries.
func installedIdentity() serviceIdentity {
	return serviceIdentity{
		pipePID: 42, servicePID: 42, state: windows.SERVICE_RUNNING,
		serviceType: windows.SERVICE_WIN32_OWN_PROCESS, configType: windows.SERVICE_WIN32_OWN_PROCESS,
		image: `C:\Program Files\Fortix\fortix-helper.exe`, binary: `"C:\Program Files\Fortix\fortix-helper.exe"`,
		directory: `C:\Program Files\Fortix`, localSystem: true,
	}
}

// TestWindowsIdentityMismatchWritesNothing checks every trust fact before any protocol I/O.
// Diagnostics are stable and do not expose the underlying process/configuration inspection error.
func TestWindowsIdentityMismatchWritesNothing(t *testing.T) {
	t.Setenv("FORTIX_SOCKET", "")
	for _, tc := range []struct {
		name   string
		change func(*serviceIdentity)
	}{
		{"zero PID", func(i *serviceIdentity) { i.pipePID, i.servicePID = 0, 0 }},
		{"foreign PID", func(i *serviceIdentity) { i.pipePID++ }},
		{"stopped", func(i *serviceIdentity) { i.state = windows.SERVICE_STOPPED }},
		{"shared process", func(i *serviceIdentity) { i.serviceType = windows.SERVICE_WIN32_SHARE_PROCESS }},
		{"wrong config type", func(i *serviceIdentity) { i.configType = windows.SERVICE_WIN32_SHARE_PROCESS }},
		{"different image", func(i *serviceIdentity) { i.image = `C:\Program Files\Fortix\foreign.exe` }},
		{"outside installation", func(i *serviceIdentity) { i.image = `C:\Temp\fortix-helper.exe`; i.binary = i.image }},
		{"sibling directory", func(i *serviceIdentity) {
			i.image = `C:\Program Files\FortixOther\fortix-helper.exe`
			i.binary = i.image
		}},
		{"traversal", func(i *serviceIdentity) { i.image = `C:\Program Files\Fortix\..\foreign.exe`; i.binary = i.image }},
		{"device path", func(i *serviceIdentity) {
			i.image = `\\?\C:\Program Files\Fortix\fortix-helper.exe`
			i.binary = i.image
		}},
		{"arguments", func(i *serviceIdentity) { i.binary += " --foreign" }},
		{"user token", func(i *serviceIdentity) { i.localSystem = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := installedIdentity()
			tc.change(&identity)
			conn := &observedConn{}
			_, err := dialVerified(t.Context(), Options{Dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }},
				func(context.Context, net.Conn) error { return validateServiceIdentity(identity) })
			if err == nil || err.Error() != "the Fortix helper service could not be verified" || !conn.closed || conn.writes != 0 || conn.reads != 0 {
				t.Fatalf("verification: err=%v closed=%v writes=%d reads=%d", err, conn.closed, conn.writes, conn.reads)
			}
		})
	}
}

// TestWindowsIdentityCanonicalImage accepts quoted configuration and case-insensitive Windows paths.
func TestWindowsIdentityCanonicalImage(t *testing.T) {
	identity := installedIdentity()
	for _, binary := range []string{identity.binary, identity.image, strings.ToUpper(identity.image)} {
		identity.binary = binary
		if err := validateServiceIdentity(identity); err != nil {
			t.Fatal(err)
		}
	}
}

// TestWindowsInjectedTransportCannotSkipVerification covers the exported production entry point.
func TestWindowsInjectedTransportCannotSkipVerification(t *testing.T) {
	t.Setenv("FORTIX_SOCKET", "")
	conn := &observedConn{}
	_, err := Dial(t.Context(), Options{Dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }})
	if err == nil || !conn.closed || conn.writes != 0 || conn.reads != 0 {
		t.Fatalf("injected transport bypass: %v, %+v", err, conn)
	}
}

// TestWindowsDialDiagnostics preserves permission identity and supplies Windows repair instructions.
func TestWindowsDialDiagnostics(t *testing.T) {
	t.Setenv("FORTIX_SOCKET", "")
	for _, tc := range []struct {
		err  error
		want string
	}{
		{windows.ERROR_ACCESS_DENIED, "net localgroup fortix <user> /add"},
		{windows.ERROR_FILE_NOT_FOUND, "fortix-helper install from an elevated terminal"},
	} {
		_, err := Dial(t.Context(), Options{Dial: func(context.Context, string, string) (net.Conn, error) { return nil, tc.err }})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatal(err)
		}
		if tc.err == windows.ERROR_ACCESS_DENIED && !errors.Is(err, os.ErrPermission) {
			t.Fatal("permission identity lost")
		}
	}
	if message := (&OperationError{Code: protocol.Unauthorized}).Error(); !strings.Contains(message, "sign out and back in") {
		t.Fatal(message)
	}
}

// TestWindowsPipeEndpointCannotRedirect rejects remote or filesystem overrides before dialing.
func TestWindowsPipeEndpointCannotRedirect(t *testing.T) {
	t.Setenv("FORTIX_SOCKET", `\\server\pipe\Fortix.Control.v1`)
	if _, err := socketPath(Options{}); err == nil {
		t.Fatal("accepted remote pipe")
	}
	path, err := socketPath(Options{Socket: `\\.\pipe\Fortix.Control.v1`})
	if err != nil || path != `\\.\pipe\Fortix.Control.v1` {
		t.Fatalf("fixed endpoint: %q %v", path, err)
	}
}

// TestWindowsVerifiedHandshakeAndCalls preserves hello, correlation, events and cancellable waits.
// The injected verifier must finish before the server sees hello; Close joins both sides.
func TestWindowsVerifiedHandshakeAndCalls(t *testing.T) {
	t.Setenv("FORTIX_SOCKET", "")
	local, remote := net.Pipe()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	verified := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer remote.Close()
		reader := protocol.NewReader(remote)
		var request protocol.Request
		if err := reader.Read(&request); err != nil {
			t.Error(err)
			return
		}
		select {
		case <-verified:
		default:
			t.Error("hello preceded verification")
		}
		if request.Op != "hello" || request.Version == "" {
			t.Error("invalid hello")
		}
		if err := protocol.Write(remote, protocol.Result{Type: "result", ID: request.ID, OK: true, Data: map[string]any{"protocol": protocol.Version}}); err != nil {
			t.Error(err)
			return
		}
		if err := reader.Read(&request); err != nil {
			t.Error(err)
			return
		}
		if err := protocol.Write(remote, protocol.Event{Type: "state", Profile: "office", State: "connected"}); err != nil {
			t.Error(err)
			return
		}
		if err := protocol.Write(remote, protocol.Result{Type: "result", ID: request.ID, OK: true, Data: "correlated"}); err != nil {
			t.Error(err)
			return
		}
		_, _ = io.Copy(io.Discard, remote)
	}()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close(); <-done })
	client, err := dialVerified(ctx, Options{Dial: func(context.Context, string, string) (net.Conn, error) { return local, nil }},
		func(context.Context, net.Conn) error { close(verified); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var result string
	if err := client.Call(ctx, protocol.Request{Op: "status"}, &result); err != nil || result != "correlated" {
		t.Fatalf("status: %q %v", result, err)
	}
	select {
	case event := <-client.Events():
		if event.Profile != "office" || event.State != "connected" {
			t.Fatal(event)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waiting, stop := context.WithTimeout(ctx, 25*time.Millisecond)
	defer stop()
	if err := client.Call(waiting, protocol.Request{Op: "status"}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(client.Err(), net.ErrClosed) {
		t.Fatal(client.Err())
	}
}
