// Package e2e exercises the installed Windows service only on explicitly enabled test hosts.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/native"
	"github.com/avhn/fortix/internal/ppp"
)

// simulatorPacket encodes bounded PPP control packets for the fake gateway peer.
func simulatorPacket(protocol uint16, code, id byte, data []byte) []byte {
	packet := make([]byte, 6+len(data))
	binary.BigEndian.PutUint16(packet, protocol)
	packet[2], packet[3] = code, id
	binary.BigEndian.PutUint16(packet[4:6], uint16(4+len(data)))
	copy(packet[6:], data)
	return packet
}

// simulatePPP adapts the existing helper assembly peer to documentation-only IPv4 ranges.
// Every option is bounds-checked, reads have deadlines, and shutdown acknowledges LCP termination.
func simulatePPP(conn net.Conn, reader io.Reader) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Minute))
	lcpSent, ipcpSent := false, false
	for {
		packet, err := native.ReadFrame(reader)
		if err != nil || len(packet) < 2 {
			return
		}
		protocol := binary.BigEndian.Uint16(packet)
		if protocol == ppp.ProtocolIPv4 {
			if native.WriteFrame(conn, packet) != nil {
				return
			}
			continue
		}
		control, err := ppp.DecodeControl(packet[2:])
		if err != nil {
			return
		}
		switch control.Code {
		case ppp.ConfigureRequest:
			code := byte(ppp.ConfigureAck)
			data := append([]byte(nil), control.Data...)
			if protocol == ppp.ProtocolIPCP {
				for i := 0; i < len(data); {
					if i+2 > len(data) || data[i+1] < 2 || i+int(data[i+1]) > len(data) {
						return
					}
					if data[i+1] == 6 {
						switch data[i] {
						case 3:
							if binary.BigEndian.Uint32(data[i+2:i+6]) == 0 {
								copy(data[i+2:i+6], []byte{198, 51, 100, 10})
							}
						case 129, 131:
							copy(data[i+2:i+6], []byte{198, 51, 100, 53})
						}
					}
					i += int(data[i+1])
				}
				if !reflect.DeepEqual(data, control.Data) {
					code = ppp.ConfigureNak
				}
			}
			if native.WriteFrame(conn, simulatorPacket(protocol, code, control.ID, data)) != nil {
				return
			}
			if protocol == ppp.ProtocolLCP && !lcpSent {
				lcpSent = true
				if native.WriteFrame(conn, simulatorPacket(protocol, ppp.ConfigureRequest, 71, []byte{1, 4, 5, 74, 5, 6, 0, 0, 0, 42})) != nil {
					return
				}
			}
			if protocol == ppp.ProtocolIPCP && !ipcpSent {
				ipcpSent = true
				if native.WriteFrame(conn, simulatorPacket(protocol, ppp.ConfigureRequest, 72, []byte{3, 6, 198, 51, 100, 1})) != nil {
					return
				}
			}
		case ppp.EchoRequest:
			if protocol != ppp.ProtocolLCP || len(control.Data) < 4 {
				return
			}
			data := append([]byte(nil), control.Data...)
			binary.BigEndian.PutUint32(data[:4], 42)
			if native.WriteFrame(conn, simulatorPacket(protocol, ppp.EchoReply, control.ID, data)) != nil {
				return
			}
		case ppp.TerminateRequest:
			_ = native.WriteFrame(conn, simulatorPacket(protocol, ppp.TerminateAck, control.ID, control.Data))
			return
		}
	}
}

// fakeGateway serves only loopback TLS and closes hijacked connections during test cleanup.
// Login, cookie validation, XML policy and PPP follow the existing helper assembly fixture.
func fakeGateway(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/remote/logincheck" {
			if r.ParseForm() != nil || r.Form.Get("username") != "fixture-user" || r.Form.Get("credential") != "fixture-password" {
				_, _ = io.WriteString(w, "ret=0")
				return
			}
			w.Header().Set("Set-Cookie", "SVPNCOOKIE=test-token")
			_, _ = io.WriteString(w, "ret=1")
			return
		}
		if r.Header.Get("Cookie") != "SVPNCOOKIE=test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/remote/fortisslvpn_xml":
			_, _ = io.WriteString(w, `<sslvpn><assigned-addr ipv4="198.51.100.10"/><dns ip="198.51.100.53" domain="example.test"/><split-tunnel-info><addr ip="203.0.113.0" mask="255.255.255.0"/></split-tunnel-info></sslvpn>`)
		case "/remote/sslvpn-tunnel":
			conn, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			simulatePPP(conn, buffer)
			mu.Lock()
			delete(connections, conn)
			mu.Unlock()
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 15 * time.Second
	server.Config.WriteTimeout = 15 * time.Second
	server.StartTLS()
	t.Cleanup(func() {
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		server.Close()
	})
	digest := sha256.Sum256(server.Certificate().Raw)
	return server, hex.EncodeToString(digest[:])
}

// framedPeer translates native SSL frames into the production PPP transport contract.
type framedPeer struct{ connection *native.Connection }

// ReadPacket keeps the fixture reader bounded by the test context deadline.
func (p framedPeer) ReadPacket(ctx context.Context) ([]byte, error) {
	deadline, _ := ctx.Deadline()
	if err := p.connection.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	return native.ReadFrame(p.connection)
}

// WritePacket keeps the fixture writer bounded without changing wire framing.
func (p framedPeer) WritePacket(ctx context.Context, packet []byte) error {
	deadline, _ := ctx.Deadline()
	if err := p.connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return native.WriteFrame(p.connection, packet)
}

// TestFakeGatewayProtocol runs the reusable TLS, cookie, XML and PPP fixture without elevation.
func TestFakeGatewayProtocol(t *testing.T) {
	server, fingerprint := fakeGateway(t)
	address := server.Listener.Addr().(*net.TCPAddr)
	c, err := native.NewClient(native.Options{Host: address.IP.String(), Port: address.Port, TrustedCert: fingerprint, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := c.Login(ctx, native.Credentials{Username: "fixture-user", Password: []byte("fixture-password")})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if connection.Config.AssignedIP.String() != "198.51.100.10" || len(connection.Config.DNS) != 1 || connection.Config.DNS[0].String() != "198.51.100.53" || !reflect.DeepEqual(connection.Config.Domains, []string{"example.test"}) || len(connection.Config.SplitRoutes) != 1 || connection.Config.SplitRoutes[0].String() != "203.0.113.0/24" {
		t.Fatalf("wrong pushed configuration: %+v", connection.Config)
	}
	info, err := ppp.Negotiate(ctx, framedPeer{connection}, ppp.Config{Magic: 7, RetryInterval: 30 * time.Millisecond, NegotiationTimeout: 3 * time.Second, EchoInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if info.LocalIP.String() != "198.51.100.10" || info.PrimaryDNS.String() != "198.51.100.53" || info.SecondaryDNS.String() != "198.51.100.53" {
		t.Fatalf("wrong negotiated configuration: %+v", info)
	}
	// Several echo intervals catch a peer that echoes our magic instead of its own.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(150 * time.Millisecond):
	}
	if _, open := info.Link.Info(); !open {
		t.Fatal("fake PPP peer did not maintain negotiated keepalive")
	}
	if err := info.Link.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := connection.Logout(ctx); err != nil {
		t.Fatal(err)
	}
}
