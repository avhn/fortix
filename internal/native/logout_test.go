package native

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLogoutRecordedPeer proves normal shutdown and failed-login cleanup use the
// verified TLS peer even when hostname dialing becomes unavailable. Host and SNI
// retain the configured DNS identity, and every logout uses a fresh connection.
func TestLogoutRecordedPeer(t *testing.T) {
	for _, scenario := range []string{"connected", "allocation failed", "reconnect failed", "config failed"} {
		t.Run(scenario, func(t *testing.T) {
			var hostnameUnavailable atomic.Bool
			var logouts atomic.Int64
			server, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/remote/logincheck":
					w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture")
					_, _ = io.WriteString(w, "ret=1")
				case "/remote/index":
					if scenario == "allocation failed" {
						hostnameUnavailable.Store(true)
						w.WriteHeader(http.StatusServiceUnavailable)
					}
				case "/remote/fortisslvpn_xml":
					if scenario == "config failed" {
						hostnameUnavailable.Store(true)
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					_, _ = io.WriteString(w, fixtureXML)
				case "/remote/logout":
					if r.Host != "gateway.test:443" || r.TLS.ServerName != "gateway.test" || r.Header.Get("Cookie") != "SVPNCOOKIE=fixture" {
						t.Error("logout lost configured HTTP or TLS identity")
					}
					logouts.Add(1)
				}
			})
			var mu sync.Mutex
			var addresses []string
			options.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				mu.Lock()
				addresses = append(addresses, address)
				count := len(addresses)
				mu.Unlock()
				if scenario == "reconnect failed" && count == 2 {
					hostnameUnavailable.Store(true)
					return nil, errors.New("injected reconnect failure")
				}
				if hostnameUnavailable.Load() && strings.HasPrefix(address, "gateway.test:") {
					return nil, errors.New("hostname path unavailable through stopped tunnel")
				}
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			tunnel, err := client.Login(ctx, loginCredentials())
			if scenario == "connected" {
				if err != nil {
					t.Fatal(err)
				}
				hostnameUnavailable.Store(true)
				_ = tunnel.Close()
				if err := tunnel.Logout(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				_ = tunnel.Close()
				t.Fatal("injected login failure succeeded")
			}
			mu.Lock()
			defer mu.Unlock()
			if logouts.Load() != 1 || len(addresses) < 2 || addresses[len(addresses)-1] != server.Listener.Addr().String() {
				t.Fatalf("logout did not use recorded peer: logouts=%d addresses=%v", logouts.Load(), addresses)
			}
		})
	}
}
