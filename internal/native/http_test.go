package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// connectionKey identifies the accepted TLS connection in fixture request contexts.
type connectionKey struct{}

// gatewayCertificate creates a short-lived self-signed fixture CA/leaf with a DNS SAN.
func gatewayCertificate(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// fakeGateway starts an in-process TLS server and returns direct-dial trusted options.
// No privileged network operation, external gateway, proxy, or credentials are used.
func fakeGateway(t *testing.T, handler http.HandlerFunc) (*httptest.Server, Options) {
	t.Helper()
	certificate := gatewayCertificate(t, "gateway.test")
	server := httptest.NewUnstartedServer(handler)
	var accepted atomic.Int64
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connectionKey{}, accepted.Add(1))
	}
	server.Config.ReadHeaderTimeout = 3 * time.Second
	server.Config.WriteTimeout = 3 * time.Second
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	options := Options{
		Host: "gateway.test", RootCAs: roots, Timeout: time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	return server, options
}

// loginCredentials returns bounded synthetic account data, including form metacharacters.
func loginCredentials() Credentials {
	return Credentials{Username: "test+user", Password: []byte("not-a-secret&="), Realm: "office"}
}

// TestGatewaySequence verifies endpoint order, TLS identity, form encoding, tunnel Host,
// buffered frame delivery, and fresh-connection logout without proxy environment use.
func TestGatewaySequence(t *testing.T) {
	testGatewaySequence(t, false)
}

// TestGatewayAllocationClose verifies a fully consumed closing allocation response is
// followed by configuration and tunnel setup on a new verified TLS connection.
func TestGatewayAllocationClose(t *testing.T) {
	testGatewaySequence(t, true)
}

// testGatewaySequence exercises authentication through logout against a fake gateway.
// closeAllocation closes the allocation response connection to test mandatory TLS
// reconnection, while connection identities verify configuration and tunnel reuse.
func testGatewaySequence(t *testing.T, closeAllocation bool) {
	t.Helper()
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	var mu sync.Mutex
	var paths []string
	var connections []int64
	_, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		connections = append(connections, r.Context().Value(connectionKey{}).(int64))
		mu.Unlock()
		if r.Proto != "HTTP/1.1" {
			t.Error("wrong HTTP protocol")
		}
		if r.UserAgent() != userAgent {
			t.Error("wrong User-Agent")
		}
		if r.URL.Path == "/remote/logincheck" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Method != http.MethodPost || r.Form.Get("username") != "test+user" || r.Form.Get("credential") != "not-a-secret&=" || r.Form.Get("realm") != "office" || r.Form.Get("ajax") != "1" {
				t.Error("incorrect login form")
			}
			w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture-token; Secure; HttpOnly")
			_, _ = io.WriteString(w, "ret=1")
			return
		}
		if r.Method != http.MethodGet || r.Header.Get("Cookie") != "SVPNCOOKIE=fixture-token" {
			t.Error("missing session cookie or wrong method")
		}
		switch r.URL.Path {
		case "/remote/fortisslvpn":
			if closeAllocation {
				w.Header().Set("Connection", "close")
			}
			_, _ = io.WriteString(w, "ok")
		case "/remote/fortisslvpn_xml":
			_, _ = io.WriteString(w, fixtureXML)
		case "/remote/sslvpn-tunnel":
			if r.Host != "sslvpn" {
				t.Error("wrong tunnel Host")
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = conn.Close() }()
			var frames bytes.Buffer
			_ = WriteFrame(&frames, []byte{0xc0, 0x21, 1, 2})
			_ = WriteFrame(&frames, []byte{0x80, 0x21, 3, 4})
			wire := frames.Bytes()
			for _, fragment := range [][]byte{wire[:1], wire[1:4], wire[4:]} {
				if _, err := conn.Write(fragment); err != nil {
					t.Error(err)
				}
			}
		default:
			_, _ = io.WriteString(w, "ok")
		}
	})
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunnel, err := client.Login(ctx, loginCredentials())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tunnel.Close() }()
	if tunnel.Config.AssignedIP.String() != "10.20.30.40" {
		t.Fatal("missing XML configuration")
	}
	if err := tunnel.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{{0xc0, 0x21, 1, 2}, {0x80, 0x21, 3, 4}} {
		got, err := ReadFrame(tunnel)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("tunnel frame: %v %v", got, err)
		}
	}
	if err := tunnel.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := "/remote/logincheck,/remote/index,/remote/fortisslvpn,/remote/fortisslvpn_xml,/remote/sslvpn-tunnel,/remote/logout"
	if strings.Join(paths, ",") != want {
		t.Fatalf("sequence: %v", paths)
	}
	if connections[0] != connections[1] || connections[1] != connections[2] || connections[2] == connections[3] || connections[3] != connections[4] || connections[5] == connections[4] || connections[5] == connections[0] {
		t.Fatalf("incorrect TLS reuse: %v", connections)
	}
}

// TestLoginRejections checks typed MFA and auth failures, bounded cookie extraction,
// body/header limits, and redaction of all gateway-controlled error text.
func TestLoginRejections(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		cookie string
		mfa    bool
		auth   bool
	}{
		{"tokeninfo", 200, "ret=2&tokeninfo=SECRET", "", true, false},
		{"tokeninfo-cookie", 200, "ret=2&tokeninfo=SECRET", "SVPNCOOKIE=fixture", true, false},
		{"challenge", 200, "ret=6", "", true, false},
		{"named-challenge", 200, "challenge=SECRET", "", true, false},
		{"html-otp", 401, `<FORM ACTION="/remote/logincheck">SECRET</FORM>`, "", true, false},
		{"auth", 200, "ret=0&message=SECRET", "", false, true},
		{"ret-zero-cookie", 200, "ret=0", "SVPNCOOKIE=SECRET", false, true},
		{"no-cookie", 200, "ret=1&message=SECRET", "", false, true},
		{"empty-cookie", 200, "ret=1", "SVPNCOOKIE=", false, true},
		{"large-cookie", 200, "ret=1", "SVPNCOOKIE=" + strings.Repeat("S", maxCookie+1), false, true},
		{"invalid-cookie", 200, "ret=1", `SVPNCOOKIE="SECRET"`, false, true},
		{"large-body", 200, strings.Repeat("S", maxLoginBody+1), "", false, false},
		{"large-header", 200, "ret=1", "SVPNCOOKIE=" + strings.Repeat("S", maxHTTPHeader), false, false},
		{"redirect", 302, "SECRET", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/remote/logincheck" {
					t.Error("followed rejected login or redirect")
				}
				if tc.cookie != "" {
					w.Header().Set("Set-Cookie", tc.cookie)
				}
				w.Header().Set("Location", "/unexpected")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Login(context.Background(), loginCredentials())
			if err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("expected sanitized error, got %v", err)
			}
			var mfa *UnsupportedMFA
			if errors.As(err, &mfa) != tc.mfa || errors.Is(err, ErrAuthentication) != tc.auth {
				t.Fatalf("wrong error type: %T %v", err, err)
			}
		})
	}
}

// TestHTTPFailures verifies malformed HTTP, compressed bodies, truncation, and early
// connection closure fail safely without leaking status or body text.
func TestHTTPFailures(t *testing.T) {
	cases := map[string]string{
		"bad-status":     "HTTP/1.1 SECRET\r\n\r\n",
		"old-http":       "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
		"gzip":           "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
		"truncated":      "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nSECRET",
		"bad-chunk":      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nSECRET\r\n",
		"close":          "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
		"partial-header": "HTTP/1.1 200 OK\r\n",
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			_, options := fakeGateway(t, func(w http.ResponseWriter, _ *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = conn.Close() }()
				_, _ = io.WriteString(conn, response)
			})
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Login(context.Background(), loginCredentials())
			if err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("expected sanitized HTTP failure: %v", err)
			}
		})
	}
}

// TestTunnelDenial verifies HTTP tunnel rejection is detected by the first frame read.
func TestTunnelDenial(t *testing.T) {
	_, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/remote/logincheck":
			w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture")
		case "/remote/fortisslvpn_xml":
			_, _ = io.WriteString(w, "<config/>")
		case "/remote/sslvpn-tunnel":
			http.Error(w, "SECRET", http.StatusForbidden)
		}
	})
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := client.Login(context.Background(), loginCredentials())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tunnel.Close() }()
	if n, err := tunnel.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
	for range 2 {
		if _, err := ReadFrame(tunnel); !errors.Is(err, ErrTunnelDenied) {
			t.Fatalf("tunnel rejection: %v", err)
		}
	}
}

// TestAllocationStatusIgnored verifies non-200 allocation responses still reach the
// configuration fetch, matching gateways that answer /remote/index with 403.
func TestAllocationStatusIgnored(t *testing.T) {
	for _, path := range []string{"/remote/index", "/remote/fortisslvpn"} {
		t.Run(path, func(t *testing.T) {
			_, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case path:
					w.WriteHeader(http.StatusForbidden)
				case "/remote/logincheck":
					w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture")
					_, _ = io.WriteString(w, "ret=1")
				case "/remote/fortisslvpn_xml":
					_, _ = io.WriteString(w, fixtureXML)
				}
			})
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			tunnel, err := client.Login(context.Background(), loginCredentials())
			if err != nil {
				t.Fatalf("allocation status was not ignored: %v", err)
			}
			_ = tunnel.Close()
		})
	}
}

// TestHTTPStatusFailures verifies config/logout statuses are not followed.
func TestHTTPStatusFailures(t *testing.T) {
	for _, path := range []string{"/remote/fortisslvpn_xml", "/remote/logout"} {
		t.Run(path, func(t *testing.T) {
			_, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == path {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if r.URL.Path == "/remote/logincheck" {
					w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture")
				}
				if r.URL.Path == "/remote/fortisslvpn_xml" {
					_, _ = io.WriteString(w, "<config/>")
				}
			})
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			tunnel, err := client.Login(context.Background(), loginCredentials())
			if tunnel != nil {
				defer func() { _ = tunnel.Close() }()
				err = tunnel.Logout(context.Background())
			}
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.Path != path || httpErr.Status != http.StatusForbidden {
				t.Fatalf("wrong HTTP failure: %v", err)
			}
		})
	}
}

// TestRequiredHTTPConnectionClose verifies closing responses are rejected when the
// login, index, or configuration connection must serve another protocol request.
func TestRequiredHTTPConnectionClose(t *testing.T) {
	for _, path := range []string{"/remote/logincheck", "/remote/index", "/remote/fortisslvpn_xml"} {
		t.Run(path, func(t *testing.T) {
			_, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == path {
					w.Header().Set("Connection", "close")
				}
				switch r.URL.Path {
				case "/remote/logincheck":
					w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture")
					_, _ = io.WriteString(w, "ret=1")
				case "/remote/fortisslvpn_xml":
					_, _ = io.WriteString(w, fixtureXML)
				case "/remote/sslvpn-tunnel":
					t.Error("switched to tunnel after required HTTP connection closed")
				}
			})
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			tunnel, err := client.Login(context.Background(), loginCredentials())
			if tunnel != nil {
				_ = tunnel.Close()
			}
			if err == nil || err.Error() != "gateway closed a required HTTP session" {
				t.Fatalf("expected required HTTP connection failure, got %v", err)
			}
		})
	}
}

// TestCookieParsing rejects duplicates and invalid values without returning their data.
func TestCookieParsing(t *testing.T) {
	for _, values := range [][]string{
		{"SVPNCOOKIE=first", "SVPNCOOKIE=second"}, {"SVPNCOOKIE=SECRET space"},
		{"SVPNCOOKIE=SECRET\\escape"}, {"other=SECRET"}, {"SVPNCOOKIE=SECRET\x7f"},
	} {
		header := http.Header{"Set-Cookie": values}
		if value, err := sessionCookie(header); value != "" || !errors.Is(err, ErrAuthentication) {
			t.Fatalf("cookie rejection: %v", err)
		}
	}
	header := http.Header{"Set-Cookie": {"other=irrelevant", "SVPNCOOKIE=abc+/=; Secure"}}
	if value, err := sessionCookie(header); err != nil || value != "SVPNCOOKIE=abc+/=" {
		t.Fatal("valid cookie rejected")
	}
}

// TestLoginCancellation bounds a silent server and ensures invalid credentials never dial.
func TestLoginCancellation(t *testing.T) {
	_, options := fakeGateway(t, func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	})
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := client.Login(ctx, loginCredentials()); err == nil || time.Since(start) > time.Second {
		t.Fatalf("cancellation was not bounded: %v", err)
	}
	options.DialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Error("dialed for invalid credentials")
		return nil, fmt.Errorf("unexpected dial")
	}
	client, err = NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, credentials := range []Credentials{{}, {Username: "test", Password: []byte{}}, {Username: strings.Repeat("x", 257), Password: []byte("x")}, {Username: "test", Password: bytes.Repeat([]byte{1}, 4097)}, {Username: "test", Password: []byte("x"), Realm: strings.Repeat("x", 257)}} {
		if _, err := client.Login(context.Background(), credentials); err == nil {
			t.Fatal("invalid credentials accepted")
		}
	}
}

// TestTunnelTruncation preserves incomplete headers and terminal EOF during handoff.
func TestTunnelTruncation(t *testing.T) {
	for size := 0; size < FrameHeaderSize; size++ {
		tunnel := &Connection{reader: bufio.NewReader(bytes.NewReader(make([]byte, size)))}
		_, err := ReadFrame(tunnel)
		want := io.ErrUnexpectedEOF
		if size == 0 {
			want = io.EOF
		}
		if !errors.Is(err, want) {
			t.Fatalf("header length %d: %v", size, err)
		}
	}
}

// TestInvalidConfig closes transport resources and logs out after invalid XML.
func TestInvalidConfig(t *testing.T) {
	var loggedOut atomic.Bool
	_, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/remote/logincheck":
			w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture")
		case "/remote/fortisslvpn_xml":
			_, _ = io.WriteString(w, "<config>SECRET")
		case "/remote/sslvpn-tunnel":
			t.Error("switched to tunnel after invalid XML")
		case "/remote/logout":
			loggedOut.Store(true)
		}
	})
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Login(context.Background(), loginCredentials()); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("invalid configuration result: %v", err)
	}
	if !loggedOut.Load() {
		t.Fatal("stranded authenticated session after config failure")
	}
}

// TestTunnelWaitsForPPP verifies login does not wait for tunnel bytes before the client
// can write its initial PPP frame, while retaining HTTP-prefix checks on the response.
func TestTunnelWaitsForPPP(t *testing.T) {
	_, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/remote/logincheck":
			w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture")
		case "/remote/fortisslvpn_xml":
			_, _ = io.WriteString(w, "<config/>")
		case "/remote/sslvpn-tunnel":
			conn, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			payload, err := ReadFrame(buffered)
			if err != nil {
				t.Error(err)
				return
			}
			if err := WriteFrame(conn, payload); err != nil {
				t.Error(err)
			}
		}
	})
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := client.Login(context.Background(), loginCredentials())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tunnel.Close() }()
	if err := tunnel.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	want := []byte{0xc0, 0x21, 1, 2}
	if err := WriteFrame(tunnel, want); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFrame(tunnel); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("PPP exchange: %v %v", got, err)
	}
}
