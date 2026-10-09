package native

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestTLSVerification checks PKI-or-pin semantics and rejection before HTTP credentials.
func TestTLSVerification(t *testing.T) {
	for _, mode := range []string{"pki", "pki-with-wrong-pin", "pin", "pin-with-wrong-host", "untrusted", "wrong-host", "wrong-pin"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int64
			server, options := fakeGateway(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte("ret=0"))
			})
			digest := sha256.Sum256(server.Certificate().Raw)
			pin := hex.EncodeToString(digest[:])
			wantReject := false
			switch mode {
			case "pki-with-wrong-pin":
				options.TrustedCert = strings.Repeat("0", 64)
			case "pin":
				options.RootCAs = nil
				options.TrustedCert = pin
			case "pin-with-wrong-host":
				options.Host = "other.test"
				options.TrustedCert = pin
			case "untrusted":
				options.RootCAs = nil
				wantReject = true
			case "wrong-host":
				options.Host = "other.test"
				wantReject = true
			case "wrong-pin":
				options.RootCAs = nil
				options.TrustedCert = strings.Repeat("0", 64)
				wantReject = true
			}
			server.TLS.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello.ServerName != options.Host {
					t.Errorf("SNI: %q", hello.ServerName)
				}
				for _, version := range hello.SupportedVersions {
					if version < tls.VersionTLS12 {
						t.Error("offered TLS below 1.2")
					}
				}
				return &server.TLS.Certificates[0], nil
			}
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Login(context.Background(), loginCredentials())
			var rejected *CertificateRejected
			if errors.As(err, &rejected) != wantReject {
				t.Fatalf("trust result: %T %v", err, err)
			}
			if wantReject {
				if requests.Load() != 0 || rejected.Digest != pin || rejected.Subject == "" || rejected.Issuer == "" {
					t.Fatalf("rejection metadata or credential isolation failed: %+v", rejected)
				}
			} else if !errors.Is(err, ErrAuthentication) || requests.Load() != 1 {
				t.Fatalf("verified connection did not reach authentication: %v", err)
			}
		})
	}
}

// TestTLSVerifierEveryConnection changes the certificate at configuration or logout,
// proving that earlier successful trust does not bypass subsequent verification.
func TestTLSVerifierEveryConnection(t *testing.T) {
	for _, rotateAt := range []int64{2, 3} {
		t.Run(string(rune('0'+rotateAt)), func(t *testing.T) {
			server, options := fakeGateway(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/remote/logincheck":
					w.Header().Set("Set-Cookie", "SVPNCOOKIE=fixture")
				case "/remote/fortisslvpn_xml":
					_, _ = w.Write([]byte("<config/>"))
				case "/remote/logout":
					t.Error("sent cookie on an unverified logout connection")
				}
			})
			rotated := gatewayCertificate(t, "rotated.test")
			var handshakes atomic.Int64
			server.TLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				if handshakes.Add(1) >= rotateAt {
					return &rotated, nil
				}
				return &server.TLS.Certificates[0], nil
			}
			client, err := NewClient(options)
			if err != nil {
				t.Fatal(err)
			}
			tunnel, err := client.Login(context.Background(), loginCredentials())
			if rotateAt == 3 {
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tunnel.Close() }()
				err = tunnel.Logout(context.Background())
			}
			var rejected *CertificateRejected
			// A rejected config connection also attempts fresh, independently verified cleanup.
			if !errors.As(err, &rejected) || handshakes.Load() != 3 {
				t.Fatalf("later connection bypassed trust: %v", err)
			}
		})
	}
}

// TestClientOptions rejects malformed settings before dialing and bounds dial timeout.
func TestClientOptions(t *testing.T) {
	for _, options := range []Options{
		{}, {Host: "https://gateway.test"}, {Host: "gateway.test\r\nInjected: value"},
		{Host: "-gateway.test"}, {Host: "a..test"}, {Host: strings.Repeat("x", 64)},
		{Host: "gateway.test", Port: -1}, {Host: "gateway.test", Port: 65536},
		{Host: "gateway.test", Timeout: -time.Second}, {Host: "gateway.test", TrustedCert: "bad"},
		{Host: "gateway.test", TrustedCert: strings.Repeat("A", 64)},
	} {
		if _, err := NewClient(options); err == nil {
			t.Fatal("accepted invalid client options")
		}
	}
	for _, host := range []string{"gateway.test.", "127.0.0.1", "::1"} {
		client, err := NewClient(Options{Host: host})
		if err != nil || client.timeout != 15*time.Second {
			t.Fatalf("defaults for %s: %v", host, err)
		}
	}
	client, err := NewClient(Options{
		Host: "gateway.test", Timeout: 10 * time.Millisecond,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.connect(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial timeout: %v", err)
	}
	if err := client.verify(tls.ConnectionState{}); err == nil {
		t.Fatal("accepted absent peer certificate")
	}
	if err := client.verify(tls.ConnectionState{NegotiatedProtocol: "h2"}); err == nil {
		t.Fatal("accepted HTTP/2")
	}
	if got := certificateText("subject\n" + strings.Repeat("x", 600)); len(got) > 512 || strings.Contains(got, "\n") {
		t.Fatal("unbounded certificate metadata")
	}
}
