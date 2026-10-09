// Package native implements the password-only TLS gateway protocol and PPP framing.
// It does not configure interfaces, mutate routes, or obtain credentials itself.
package native

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Options specifies an immutable gateway and its trust policy. RootCAs defaults to
// system roots; DialContext defaults to direct TCP dialing without proxy discovery.
// Timeout bounds each connection and HTTP operation, defaulting to fifteen seconds.
// TrustedCert optionally accepts a lowercase leaf DER SHA-256 digest in addition to PKI.
type Options struct {
	Host        string
	Port        int
	TrustedCert string
	RootCAs     *x509.CertPool
	DialContext func(context.Context, string, string) (net.Conn, error)
	Timeout     time.Duration
}

// Client holds reusable connection settings, not credentials or session cookies.
// Every TLS connection uses the same verifier, including configuration and logout.
type Client struct {
	host    string
	address string
	roots   *x509.CertPool
	pin     []byte
	dial    func(context.Context, string, string) (net.Conn, error)
	timeout time.Duration
}

// CertificateRejected reports a rejected leaf before HTTP can send credentials.
// Digest is lowercase SHA-256 over leaf DER; Subject and Issuer are bounded display
// metadata, not trust inputs. An absent or malformed certificate has no digest.
type CertificateRejected struct {
	Digest  string
	Subject string
	Issuer  string
}

// Error returns a fixed diagnostic without including untrusted certificate text.
func (*CertificateRejected) Error() string { return "gateway certificate rejected" }

// NewClient validates options and snapshots roots before any I/O. It returns an
// error for invalid host, port, digest, or timeout, and never sends credentials.
func NewClient(options Options) (*Client, error) {
	if !validHost(options.Host) {
		return nil, errors.New("invalid gateway host")
	}
	if options.Port == 0 {
		options.Port = 443
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, errors.New("invalid gateway port")
	}
	if options.Timeout == 0 {
		options.Timeout = 15 * time.Second
	}
	if options.Timeout < 0 {
		return nil, errors.New("invalid gateway timeout")
	}
	var pin []byte
	if options.TrustedCert != "" {
		var err error
		pin, err = hex.DecodeString(options.TrustedCert)
		if err != nil || len(pin) != sha256.Size || options.TrustedCert != strings.ToLower(options.TrustedCert) {
			return nil, errors.New("invalid gateway certificate digest")
		}
	}
	if options.DialContext == nil {
		options.DialContext = (&net.Dialer{}).DialContext
	}
	client := &Client{
		host: options.Host, address: net.JoinHostPort(options.Host, strconv.Itoa(options.Port)),
		pin: pin, dial: options.DialContext, timeout: options.Timeout,
	}
	if options.RootCAs != nil {
		client.roots = options.RootCAs.Clone()
	}
	return client, nil
}

// validHost accepts bare IP literals or ASCII DNS labels, preventing URL and header
// injection while allowing IPv6 literals as the outer TLS gateway address.
func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-'
			if !valid {
				return false
			}
		}
	}
	return true
}

// connect establishes direct TLS with a bounded handshake and HTTP/1.1 ALPN.
// ctx cancellation closes partial resources; trust rejection is returned intact.
func (c *Client) connect(ctx context.Context) (*tls.Conn, error) {
	return c.connectTo(ctx, c.address)
}

// connectTo dials a configured endpoint or a previously verified TLS peer address.
// The configured hostname still supplies SNI and certificate verification, regardless
// of the dial target. Cancellation and the client timeout bound the full handshake.
func (c *Client) connectTo(ctx context.Context, address string) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	raw, err := c.dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: c.host, NextProtos: []string{"http/1.1"},
		// Verification below deliberately accepts either verified PKI or an explicit leaf pin.
		InsecureSkipVerify: true, VerifyConnection: c.verify,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// verify checks hostname and PKI first, then the explicit leaf DER pin. It rejects
// unsupported ALPN and returns bounded certificate metadata without gateway text.
func (c *Client) verify(state tls.ConnectionState) error {
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		return errors.New("gateway selected an unsupported application protocol")
	}
	if len(state.PeerCertificates) == 0 {
		return &CertificateRejected{}
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: c.host, Roots: c.roots, Intermediates: intermediates,
	}); err == nil {
		return nil
	}
	digest := sha256.Sum256(leaf.Raw)
	if len(c.pin) == sha256.Size && subtle.ConstantTimeCompare(digest[:], c.pin) == 1 {
		return nil
	}
	return &CertificateRejected{
		Digest: hex.EncodeToString(digest[:]), Subject: certificateText(leaf.Subject.String()),
		Issuer: certificateText(leaf.Issuer.String()),
	}
}

// certificateText strips control characters and caps certificate display metadata.
// The output is diagnostic only and must never become a verification input.
func certificateText(text string) string {
	var out strings.Builder
	for _, r := range text {
		if unicode.IsControl(r) {
			r = ' '
		}
		if out.Len()+len(string(r)) > 512 {
			break
		}
		out.WriteRune(r)
	}
	return out.String()
}

// deadline bounds synchronous connection I/O and wakes it on ctx cancellation.
// The returned cleanup waits for any cancellation callback before clearing the deadline,
// avoiding a stale callback poisoning a connection transferred to the tunnel reader.
func (c *Client) deadline(ctx context.Context, conn net.Conn) func() {
	until := time.Now().Add(c.timeout)
	if end, ok := ctx.Deadline(); ok && end.Before(until) {
		until = end
	}
	_ = conn.SetDeadline(until)
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(finished)
	})
	return func() {
		if !stop() {
			<-finished
		}
		_ = conn.SetDeadline(time.Time{})
	}
}
