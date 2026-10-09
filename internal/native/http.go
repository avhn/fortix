package native

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HTTP limits cap authentication data and response headers independently of XML.
const (
	maxHTTPHeader = 32 * 1024
	maxLoginBody  = 16 * 1024
	maxCookie     = 4096
)

// Credentials borrows one account password only for Login. Password is never retained
// by the returned connection; realm and username are form-encoded, never URL paths.
type Credentials struct {
	Username string
	Password []byte
	Realm    string
}

// UnsupportedMFA reports an unexpected second-factor challenge on a native session.
// It is actionable without exposing challenge text or silently changing backends.
type UnsupportedMFA struct{}

// Error recommends the explicit backend that supports second-factor authentication.
func (*UnsupportedMFA) Error() string {
	return "gateway requires unsupported second-factor authentication; use the openfortivpn backend"
}

// ErrAuthentication identifies credential rejection or a missing session cookie.
var ErrAuthentication = errors.New("gateway authentication failed")

// ErrTunnelDenied identifies an HTTP response where binary tunnel frames are required.
var ErrTunnelDenied = errors.New("gateway refused tunnel mode")

// HTTPError records a fixed request path and numeric non-success status. It excludes
// gateway response text, redirects, and cookies from display and diagnostic output.
type HTTPError struct {
	Path   string
	Status int
}

// Error returns the fixed request path and status without untrusted response text.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("gateway request %s failed with HTTP status %d", e.Path, e.Status)
}

// Connection owns a verified TLS tunnel and XML fallback metadata. Close releases
// local transport resources; Logout separately invalidates the remote session using
// a fresh verified connection. Config must be treated as an immutable snapshot.
// Reads preserve bytes buffered during HTTP parsing and reject HTTP tunnel denials.
type Connection struct {
	net.Conn
	Config VPNConfig
	client *Client
	cookie string
	reader *bufio.Reader
	readMu sync.Mutex
	prefix bool
	denied bool
}

// Read returns tunnel bytes, preserving fragmented or coalesced frame data. The first
// nonempty read checks for an HTTP/1 error prefix without discarding buffered bytes.
// Prefix checking is deferred so gateways waiting for a PPP request do not deadlock
// Login. Read deadlines and Close have their usual net.Conn cancellation semantics.
func (c *Connection) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.denied {
		return 0, ErrTunnelDenied
	}
	if !c.prefix {
		prefix, err := c.reader.Peek(FrameHeaderSize)
		if err != nil {
			if errors.Is(err, io.EOF) && len(prefix) != 0 {
				// Preserve a truncated header so ReadFrame can report unexpected EOF.
				c.prefix = true
				return c.reader.Read(data)
			}
			return 0, err
		}
		c.prefix = true
		if bytes.Equal(prefix, []byte("HTTP/1")) {
			c.denied = true
			return 0, ErrTunnelDenied
		}
	}
	return c.reader.Read(data)
}

// wireHTTP tracks buffered HTTP bytes on one TLS connection until tunnel handoff.
// A bounded header reader prevents net/http's response parser from allocating freely.
type wireHTTP struct {
	conn   net.Conn
	reader *bufio.Reader
	client *Client
}

// Login performs password authentication, allocation, TLS reconnection, XML retrieval,
// and the binary tunnel switch on the configuration connection. ctx and the client
// timeout bound each operation. Failures close partial resources, attempt bounded
// logout after accepted authentication, and return typed trust, MFA, authentication,
// HTTP, or transport errors without server body text.
// Callers own Close and best-effort Logout after a successful return.
func (c *Client) Login(ctx context.Context, credentials Credentials) (*Connection, error) {
	if credentials.Username == "" || len(credentials.Username) > 256 || len(credentials.Password) == 0 || len(credentials.Password) > 4096 || len(credentials.Realm) > 256 {
		return nil, errors.New("invalid native login credentials")
	}
	first, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = first.Close() }()
	wire := &wireHTTP{conn: first, reader: bufio.NewReader(first), client: c}
	form := url.Values{
		"username": {credentials.Username}, "credential": {string(credentials.Password)},
		"realm": {credentials.Realm}, "ajax": {"1"},
	}
	response, body, err := wire.request(ctx, http.MethodPost, "/remote/logincheck", form.Encode(), "", maxLoginBody)
	if err != nil {
		return nil, err
	}
	lower := strings.ToLower(string(body))
	result, _ := url.ParseQuery(string(body))
	if strings.Contains(lower, "tokeninfo=") || strings.Contains(lower, "challenge") || result.Get("ret") == "6" || response.StatusCode == http.StatusUnauthorized && strings.Contains(lower, "<form") {
		return nil, &UnsupportedMFA{}
	}
	if response.StatusCode != http.StatusOK || result.Get("ret") == "0" {
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return nil, &HTTPError{Path: "/remote/logincheck", Status: response.StatusCode}
		}
		return nil, ErrAuthentication
	}
	cookie, err := sessionCookie(response.Header)
	if err != nil {
		return nil, err
	}
	success := false
	peerAddress := first.RemoteAddr().String()
	defer func() {
		if !success {
			// A failed allocation or config fetch must not strand an authenticated session.
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), min(c.timeout, 5*time.Second))
			defer cancel()
			_ = c.logout(cleanup, cookie, peerAddress)
		}
	}()
	for _, path := range []string{"/remote/index", "/remote/fortisslvpn"} {
		if _, err := wire.get(ctx, path, cookie); err != nil {
			return nil, err
		}
	}
	// The gateway requires a new TLS connection before config, then reuses it for PPP.
	_ = first.Close()
	second, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	peerAddress = second.RemoteAddr().String()
	defer func() {
		if !success {
			_ = second.Close()
		}
	}()
	wire = &wireHTTP{conn: second, reader: bufio.NewReader(second), client: c}
	xmlBody, err := wire.get(ctx, "/remote/fortisslvpn_xml", cookie)
	if err != nil {
		return nil, err
	}
	config, err := ParseConfig(bytes.NewReader(xmlBody))
	if err != nil {
		return nil, err
	}
	finish := c.deadline(ctx, second)
	err = wire.send(http.MethodGet, "/remote/sslvpn-tunnel", "", cookie, "sslvpn")
	finish()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	success = true
	return &Connection{Conn: second, Config: config, client: c, cookie: cookie, reader: wire.reader}, nil
}

// Logout sends the session cookie on a fresh connection with the identical TLS trust
// policy. The recorded TLS peer bypasses DNS and retains the gateway host exception
// while tunnel routes are still installed. It honors ctx and the client timeout and
// does not close the tunnel itself.
func (c *Connection) Logout(ctx context.Context) error {
	return c.client.logout(ctx, c.cookie, c.RemoteAddr().String())
}

// logout invalidates cookie using a fresh verified connection to the recorded TLS peer,
// independently of any failed or closed tunnel. The configured hostname still controls
// HTTP Host and TLS verification. ctx bounds dialing and the logout HTTP operation.
func (c *Client) logout(ctx context.Context, cookie, peerAddress string) error {
	conn, err := c.connectTo(ctx, peerAddress)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	wire := &wireHTTP{conn: conn, reader: bufio.NewReader(conn), client: c}
	_, err = wire.get(ctx, "/remote/logout", cookie)
	return err
}

// sessionCookie extracts exactly one bounded nonempty SVPNCOOKIE. Invalid bytes,
// duplicate cookies, and malformed values fail without including cookie contents.
func sessionCookie(header http.Header) (string, error) {
	cookie := ""
	for _, line := range header.Values("Set-Cookie") {
		pair := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name != "SVPNCOOKIE" {
			continue
		}
		if cookie != "" || len(value) == 0 || len(value) > maxCookie {
			return "", ErrAuthentication
		}
		for _, b := range []byte(value) {
			if b < 0x21 || b > 0x7e || strings.ContainsRune("\";,\\", rune(b)) {
				return "", ErrAuthentication
			}
		}
		cookie = "SVPNCOOKIE=" + value
	}
	if cookie == "" {
		return "", ErrAuthentication
	}
	return cookie, nil
}

// get requests one bounded successful page without redirects or automatic retries.
func (w *wireHTTP) get(ctx context.Context, path, cookie string) ([]byte, error) {
	response, body, err := w.request(ctx, http.MethodGet, path, "", cookie, MaxConfigBytes)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, &HTTPError{Path: path, Status: response.StatusCode}
	}
	return body, nil
}

// send writes an HTTP/1.1 request directly to TLS, with no proxy, redirect, HTTP/2,
// compression, or credential-bearing URL. host overrides only the tunnel Host header.
func (w *wireHTTP) send(method, path, form, cookie, host string) error {
	request, err := http.NewRequest(method, "https://"+w.client.address+path, strings.NewReader(form))
	if err != nil {
		return errors.New("invalid gateway request")
	}
	if host != "" {
		request.Host = host
	}
	if form != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	return request.Write(w.conn)
}

// request reads bounded headers and a bounded response body on the same connection.
// All parser errors are fixed diagnostics because raw errors may contain server text.
// Its layered reader retains any prefetched bytes for the next HTTP request or PPP.
// Only allocation and logout may close the connection after a fully consumed body;
// every other response must leave the connection available for the next request.
func (w *wireHTTP) request(ctx context.Context, method, path, form, cookie string, limit int64) (*http.Response, []byte, error) {
	finish := w.client.deadline(ctx, w.conn)
	defer finish()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := w.send(method, path, form, cookie, ""); err != nil {
		return nil, nil, err
	}
	header := make([]byte, 0, 1024)
	for {
		b, err := w.reader.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		header = append(header, b)
		if len(header) > maxHTTPHeader {
			return nil, nil, errors.New("gateway HTTP headers are too large")
		}
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			break
		}
	}
	w.reader = bufio.NewReader(io.MultiReader(bytes.NewReader(header), w.reader))
	response, err := http.ReadResponse(w.reader, nil)
	if err != nil {
		return nil, nil, errors.New("invalid gateway HTTP response")
	}
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, nil, errors.New("unsupported gateway HTTP response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, nil, errors.New("failed to read gateway HTTP body")
	}
	if int64(len(body)) > limit {
		// Do not drain an oversized body; the caller closes this connection on error.
		return nil, nil, errors.New("gateway HTTP body is too large")
	}
	if err := response.Body.Close(); err != nil {
		return nil, nil, errors.New("failed to close gateway HTTP body")
	}
	// Allocation is followed by TLS reconnection; logout has no subsequent request.
	if response.Close && path != "/remote/fortisslvpn" && path != "/remote/logout" {
		return nil, nil, errors.New("gateway closed a required HTTP session")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return response, body, nil
}
