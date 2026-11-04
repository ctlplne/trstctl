// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// What a ClickHouse session's recording keeps of each request and response
// (A256), and the largest request header the gateway reads.
const (
	clickhouseRecordBytes = 4 << 10
	clickhouseMaxHeader   = 1 << 20
)

// clickhouseClientAuth are the request headers by which an HTTP client could
// sign in as someone else; the gateway removes them and signs every request
// in as the session's user.
var clickhouseClientAuth = []string{"Authorization", "Proxy-Authorization", "X-ClickHouse-User", "X-ClickHouse-Key",
	"X-ClickHouse-SSL-Certificate-Auth"}

// clickhouseCredential is the session's ClickHouse user as the provider
// issued it.
type clickhouseCredential struct {
	Username string           `json:"username"`
	Password secret.JSONBytes `json:"password"`
}

func parseClickHouseCredential(credential []byte) (*clickhouseCredential, error) {
	var c clickhouseCredential
	if err := json.Unmarshal(credential, &c); err != nil || c.Username == "" || len(c.Password) == 0 {
		secret.Wipe(c.Password)
		return nil, errors.New("accessgateway: the ClickHouse credential is not a user and password")
	}
	return &c, nil
}

// serveClickHouse relays a stock HTTP client (curl, or any tool on
// ClickHouse's HTTP interface) to the target as the session's user (A256).
// The client sends no credential — the admitted tunnel is its
// authentication — and any it sends (a basic-auth header, ClickHouse's user
// and key headers or user and password parameters) is removed; the gateway
// signs each request in itself. The client never receives the credential.
func serveClickHouse(ctx context.Context, client net.Conn, credential []byte, upstream httpUpstream, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	user, err := parseClickHouseCredential(credential)
	if err != nil {
		return err
	}
	defer secret.Wipe(user.Password)
	target, transport, err := upstream.transport(dial)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			for _, h := range clickhouseClientAuth {
				r.Out.Header.Del(h)
			}
			query := r.Out.URL.Query()
			query.Del("user")
			query.Del("password")
			r.Out.URL.RawQuery = query.Encode()
			r.Out.Header.Set("X-ClickHouse-User", user.Username)
			r.Out.Header.Set("X-ClickHouse-Key", string(user.Password))
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			if rec == nil {
				return nil
			}
			status := strconv.Itoa(resp.StatusCode)
			if code := resp.Header.Get("X-ClickHouse-Exception-Code"); code != "" {
				status += " exception " + code
			}
			if summary := resp.Header.Get("X-ClickHouse-Summary"); summary != "" {
				status += " " + summary
			}
			resp.Body = &recordedBody{ReadCloser: resp.Body, done: func(head []byte, size int) {
				rec.event("result", "response", status+": "+boundedHTTPText(head, size), 0)
			}}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			// The gateway's own words, never the upstream's error text.
			http.Error(w, "the access gateway could not reach the target", http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec != nil {
			// The statement is the query parameter, the body, or both; the
			// body is peeked, not read, so it still streams upstream.
			body := bufio.NewReaderSize(r.Body, clickhouseRecordBytes+1)
			head, _ := body.Peek(clickhouseRecordBytes)
			text := r.Method + " " + r.URL.Path
			if q := r.URL.Query().Get("query"); q != "" {
				text += " query=" + boundedHTTPText([]byte(q), len(q))
			}
			if len(head) > 0 {
				text += " body=" + boundedHTTPText(head, len(head))
			}
			rec.event("clickhouse", "request", text, 0)
			r.Body = struct {
				io.Reader
				io.Closer
			}{body, r.Body}
		}
		proxy.ServeHTTP(w, r)
	})
	listener := newOneConnListener(client)
	server := &http.Server{
		Handler: handler, MaxHeaderBytes: clickhouseMaxHeader, ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() { <-listener.closed; _ = server.Close() }()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, errOneConnDone) {
		return err
	}
	return nil
}

// httpUpstream is where an HTTP-speaking target is reached and how its
// certificate is verified: the session job's upstream URL, CA and server
// name (no CA: the system roots).
type httpUpstream struct {
	URL, CAPEM, ServerName string
}

// transport parses the URL and builds the transport that reaches it through
// the gateway's dialer.
func (u httpUpstream) transport(dial func(context.Context, string, string) (net.Conn, error)) (*url.URL, *http.Transport, error) {
	target, err := url.Parse(u.URL)
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Host == "" {
		return nil, nil, errors.New("accessgateway: the session's upstream is not an http(s) URL")
	}
	var transport *http.Transport
	if u.CAPEM == "" {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		serverName := u.ServerName
		if serverName == "" {
			serverName = target.Hostname()
		}
		if transport, err = mtls.HTTPTransportForServerName([]byte(u.CAPEM), serverName); err != nil {
			return nil, nil, err
		}
	}
	if dial != nil {
		transport.DialContext = dial
	}
	return target, transport, nil
}

// boundedHTTPText is a request or response text under the recording bound;
// binary content appears by its size.
func boundedHTTPText(head []byte, size int) string {
	if len(head) > clickhouseRecordBytes {
		head = head[:clickhouseRecordBytes]
	}
	switch {
	case !printable(head):
		return "<" + strconv.Itoa(size) + " bytes>"
	case size > len(head):
		return strings.TrimSpace(string(head)) + "...<" + strconv.Itoa(size) + " bytes>"
	}
	return strings.TrimSpace(string(head))
}

// recordedBody keeps the head of a body as it streams and reports it, with
// the body's size, when the body is closed.
type recordedBody struct {
	io.ReadCloser
	head []byte
	size int
	once sync.Once
	done func(head []byte, size int)
}

func (b *recordedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if room := clickhouseRecordBytes - len(b.head); room > 0 && n > 0 {
		b.head = append(b.head, p[:min(n, room)]...)
	}
	b.size += n
	return n, err
}

func (b *recordedBody) Close() error {
	b.once.Do(func() { b.done(b.head, b.size) })
	return b.ReadCloser.Close()
}

var errOneConnDone = errors.New("accessgateway: the connection was served")

// oneConnListener hands an HTTP server one connection, then waits for it to
// close.
type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
	served bool
	mu     sync.Mutex
}

func newOneConnListener(conn net.Conn) *oneConnListener {
	l := &oneConnListener{closed: make(chan struct{})}
	l.conn = &closeNotifyConn{Conn: conn, closed: func() { l.once.Do(func() { close(l.closed) }) }}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	served := l.served
	l.served = true
	l.mu.Unlock()
	if !served {
		return l.conn, nil
	}
	<-l.closed
	return nil, errOneConnDone
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// closeNotifyConn reports when the HTTP server closes the connection.
type closeNotifyConn struct {
	net.Conn
	closed func()
}

func (c *closeNotifyConn) Close() error {
	c.closed()
	return c.Conn.Close()
}
