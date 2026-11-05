// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// credentialHTTPRoundTrip verifies the fixed upstream, bounds response headers,
// and serializes secret auth headers only from locked byte-backed memory.
func credentialHTTPRoundTrip(ctx context.Context, request *http.Request, body []byte, upstream httpUpstream, deadline time.Time, dial func(context.Context, string, string) (net.Conn, error), authorize func(*http.Request) (*secret.Buffer, error)) (*http.Response, error) {
	target, err := url.Parse(upstream.URL)
	if err != nil || target.Host == "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, errors.New("accessgateway: invalid credential upstream")
	}
	if target.Scheme == "http" {
		host := target.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("accessgateway: credential upstream requires verified HTTPS")
		}
	}
	address := target.Host
	if target.Port() == "" {
		port := "443"
		if target.Scheme == "http" {
			port = "80"
		}
		address = net.JoinHostPort(target.Hostname(), port)
	}
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if target.Scheme == "https" {
		name := upstream.ServerName
		if name == "" {
			name = target.Hostname()
		}
		conn, err = mtls.VerifyClientConnection(ctx, conn, name, []byte(upstream.CAPEM))
		if err != nil {
			return nil, err
		}
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	success := false
	defer func() {
		if !success {
			stop()
			_ = conn.Close()
		}
	}()
	out := request.Clone(ctx)
	out.URL.Scheme = target.Scheme
	out.URL.Host = target.Host
	out.URL.User = nil
	out.URL.Fragment = ""
	out.URL.Opaque = ""
	out.Host = target.Host
	out.RequestURI = ""
	out.Close = true
	out.TransferEncoding = nil
	out.Trailer = nil
	out.GetBody = nil
	out.ContentLength = int64(len(body))
	out.Body = io.NopCloser(bytes.NewReader(body))
	for _, name := range strings.Split(out.Header.Get("Connection"), ",") {
		out.Header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "X-Snowflake-Authorization-Token-Type", "X-Amz-Security-Token", "Cookie", "Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Idempotency-Key", "X-Idempotency-Key", "Expect"} {
		out.Header.Del(name)
	}
	auth, err := authorize(out)
	if err != nil {
		return nil, err
	}
	defer auth.Destroy()
	var wire bytes.Buffer
	if err := out.Write(&wire); err != nil {
		return nil, err
	}
	defer secret.Wipe(wire.Bytes())
	split := bytes.Index(wire.Bytes(), []byte("\r\n\r\n"))
	if split < 0 {
		return nil, errors.New("accessgateway: invalid serialized credential request")
	}
	err = auth.Use(func(headers []byte) error {
		parts := net.Buffers{wire.Bytes()[:split], []byte("\r\n"), headers, wire.Bytes()[split:]}
		_, err := parts.WriteTo(conn)
		return err
	})
	if err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: conn, N: 64 << 10}
	reader := bufio.NewReader(limited)
	var response *http.Response
	for interim := 0; ; interim++ {
		response, err = http.ReadResponse(reader, out)
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= 200 {
			break
		}
		_ = response.Body.Close()
		if response.StatusCode == http.StatusSwitchingProtocols || interim >= 7 {
			return nil, errors.New("accessgateway: unsupported credential HTTP interim response")
		}
	}
	limited.N = 1 << 62

	response.Body = &credentialHTTPResponseBody{ReadCloser: response.Body, conn: conn, stop: stop}
	response.Header.Del("Set-Cookie")
	response.Header.Del("Authorization")
	success = true
	return response, nil
}

type credentialHTTPResponseBody struct {
	io.ReadCloser
	conn net.Conn
	stop func() bool
}

func (b *credentialHTTPResponseBody) Close() error {
	b.stop()
	_ = b.conn.Close()
	return b.ReadCloser.Close()
}
