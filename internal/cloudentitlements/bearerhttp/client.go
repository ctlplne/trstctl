// SPDX-License-Identifier: BUSL-1.1
// Package bearerhttp performs bounded fixed-origin cloud metadata reads without
// converting the bearer credential into a Go string.
package bearerhttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/netsec"
)

const MaxResponse = 2 << 20

type Borrow func(context.Context, func([]byte) error) error
type Config struct {
	Endpoint              string
	CAPEM                 []byte
	AllowInsecureLoopback bool
	PrivateEgressCIDRs    []netip.Prefix
	UseToken              Borrow
}
type Client struct {
	cfg      Config
	endpoint *url.URL
	dialer   net.Dialer
}
type StatusError struct{ Status int }

func (e *StatusError) Error() string {
	return fmt.Sprintf("cloud metadata read answered HTTP %d", e.Status)
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || len(cfg.Endpoint) > 2048 || cfg.UseToken == nil {
		return nil, errors.New("invalid fixed metadata origin or missing token borrow")
	}
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	control := netsec.SafeDialControlWithOptions(netsec.SafeClientOptions{AllowPrivateCIDRs: append([]netip.Prefix(nil), cfg.PrivateEgressCIDRs...)})
	if u.Scheme == "http" {
		control = func(_ string, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
				return errors.New("plaintext metadata endpoint must resolve to loopback")
			}
			return nil
		}
	}
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	return &Client{cfg: cfg, endpoint: u, dialer: net.Dialer{Timeout: 10 * time.Second, Control: control}}, nil
}

// FileToken borrows a raw owner-only access-token file. Operators refresh that
// file; no credential value is retained in a collector configuration or state.
func FileToken(path string) Borrow {
	return func(ctx context.Context, use func([]byte) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := secretfile.LoadBounded(path, 32<<10)
		if err != nil {
			return errors.New("private cloud reader token file unavailable")
		}
		defer secret.Wipe(raw)
		token := bytes.TrimSpace(raw)
		if !ValidToken(token) {
			return errors.New("invalid bounded cloud reader token")
		}
		held, err := secret.NewFrom(token)
		if err != nil {
			return err
		}
		defer held.Destroy()
		return held.Use(use)
	}
}
func ValidToken(token []byte) bool {
	if len(token) == 0 || len(token) > 32<<10 || token[0] == '=' {
		return false
	}
	padding := false
	for _, b := range token {
		if b == '=' {
			padding = true
			continue
		}
		if padding {
			return false
		}
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && !bytes.ContainsRune([]byte("-._~+/"), rune(b)) {
			return false
		}
	}
	return true
}

// ReadJSON sends a fixed-origin GET or an explicitly named read-only POST. The
// containing discovery outbox owns this external call and its retry policy.
func (c *Client) ReadJSON(ctx context.Context, method, path string, body []byte, out any) error {
	readPath := strings.SplitN(path, "?", 2)[0]
	if method != http.MethodGet && (method != http.MethodPost || (!strings.HasSuffix(readPath, ":getIamPolicy") && readPath != "/v2/entries:list")) {
		return errors.New("operation is outside cloud metadata reads")
	}
	ref, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(path, "/") || ref.IsAbs() || ref.Host != "" || ref.User != nil || ref.Fragment != "" || ref.Opaque != "" || len(path) > 16<<10 || len(body) > 64<<10 {
		return errors.New("invalid bounded metadata path")
	}
	for _, segment := range strings.Split(ref.Path, "/") {
		if segment == "." || segment == ".." || strings.ContainsAny(segment, "\r\n\x00") {
			return errors.New("metadata path contains an invalid segment")
		}
	}
	target := c.endpoint.ResolveReference(ref)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("metadata request construction failed")
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	var wire bytes.Buffer
	if req.Write(&wire) != nil {
		return errors.New("metadata request serialization failed")
	}
	split := bytes.Index(wire.Bytes(), []byte("\r\n\r\n"))
	if split < 0 {
		return errors.New("metadata request framing failed")
	}
	address := target.Host
	if target.Port() == "" {
		port := "443"
		if target.Scheme == "http" {
			port = "80"
		}
		address = net.JoinHostPort(target.Hostname(), port)
	}
	conn, err := c.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.New("metadata origin dial failed")
	}
	rawConn := conn
	defer func() { _ = rawConn.Close() }()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return errors.New("metadata connection deadline failed")
	}
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if target.Scheme == "https" {
		conn, err = mtls.VerifyClientConnection(ctx, conn, target.Hostname(), c.cfg.CAPEM)
		if err != nil {
			return errors.New("metadata TLS identity verification failed")
		}
	}
	err = c.cfg.UseToken(ctx, func(token []byte) error {
		if !ValidToken(token) {
			return errors.New("invalid bounded cloud reader token")
		}
		prefix := []byte("Authorization: Bearer ")
		held, err := secret.New(len(prefix) + len(token))
		if err != nil {
			return err
		}
		defer held.Destroy()
		return held.Use(func(header []byte) error {
			copy(header, prefix)
			copy(header[len(prefix):], token)
			parts := net.Buffers{wire.Bytes()[:split], []byte("\r\n"), header, wire.Bytes()[split:]}
			_, err := parts.WriteTo(conn)
			return err
		})
	})
	if err != nil {
		return errors.New("metadata token borrow or request write failed")
	}
	limited := &io.LimitedReader{R: conn, N: 64 << 10}
	reader := bufio.NewReader(limited)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return errors.New("invalid bounded metadata response headers")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Status: resp.StatusCode}
	}
	limited.N = MaxResponse + 1
	held, err := secret.New(MaxResponse + 1)
	if err != nil {
		return err
	}
	defer held.Destroy()
	return held.Use(func(raw []byte) error {
		n, err := io.ReadFull(resp.Body, raw)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return errors.New("metadata response incomplete")
		}
		if n > MaxResponse {
			return errors.New("metadata response exceeds bound")
		}
		return DecodeJSON(raw[:n], out)
	})
}
