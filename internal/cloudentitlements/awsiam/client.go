// SPDX-License-Identifier: BUSL-1.1
package awsiam

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
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

const maxResponse = 4 << 20

type Client struct {
	cfg      Config
	endpoint *url.URL
	dialer   net.Dialer
}

func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://iam.amazonaws.com"
	}
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" || (endpoint.Path != "" && endpoint.Path != "/") || len(cfg.Endpoint) > 2048 || cfg.UseCredentials == nil {
		return nil, errors.New("awsiam: invalid fixed endpoint or missing credential borrow")
	}
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if !scopeName(cfg.Region) {
		return nil, errors.New("awsiam: invalid signing region")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	cfg.PrivateEgressCIDRs = append(cfg.PrivateEgressCIDRs[:0:0], cfg.PrivateEgressCIDRs...)
	control := netsec.SafeDialControlWithOptions(netsec.SafeClientOptions{AllowPrivateCIDRs: cfg.PrivateEgressCIDRs})
	if endpoint.Scheme == "http" {
		control = func(_ string, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
				return errors.New("awsiam: resolved plaintext target is not loopback")
			}
			return nil
		}
	}
	return &Client{cfg: cfg, endpoint: endpoint, dialer: net.Dialer{Timeout: 10 * time.Second, Control: control}}, nil
}
func scopeName(v string) bool {
	if len(v) == 0 || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

type captureSession struct {
	c           *Client
	calls       int
	policyBytes int
}

// call permits metadata reads only. It neither follows redirects nor retries a
// credential-bearing request. The caller's outbox worker owns external effects.
func (s *captureSession) call(ctx context.Context, action string, values url.Values) (*element, error) {
	return s.query(ctx, action, values, false)
}

func (s *captureSession) query(ctx context.Context, action string, values url.Values, mutation bool) (*element, error) {
	if mutation {
		if action != "DeleteAccessKey" && action != "PutUserPolicy" && action != "PutRolePolicy" {
			return nil, errors.New("awsiam: operation is outside reviewed cloud changes")
		}
	} else {
		switch action {
		case "GetUser", "GetRole", "ListUserPolicies", "GetUserPolicy", "ListRolePolicies", "GetRolePolicy", "ListAttachedUserPolicies", "ListAttachedRolePolicies", "ListGroupsForUser", "ListGroupPolicies", "GetGroupPolicy", "ListAttachedGroupPolicies", "GetPolicy", "GetPolicyVersion", "ListAccessKeys", "GetAccessKeyLastUsed":
		default:
			return nil, errors.New("awsiam: operation is outside read-only inventory")
		}
	}
	if s.calls >= 5000 {
		return nil, errors.New("awsiam: capture call budget exceeded")
	}
	s.calls++
	values.Set("Action", action)
	values.Set("Version", "2010-05-08")
	body := []byte(values.Encode())
	if len(body) > 64<<10 {
		return nil, errors.New("awsiam: request exceeds bound")
	}
	c := s.c
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("awsiam: request construction failed")
	}
	request.Close = true
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	var held *secret.Buffer
	err = c.cfg.UseCredentials(ctx, func(credential awssignin.Credentials) error {
		headers, err := awssignin.Sign(request, body, credential, c.cfg.Region, "iam", c.cfg.Now())
		defer secret.Wipe(headers)
		if err != nil {
			return err
		}
		held, err = secret.NewFrom(headers)
		return err
	})
	if held != nil {
		defer held.Destroy()
	}
	if err != nil {
		return nil, fmt.Errorf("awsiam: %s credential signing failed", action)
	}
	if held == nil {
		return nil, errors.New("awsiam: credential borrow did not sign")
	}
	var wire bytes.Buffer
	if err = request.Write(&wire); err != nil {
		return nil, errors.New("awsiam: request serialization failed")
	}
	split := bytes.Index(wire.Bytes(), []byte("\r\n\r\n"))
	if split < 0 {
		return nil, errors.New("awsiam: request framing failed")
	}
	address := c.endpoint.Host
	if c.endpoint.Port() == "" {
		port := "443"
		if c.endpoint.Scheme == "http" {
			port = "80"
		}
		address = net.JoinHostPort(c.endpoint.Hostname(), port)
	}
	conn, err := c.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("awsiam: %s dial failed: %w", action, err)
	}
	rawConn := conn
	defer func() { _ = rawConn.Close() }()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, errors.New("awsiam: deadline setup failed")
	}
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if c.endpoint.Scheme == "https" {
		conn, err = mtls.VerifyClientConnection(ctx, conn, c.endpoint.Hostname(), c.cfg.CAPEM)
		if err != nil {
			return nil, fmt.Errorf("awsiam: %s TLS identity verification failed", action)
		}
	}
	err = held.Use(func(headers []byte) error {
		parts := net.Buffers{wire.Bytes()[:split], []byte("\r\n"), headers, wire.Bytes()[split:]}
		_, err := parts.WriteTo(conn)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("awsiam: %s write failed", action)
	}
	limited := &io.LimitedReader{R: conn, N: 64 << 10}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("awsiam: %s bounded response headers failed", action)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, &StatusError{Action: action, Status: response.StatusCode}
	}
	limited.N = maxResponse + 1
	raw, err := secret.ReadBounded(response.Body, maxResponse+1)
	defer secret.Wipe(raw)
	if err != nil || len(raw) > maxResponse {
		return nil, fmt.Errorf("awsiam: %s response exceeds bound or is incomplete", action)
	}
	result, err := parseEnvelope(raw, action, mutation)
	if err != nil {
		return nil, fmt.Errorf("awsiam: %s malformed response: %w", action, err)
	}
	return result, nil
}
func validateName(name string) bool {
	if len(name) < 1 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("+=,.@_-", r) {
			return false
		}
	}
	return true
}

// StatusError never retains an upstream response body or credential.
type StatusError struct {
	Action string
	Status int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("awsiam: %s status %d (body redacted)", e.Action, e.Status)
}
