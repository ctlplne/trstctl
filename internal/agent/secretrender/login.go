// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A238-L1: a renderer can sign in as its workload instead of holding an API
// token with secrets:read. It exchanges the workload's own credential — a
// Kubernetes service-account token, a cloud identity token, whatever the
// tenant's machine auth method accepts — for a machine session at
// POST /api/v1/secrets/login, reading the credential file again at each
// sign-in so a rotated token works. It signs in again a minute before the
// session expires, or once when the control plane stops accepting it, and
// ends the session when it stops. What the renderer may read is the auth
// method's role, so its reach is that one workload's.

// sessionRefreshMargin is how long before its expiry a session is replaced.
const sessionRefreshMargin = time.Minute

// SessionClient reads, reports and leases over a machine session it keeps
// signed in. It implements Fetcher, Reporter, LeaseClient and
// ReplacementReader.
type SessionClient struct {
	server, tenant, method, credentialFile string
	client                                 *http.Client
	now                                    func() time.Time

	mu      sync.Mutex
	current *HTTPClient
	expires time.Time
	// logins numbers this client's sign-ins: each one is a new session, so a
	// sign-in after the control plane ended the last one never replays it.
	logins int
}

// NewSessionClient builds a session client; it signs in at the first call.
func NewSessionClient(server, tenant, method, credentialFile string, client *http.Client) (*SessionClient, error) {
	if client == nil || strings.TrimSpace(method) == "" || strings.TrimSpace(credentialFile) == "" {
		return nil, errors.New("secretrender: a control-plane client, a login method and a credential file are required")
	}
	return &SessionClient{server: strings.TrimRight(server, "/"), tenant: tenant, method: method,
		credentialFile: credentialFile, client: client, now: time.Now}, nil
}

// session returns the signed-in client, signing in when there is none, when
// it is about to expire, or when force says the control plane refused it.
func (s *SessionClient) session(ctx context.Context, force bool) (*HTTPClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && !force && (s.expires.IsZero() || s.now().Add(sessionRefreshMargin).Before(s.expires)) {
		return s.current, nil
	}
	next, expires, err := s.login(ctx)
	if err != nil {
		return nil, err
	}
	if s.current != nil {
		s.current.Wipe()
	}
	s.current, s.expires = next, expires
	return next, nil
}

// login exchanges the workload credential for a session. Its idempotency key
// is the credential's digest, a ten-minute window and this client's sign-in
// number: each sign-in is a fresh session — one after the control plane ended
// the last must not get that ended session back — and a restarted renderer
// within the window resumes its first session while it still lives.
func (s *SessionClient) login(ctx context.Context) (*HTTPClient, time.Time, error) {
	credential, err := os.ReadFile(s.credentialFile) // #nosec G304 -- operator-configured workload credential file (CWE-22)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer secret.Wipe(credential)
	credential = bytes.TrimSpace(credential)
	if len(credential) == 0 {
		return nil, time.Time{}, errors.New("secretrender: the login credential file is empty")
	}
	body, err := json.Marshal(struct {
		Method     string           `json:"method"`
		Credential secret.JSONBytes `json:"credential"`
	}{s.method, secret.JSONBytes(credential)})
	if err != nil {
		return nil, time.Time{}, err
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.server+"/api/v1/secrets/login", bytes.NewReader(body))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.tenant != "" {
		req.Header.Set("X-Tenant-ID", s.tenant)
	}
	req.Header.Set("Idempotency-Key", "secret-render-login-"+crypto.SHA256Hex(credential)[:32]+"-"+
		strconv.FormatInt(s.now().Unix()/600, 10)+"-"+strconv.Itoa(s.logins))
	s.logins++
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, time.Time{}, errors.New("the control plane could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, time.Time{}, refusedError{http.StatusUnauthorized, "the login"}
	case resp.StatusCode != http.StatusOK:
		return nil, time.Time{}, fmt.Errorf("the control plane answered %d to the login", resp.StatusCode)
	}
	var out struct {
		Token     secret.JSONBytes `json:"token"`
		ExpiresAt time.Time        `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil || len(out.Token) == 0 {
		secret.Wipe(out.Token)
		return nil, time.Time{}, errors.New("the control plane's login answer could not be read")
	}
	next, err := NewSessionHTTPClient(s.server, s.tenant, out.Token, s.client)
	if err != nil {
		secret.Wipe(out.Token)
		return nil, time.Time{}, err
	}
	return next, out.ExpiresAt, nil
}

// with runs call over the session, signing in again once when the control
// plane no longer accepts it.
func (s *SessionClient) with(ctx context.Context, call func(*HTTPClient) error) error {
	c, err := s.session(ctx, false)
	if err != nil {
		return err
	}
	if err = call(c); !errors.Is(err, ErrUnauthenticated) {
		return err
	}
	if c, err = s.session(ctx, true); err != nil {
		return err
	}
	return call(c)
}

// Fetch reads one secret over the session.
func (s *SessionClient) Fetch(ctx context.Context, name string) (value []byte, version int, err error) {
	err = s.with(ctx, func(c *HTTPClient) error {
		value, version, err = c.Fetch(ctx, name)
		return err
	})
	return value, version, err
}

// Report sends a delivery report over the session.
func (s *SessionClient) Report(ctx context.Context, consumer, state string, versions map[string]int) error {
	return s.with(ctx, func(c *HTTPClient) error { return c.Report(ctx, consumer, state, versions) })
}

// IssueLease issues a dynamic lease over the session.
func (s *SessionClient) IssueLease(ctx context.Context, provider, role string, ttl time.Duration, key string) (lease Lease, err error) {
	err = s.with(ctx, func(c *HTTPClient) error {
		lease, err = c.IssueLease(ctx, provider, role, ttl, key)
		return err
	})
	return lease, err
}

// RenewLease renews a lease over the session.
func (s *SessionClient) RenewLease(ctx context.Context, id string, extend time.Duration, key string) (expires time.Time, err error) {
	err = s.with(ctx, func(c *HTTPClient) error {
		expires, err = c.RenewLease(ctx, id, extend, key)
		return err
	})
	return expires, err
}

// RevokeLease revokes a lease over the session.
func (s *SessionClient) RevokeLease(ctx context.Context, id, key string) error {
	return s.with(ctx, func(c *HTTPClient) error { return c.RevokeLease(ctx, id, key) })
}

// ReadReplacement reads a replacement publication over the session.
func (s *SessionClient) ReadReplacement(ctx context.Context, id string) (pub ReplacementPublication, err error) {
	err = s.with(ctx, func(c *HTTPClient) error {
		pub, err = c.ReadReplacement(ctx, id)
		return err
	})
	return pub, err
}

// Close ends the session, so its token stops working now, and wipes it.
func (s *SessionClient) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil
	}
	err := s.current.EndSession(ctx, "secret-render-logout-"+strconv.FormatInt(s.now().UnixNano(), 10))
	s.current.Wipe()
	s.current = nil
	return err
}
