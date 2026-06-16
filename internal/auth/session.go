package auth

import (
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// Session is the authenticated session minted after a successful login. Roles
// are the RBAC role names the logged-in user holds; the API's principal resolver
// maps them to grants so a session authorizes API calls (not just /auth/me).
type Session struct {
	Subject   string   `json:"sub"`
	TenantID  string   `json:"tenant"`
	Email     string   `json:"email,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	ExpiresAt int64    `json:"exp"`
}

// SessionIssuer mints and verifies stateless, HMAC-signed session tokens.
type SessionIssuer struct {
	secret []byte
	ttl    time.Duration
	Now    func() time.Time
}

// NewSessionIssuer returns an issuer that signs sessions with secret and gives
// them a lifetime of ttl.
func NewSessionIssuer(secret []byte, ttl time.Duration) *SessionIssuer {
	return &SessionIssuer{secret: secret, ttl: ttl}
}

func (s *SessionIssuer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Issue mints a signed session token for the subject in a tenant, carrying the
// RBAC role names the user holds.
func (s *SessionIssuer) Issue(subject, tenantID, email string, roles []string) (string, error) {
	b, err := json.Marshal(Session{
		Subject: subject, TenantID: tenantID, Email: email, Roles: roles,
		ExpiresAt: s.now().Add(s.ttl).Unix(),
	})
	if err != nil {
		return "", err
	}
	return jose.SignHS256(s.secret, b), nil
}

// Verify validates a session token's signature and expiry and returns the
// session.
func (s *SessionIssuer) Verify(token string) (Session, error) {
	b, err := jose.VerifyHS256(s.secret, token)
	if err != nil {
		return Session{}, err
	}
	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return Session{}, err
	}
	if sess.ExpiresAt <= s.now().Unix() {
		return Session{}, errors.New("auth: session has expired")
	}
	return sess, nil
}
