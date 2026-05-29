package auth

import (
	"encoding/json"
	"errors"
	"time"

	"certctl.io/certctl/internal/crypto/jose"
)

// Session is the authenticated session minted after a successful login.
type Session struct {
	Subject   string `json:"sub"`
	TenantID  string `json:"tenant"`
	Email     string `json:"email,omitempty"`
	ExpiresAt int64  `json:"exp"`
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

// Issue mints a signed session token for the subject in a tenant.
func (s *SessionIssuer) Issue(subject, tenantID, email string) (string, error) {
	b, err := json.Marshal(Session{
		Subject: subject, TenantID: tenantID, Email: email,
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
