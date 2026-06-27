package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/secret"
)

var (
	ErrSessionNotFound = errors.New("auth: session not found")
	ErrSessionRevoked  = errors.New("auth: session revoked")
	ErrSessionExpired  = errors.New("auth: session has expired")
)

// Session is the authenticated session minted after a successful login. Roles
// are the RBAC role names the logged-in user holds; the API's principal resolver
// maps them to grants so a session authorizes API calls (not just /auth/me).
type Session struct {
	ID        string   `json:"sid"`
	Subject   string   `json:"sub"`
	TenantID  string   `json:"tenant"`
	Email     string   `json:"email,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	ExpiresAt int64    `json:"exp"`
}

type sessionCookie struct {
	ID        string `json:"sid"`
	ExpiresAt int64  `json:"exp"`
}

type SessionRecord struct {
	Session
	CreatedAt  time.Time
	LastSeenAt time.Time
	RevokedAt  *time.Time
}

type SessionStore interface {
	Create(SessionRecord) error
	Get(id string) (SessionRecord, error)
	Revoke(id string, revokedAt time.Time) error
	RevokeSubject(subject string, revokedAt time.Time) error
	Touch(id string, seenAt time.Time) error
}

type MemorySessionStore struct {
	mu   sync.Mutex
	rows map[string]SessionRecord
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{rows: map[string]SessionRecord{}}
}

func (s *MemorySessionStore) Create(rec SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.Roles = append([]string(nil), rec.Roles...)
	s.rows[rec.ID] = rec
	return nil
}

func (s *MemorySessionStore) Get(id string) (SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.rows[id]
	if !ok {
		return SessionRecord{}, ErrSessionNotFound
	}
	rec.Roles = append([]string(nil), rec.Roles...)
	return rec, nil
}

func (s *MemorySessionStore) Revoke(id string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.rows[id]
	if !ok {
		return ErrSessionNotFound
	}
	rec.RevokedAt = &revokedAt
	s.rows[id] = rec
	return nil
}

func (s *MemorySessionStore) RevokeSubject(subject string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range s.rows {
		if rec.Subject == subject && rec.RevokedAt == nil {
			rec.RevokedAt = &revokedAt
			s.rows[id] = rec
		}
	}
	return nil
}

func (s *MemorySessionStore) Touch(id string, seenAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.rows[id]
	if !ok {
		return ErrSessionNotFound
	}
	rec.LastSeenAt = seenAt
	s.rows[id] = rec
	return nil
}

// SessionIssuer mints and verifies HMAC-signed opaque session-id cookies backed by
// a server-side session store.
type SessionIssuer struct {
	secret      []byte
	ttl         time.Duration
	idleTimeout time.Duration
	store       SessionStore
	Now         func() time.Time
}

// NewSessionIssuer returns an issuer that signs sessions with secret and gives
// them a lifetime of ttl.
func NewSessionIssuer(secret []byte, ttl time.Duration) *SessionIssuer {
	return NewSessionIssuerWithStore(secret, ttl, ttl, NewMemorySessionStore())
}

func NewSessionIssuerWithStore(secret []byte, ttl, idleTimeout time.Duration, store SessionStore) *SessionIssuer {
	if store == nil {
		store = NewMemorySessionStore()
	}
	return &SessionIssuer{secret: secret, ttl: ttl, idleTimeout: idleTimeout, store: store}
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
	now := s.now()
	id, err := randomSessionID()
	if err != nil {
		return "", err
	}
	expiresAt := now.Add(s.ttl)
	if err := s.store.Create(SessionRecord{
		Session: Session{
			ID: id, Subject: subject, TenantID: tenantID, Email: email, Roles: roles,
			ExpiresAt: expiresAt.Unix(),
		},
		CreatedAt: now, LastSeenAt: now,
	}); err != nil {
		return "", err
	}
	b, err := json.Marshal(sessionCookie{ID: id, ExpiresAt: expiresAt.Unix()})
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
	var cookie sessionCookie
	if err := json.Unmarshal(b, &cookie); err != nil {
		return Session{}, err
	}
	now := s.now()
	if cookie.ID == "" || cookie.ExpiresAt <= now.Unix() {
		return Session{}, ErrSessionExpired
	}
	rec, err := s.store.Get(cookie.ID)
	if err != nil {
		return Session{}, err
	}
	if rec.RevokedAt != nil {
		return Session{}, ErrSessionRevoked
	}
	if rec.ExpiresAt <= now.Unix() {
		return Session{}, ErrSessionExpired
	}
	if s.idleTimeout > 0 && !rec.LastSeenAt.IsZero() && !rec.LastSeenAt.Add(s.idleTimeout).After(now) {
		return Session{}, ErrSessionExpired
	}
	_ = s.store.Touch(cookie.ID, now)
	return rec.Session, nil
}

func (s *SessionIssuer) Revoke(id string) error {
	return s.store.Revoke(id, s.now())
}

func (s *SessionIssuer) RevokeSubject(subject string) error {
	return s.store.RevokeSubject(subject, s.now())
}

func randomSessionID() (string, error) {
	b, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}
