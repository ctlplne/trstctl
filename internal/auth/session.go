// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
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
	ErrSessionNotFound      = errors.New("auth: session not found")
	ErrSessionRevoked       = errors.New("auth: session revoked")
	ErrSessionExpired       = errors.New("auth: session has expired")
	ErrSessionInvalid       = errors.New("auth: invalid signed session")
	ErrOIDCSessionLoggedOut = errors.New("auth: OIDC session was signed out by its identity provider")
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
	Session
}

type SessionRecord struct {
	Session
	CreatedAt  time.Time
	LastSeenAt time.Time
	RevokedAt  *time.Time
	// OIDC is present only for a browser session established from a verified
	// OIDC ID token. SAML and LDAP sessions must never match an IdP logout.
	OIDC *OIDCSessionBinding
}

type OIDCSessionBinding struct {
	Issuer   string
	ClientID string
	SID      string
	IssuedAt int64
}

type SessionStore interface {
	Create(context.Context, SessionRecord) error
	Get(context.Context, string, string) (SessionRecord, error)
	Revoke(context.Context, string, string, time.Time) error
	RevokeSubject(context.Context, string, string, time.Time) error
	RevokeOIDC(context.Context, string, LogoutTokenClaims, time.Time) error
	LogoutOIDC(context.Context, LogoutTokenClaims, string, time.Time) error
	Touch(context.Context, string, string, time.Time) error
}

type MemorySessionStore struct {
	mu      sync.Mutex
	rows    map[string]SessionRecord
	logouts map[string]memoryOIDCLogout
}

type memoryOIDCLogout struct {
	claims        LogoutTokenClaims
	assertionHash string
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{rows: map[string]SessionRecord{}, logouts: map[string]memoryOIDCLogout{}}
}

func sessionStoreKey(tenantID, id string) string { return tenantID + "\x00" + id }

func (s *MemorySessionStore) Create(_ context.Context, rec SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.OIDC != nil {
		for _, logout := range s.logouts {
			if oidcLogoutMatchesRecord(logout.claims, rec) {
				return ErrOIDCSessionLoggedOut
			}
		}
	}
	rec.Roles = append([]string(nil), rec.Roles...)
	s.rows[sessionStoreKey(rec.TenantID, rec.ID)] = rec
	return nil
}

// LogoutOIDC is the in-memory test counterpart of the PostgreSQL authority
// transaction. Production uses the durable, indexed PostgreSQL receiver.
func (s *MemorySessionStore) LogoutOIDC(_ context.Context, claims LogoutTokenClaims, assertionHash string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := claims.Issuer + "\x00" + claims.ClientID + "\x00" + claims.JTI
	if prior, ok := s.logouts[key]; ok {
		if prior.assertionHash == assertionHash {
			return nil
		}
		return ErrLogoutTokenReplay
	}
	for id, rec := range s.rows {
		if rec.RevokedAt != nil || !oidcLogoutMatchesRecord(claims, rec) {
			continue
		}
		rec.RevokedAt = &revokedAt
		s.rows[id] = rec
	}
	s.logouts[key] = memoryOIDCLogout{claims: claims, assertionHash: assertionHash}
	return nil
}

func oidcLogoutMatchesRecord(claims LogoutTokenClaims, rec SessionRecord) bool {
	binding := rec.OIDC
	return binding != nil && binding.Issuer == claims.Issuer && binding.ClientID == claims.ClientID &&
		(claims.Subject == "" || rec.Subject == claims.Subject) &&
		(claims.SID == "" || binding.SID == claims.SID) &&
		(claims.SID != "" || binding.IssuedAt <= claims.IssuedAt)
}

func (s *MemorySessionStore) Get(_ context.Context, tenantID, id string) (SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.rows[sessionStoreKey(tenantID, id)]
	if !ok {
		return SessionRecord{}, ErrSessionNotFound
	}
	rec.Roles = append([]string(nil), rec.Roles...)
	return rec, nil
}

func (s *MemorySessionStore) Revoke(_ context.Context, tenantID, id string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sessionStoreKey(tenantID, id)
	rec, ok := s.rows[key]
	if !ok {
		return ErrSessionNotFound
	}
	rec.RevokedAt = &revokedAt
	s.rows[key] = rec
	return nil
}

func (s *MemorySessionStore) RevokeSubject(_ context.Context, tenantID, subject string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range s.rows {
		if rec.TenantID == tenantID && rec.Subject == subject && rec.RevokedAt == nil {
			rec.RevokedAt = &revokedAt
			s.rows[id] = rec
		}
	}
	return nil
}

func (s *MemorySessionStore) RevokeOIDC(_ context.Context, tenantID string, claims LogoutTokenClaims, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range s.rows {
		binding := rec.OIDC
		if rec.TenantID != tenantID || binding == nil || rec.RevokedAt != nil ||
			binding.Issuer != claims.Issuer || binding.ClientID != claims.ClientID ||
			(claims.Subject != "" && rec.Subject != claims.Subject) ||
			(claims.SID != "" && binding.SID != claims.SID) {
			continue
		}
		rec.RevokedAt = &revokedAt
		s.rows[id] = rec
	}
	return nil
}

func (s *MemorySessionStore) Touch(_ context.Context, tenantID, id string, seenAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sessionStoreKey(tenantID, id)
	rec, ok := s.rows[key]
	if !ok {
		return ErrSessionNotFound
	}
	rec.LastSeenAt = seenAt
	s.rows[key] = rec
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
	return s.IssueContext(context.Background(), subject, tenantID, email, roles)
}

// IssueContext mints a signed, opaque-ID cookie and records only a digest of its
// random ID in the shared session store.
func (s *SessionIssuer) IssueContext(ctx context.Context, subject, tenantID, email string, roles []string) (string, error) {
	return s.issueContext(ctx, subject, tenantID, email, roles, nil)
}

// IssueOIDCContext keeps the verified provider and IdP session binding with
// the browser-session authority. A backchannel logout must use these bindings
// rather than equating an IdP sid with trstctl's independent cookie ID.
func (s *SessionIssuer) IssueOIDCContext(ctx context.Context, subject, tenantID, email string, roles []string, binding OIDCSessionBinding) (string, error) {
	if binding.Issuer == "" || binding.ClientID == "" || binding.IssuedAt <= 0 || subject == "" {
		return "", ErrSessionInvalid
	}
	return s.issueContext(ctx, subject, tenantID, email, roles, &binding)
}

func (s *SessionIssuer) issueContext(ctx context.Context, subject, tenantID, email string, roles []string, binding *OIDCSessionBinding) (string, error) {
	now := s.now()
	id, err := randomSessionID()
	if err != nil {
		return "", err
	}
	expiresAt := now.Add(s.ttl)
	storedID := crypto.SHA256Hex([]byte(id))
	session := Session{
		ID: id, Subject: subject, TenantID: tenantID, Email: email, Roles: append([]string(nil), roles...),
		ExpiresAt: expiresAt.Unix(),
	}
	stored := session
	stored.ID = storedID
	if err := s.store.Create(ctx, SessionRecord{
		Session: Session{
			ID: stored.ID, Subject: subject, TenantID: tenantID, Email: email, Roles: append([]string(nil), roles...),
			ExpiresAt: expiresAt.Unix(),
		},
		CreatedAt: now, LastSeenAt: now, OIDC: binding,
	}); err != nil {
		return "", err
	}
	b, err := json.Marshal(sessionCookie{Session: session})
	if err != nil {
		return "", err
	}
	return jose.SignHS256(s.secret, b), nil
}

// Verify validates a session token's signature and expiry and returns the
// session.
func (s *SessionIssuer) Verify(token string) (Session, error) {
	return s.VerifyContext(context.Background(), token)
}

func (s *SessionIssuer) VerifyContext(ctx context.Context, token string) (Session, error) {
	rec, err := s.verifySignedRecord(ctx, token)
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	if rec.RevokedAt != nil {
		return Session{}, ErrSessionRevoked
	}
	if s.idleTimeout > 0 && !rec.LastSeenAt.IsZero() && !rec.LastSeenAt.Add(s.idleTimeout).After(now) {
		return Session{}, ErrSessionExpired
	}
	_ = s.store.Touch(ctx, rec.TenantID, crypto.SHA256Hex([]byte(rec.ID)), now)
	return rec.Session, nil
}

// VerifyForLogout authenticates the signed, unexpired cookie but deliberately
// returns an already-revoked record. This narrow seam lets an exact logout
// transport retry reach its completed idempotency receipt after the first call
// revoked the session. It does not refresh last-seen time and must never be
// used to authorize any operation other than logout.
func (s *SessionIssuer) VerifyForLogout(token string) (Session, error) {
	return s.VerifyForLogoutContext(context.Background(), token)
}

func (s *SessionIssuer) VerifyForLogoutContext(ctx context.Context, token string) (Session, error) {
	rec, err := s.verifySignedRecord(ctx, token)
	if err != nil {
		return Session{}, err
	}
	return rec.Session, nil
}

func (s *SessionIssuer) verifySignedRecord(ctx context.Context, token string) (SessionRecord, error) {
	b, err := jose.VerifyHS256(s.secret, token)
	if err != nil {
		return SessionRecord{}, ErrSessionInvalid
	}
	var cookie sessionCookie
	if err := json.Unmarshal(b, &cookie); err != nil {
		return SessionRecord{}, ErrSessionInvalid
	}
	now := s.now()
	if cookie.ID == "" || cookie.Subject == "" || cookie.TenantID == "" || cookie.ExpiresAt <= now.Unix() {
		return SessionRecord{}, ErrSessionExpired
	}
	storedID := crypto.SHA256Hex([]byte(cookie.ID))
	rec, err := s.store.Get(ctx, cookie.TenantID, storedID)
	if err != nil {
		return SessionRecord{}, err
	}
	if rec.ExpiresAt <= now.Unix() {
		return SessionRecord{}, ErrSessionExpired
	}
	// The server-side row is revocation/idle authority; the signed cookie carries
	// the authenticated display claims. Restore the raw ID only after both agree.
	rec.Session = cookie.Session
	return rec, nil
}

func (s *SessionIssuer) Revoke(id string) error {
	return errors.New("auth: tenant id is required to revoke a browser session")
}

func (s *SessionIssuer) RevokeContext(ctx context.Context, tenantID, id string) error {
	return s.store.Revoke(ctx, tenantID, crypto.SHA256Hex([]byte(id)), s.now())
}

func (s *SessionIssuer) RevokeSubject(subject string) error {
	return errors.New("auth: tenant id is required to revoke browser sessions by subject")
}

func (s *SessionIssuer) RevokeSubjectContext(ctx context.Context, tenantID, subject string) error {
	return s.store.RevokeSubject(ctx, tenantID, subject, s.now())
}

func (s *SessionIssuer) RevokeOIDCContext(ctx context.Context, tenantID string, claims LogoutTokenClaims) error {
	return s.store.RevokeOIDC(ctx, tenantID, claims, s.now())
}

func (s *SessionIssuer) LogoutOIDCContext(ctx context.Context, claims LogoutTokenClaims, assertionHash string) error {
	return s.store.LogoutOIDC(ctx, claims, assertionHash, s.now())
}

func randomSessionID() (string, error) {
	b, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}
