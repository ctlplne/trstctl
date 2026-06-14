// Package authmethod is the platform auth-method framework (S16.1, F58): the
// first-class machine-identity *login* methods workloads use to authenticate TO
// trustctl's secrets/identity layer (distinct from issuance attestation, which
// gates issuance). A Method verifies a credential and yields a principal+scopes;
// the Manager turns that into a scoped, audited, tenant-scoped Session. Method
// credentials are []byte and never logged (AN-8); sessions are audited (AN-2);
// methods are tenant-scoped (AN-1).
package authmethod

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
)

// Method is one login method (Kubernetes, AWS/GCP/Azure, OIDC, LDAP, TLS-cert,
// token, ...). Concrete methods implement only verification.
type Method interface {
	Name() string
	Authenticate(ctx context.Context, credential []byte) (principal string, scopes []string, err error)
}

// Session is a scoped, audited login session.
type Session struct {
	ID        string
	TenantID  string
	Principal string
	Method    string
	Scopes    []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Config configures a Manager.
type Config struct {
	TenantID string
	Methods  []Method
	Audit    auditsink.Auditor
	TTL      time.Duration
	Clock    func() time.Time
}

// Manager issues sessions via registered methods.
type Manager struct {
	cfg     Config
	methods map[string]Method
}

// New validates configuration and constructs a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("authmethod: TenantID required (AN-1)")
	}
	m := map[string]Method{}
	for _, meth := range cfg.Methods {
		if meth == nil || meth.Name() == "" {
			return nil, fmt.Errorf("authmethod: method with empty name")
		}
		m[meth.Name()] = meth
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Manager{cfg: cfg, methods: m}, nil
}

// Login authenticates a credential via the named method and returns a scoped
// session. An invalid credential is rejected and audited (fail-closed).
func (m *Manager) Login(ctx context.Context, method string, credential []byte) (Session, error) {
	meth, ok := m.methods[method]
	if !ok {
		return Session{}, fmt.Errorf("authmethod: unknown method %q", method)
	}
	principal, scopes, err := meth.Authenticate(ctx, credential)
	if err != nil {
		_ = m.cfg.Audit.Audit(ctx, "auth.rejected", m.cfg.TenantID, []byte(fmt.Sprintf(`{"method":%q}`, method)))
		return Session{}, fmt.Errorf("authmethod: %s authentication failed: %w", method, err)
	}
	idb, _ := crypto.RandomBytes(16)
	now := m.cfg.Clock()
	sess := Session{
		ID: hex.EncodeToString(idb), TenantID: m.cfg.TenantID, Principal: principal,
		Method: method, Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(m.cfg.TTL),
	}
	_ = m.cfg.Audit.Audit(ctx, "auth.session.issued", m.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"method":%q,"principal":%q,"scopes":%d}`, method, principal, len(scopes))))
	return sess, nil
}

// TokenMethod authenticates a bearer token of the form "<principal>.<hexHMAC>",
// where the MAC is HMAC-SHA256(secret, principal) (computed via the crypto
// boundary). Scopes are looked up per principal.
type TokenMethod struct {
	Secret []byte
	Scopes map[string][]string
}

// Name implements Method.
func (TokenMethod) Name() string { return "token" }

// Authenticate implements Method.
func (t TokenMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	s := string(credential)
	dot := -1
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 {
		return "", nil, fmt.Errorf("malformed token")
	}
	principal, macHex := s[:dot], s[dot+1:]
	mac, err := hex.DecodeString(macHex)
	if err != nil {
		return "", nil, fmt.Errorf("malformed token MAC")
	}
	want := crypto.HMACSHA256(t.Secret, []byte(principal))
	if !crypto.ConstantTimeEqual(mac, want) {
		return "", nil, fmt.Errorf("invalid token")
	}
	return principal, t.Scopes[principal], nil
}

// OIDCMethod authenticates an OIDC/JWT credential against a JWKS (reusing the
// crypto-boundary JWT verification). It checks issuer/audience/expiry; the subject
// is the principal.
type OIDCMethod struct {
	JWKS     crypto.JWKS
	Issuer   string
	Audience string
	Now      func() time.Time
}

// Name implements Method.
func (OIDCMethod) Name() string { return "oidc" }

// Authenticate implements Method.
func (o OIDCMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	raw, err := crypto.VerifyJWT(string(credential), o.JWKS)
	if err != nil {
		return "", nil, err
	}
	var c struct {
		Iss    string   `json:"iss"`
		Aud    string   `json:"aud"`
		Sub    string   `json:"sub"`
		Exp    int64    `json:"exp"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", nil, err
	}
	if o.Issuer != "" && c.Iss != o.Issuer {
		return "", nil, fmt.Errorf("unexpected issuer")
	}
	if o.Audience != "" && c.Aud != o.Audience {
		return "", nil, fmt.Errorf("unexpected audience")
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if c.Exp != 0 && now().Unix() >= c.Exp {
		return "", nil, fmt.Errorf("token expired")
	}
	if c.Sub == "" {
		return "", nil, fmt.Errorf("token has no subject")
	}
	return c.Sub, c.Scopes, nil
}
