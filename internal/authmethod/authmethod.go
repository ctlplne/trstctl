// Package authmethod is the platform auth-method framework (S16.1, F58): the
// first-class machine-identity *login* methods workloads use to authenticate TO
// trstctl's secrets/identity layer (distinct from issuance attestation, which
// gates issuance). A Method verifies a credential and yields a principal+scopes;
// the Manager turns that into a scoped, audited, tenant-scoped Session. Method
// credentials are []byte and never logged (AN-8); sessions are audited (AN-2);
// methods are tenant-scoped (AN-1).
package authmethod

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
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
		_ = auditsink.Emit(ctx, m.cfg.Audit, nil, "auth.rejected", m.cfg.TenantID, []byte(fmt.Sprintf(`{"method":%q}`, method)))
		return Session{}, fmt.Errorf("authmethod: %s authentication failed: %w", method, err)
	}
	// Fail closed on an RNG failure: a discarded error would leave idb as 16 zero
	// bytes and mint an all-zero, guessable, non-unique session ID. Propagate it
	// instead so no session is issued (GAP-008).
	idb, err := crypto.RandomBytes(16)
	if err != nil {
		return Session{}, fmt.Errorf("authmethod: generate session id: %w", err)
	}
	now := m.cfg.Clock()
	sess := Session{
		ID: hex.EncodeToString(idb), TenantID: m.cfg.TenantID, Principal: principal,
		Method: method, Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(m.cfg.TTL),
	}
	_ = auditsink.Emit(ctx, m.cfg.Audit, nil, "auth.session.issued", m.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"method":%q,"principal":%q,"scopes":%d}`, method, principal, len(scopes))))
	return sess, nil
}

// TokenMethod authenticates a bearer token whose canonical form is
// "<principal>.<expUnix>.<hexHMAC>", where the MAC is
// HMAC-SHA256(secret, principal+"."+expUnix) computed via the crypto boundary, and
// expUnix is the token's expiry as a Unix-seconds integer. Binding the expiry into
// the MAC means a captured token stops working at expUnix and the expiry cannot be
// tampered without the secret (GAP-008). Scopes are looked up per principal.
//
// The legacy two-field form "<principal>.<hexHMAC>" (MAC over the principal alone)
// has no expiry and is therefore an indefinite, replayable credential; it is
// rejected unless AllowUnexpiring is set, so the default is fail-closed against
// never-expiring tokens.
type TokenMethod struct {
	Secret []byte
	Scopes map[string][]string
	// AllowUnexpiring, when true, accepts the legacy two-field form with no expiry.
	// Leave it false (the default) so every accepted token is expiry-bound.
	AllowUnexpiring bool
	// Clock overrides the expiry comparison clock (tests); nil selects time.Now.
	Clock func() time.Time
}

// Name implements Method.
func (TokenMethod) Name() string { return "token" }

// Issue mints a canonical, expiry-bound token for principal valid until expiresAt.
// The returned string is "<principal>.<expUnix>.<hexHMAC>"; presenting it after
// expiresAt is rejected by Authenticate. principal must not contain a '.' (it is
// the MAC-covered field separator).
func (t TokenMethod) Issue(principal string, expiresAt time.Time) (string, error) {
	if principal == "" || strings.ContainsRune(principal, '.') {
		return "", fmt.Errorf("authmethod: token principal must be non-empty and contain no '.'")
	}
	exp := strconv.FormatInt(expiresAt.Unix(), 10)
	mac := crypto.HMACSHA256(t.Secret, []byte(principal+"."+exp))
	return principal + "." + exp + "." + hex.EncodeToString(mac), nil
}

// Authenticate implements Method.
func (t TokenMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	parts := bytes.Split(credential, []byte("."))
	switch len(parts) {
	case 3:
		// Canonical expiry-bound form: principal.expUnix.hexHMAC.
		principalBytes, expBytes, macHex := parts[0], parts[1], parts[2]
		if len(principalBytes) == 0 || len(expBytes) == 0 {
			return "", nil, fmt.Errorf("malformed token")
		}
		exp, err := parseUnixBytes(expBytes)
		if err != nil {
			return "", nil, fmt.Errorf("malformed token expiry")
		}
		mac := make([]byte, hex.DecodedLen(len(macHex)))
		if _, err := hex.Decode(mac, macHex); err != nil {
			return "", nil, fmt.Errorf("malformed token MAC")
		}
		// Verify the MAC over principal+"."+expStr BEFORE trusting the expiry, so a
		// tampered expiry fails the constant-time MAC check rather than extending the
		// token's life.
		covered := make([]byte, 0, len(principalBytes)+1+len(expBytes))
		covered = append(covered, principalBytes...)
		covered = append(covered, '.')
		covered = append(covered, expBytes...)
		want := crypto.HMACSHA256(t.Secret, covered)
		if !crypto.ConstantTimeEqual(mac, want) {
			return "", nil, fmt.Errorf("invalid token")
		}
		now := time.Now
		if t.Clock != nil {
			now = t.Clock
		}
		if !now().Before(time.Unix(exp, 0)) {
			return "", nil, fmt.Errorf("token expired")
		}
		principal := string(principalBytes)
		return principal, t.Scopes[principal], nil
	case 2:
		// Legacy unbounded form: principal.hexHMAC (MAC over the principal only). It
		// never expires, so accept it only when the operator has opted in.
		if !t.AllowUnexpiring {
			return "", nil, fmt.Errorf("unexpiring token rejected (set AllowUnexpiring to accept the legacy form)")
		}
		principalBytes, macHex := parts[0], parts[1]
		if len(principalBytes) == 0 {
			return "", nil, fmt.Errorf("malformed token")
		}
		mac := make([]byte, hex.DecodedLen(len(macHex)))
		if _, err := hex.Decode(mac, macHex); err != nil {
			return "", nil, fmt.Errorf("malformed token MAC")
		}
		want := crypto.HMACSHA256(t.Secret, principalBytes)
		if !crypto.ConstantTimeEqual(mac, want) {
			return "", nil, fmt.Errorf("invalid token")
		}
		principal := string(principalBytes)
		return principal, t.Scopes[principal], nil
	default:
		return "", nil, fmt.Errorf("malformed token")
	}
}

func parseUnixBytes(b []byte) (int64, error) {
	const maxInt64 = int64(9223372036854775807)
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a base-10 integer")
		}
		d := int64(c - '0')
		if n > (maxInt64-d)/10 {
			return 0, fmt.Errorf("integer overflow")
		}
		n = n*10 + d
	}
	return n, nil
}

// OIDCMethod authenticates an OIDC/JWT credential against a JWKS (reusing the
// crypto-boundary JWT verification). After the signature is checked it validates
// the registered JWT claims (RFC 7519): issuer, audience (which may be a single
// string OR an array), expiry (exp), not-before (nbf), and issued-at (iat) — the
// last two with a small clock-skew leeway. The subject (sub) is the principal.
//
// When a Replay cache is configured, the token's jti is recorded and a replayed
// jti is rejected until its exp, giving single-use semantics (a captured token
// cannot be re-presented). The cache is bounded (AN-7): it self-evicts expired
// entries and never grows without limit.
type OIDCMethod struct {
	JWKS     crypto.JWKS
	Issuer   string
	Audience string
	Now      func() time.Time
	// Leeway tolerates small clock skew on the nbf/iat checks. Zero selects a
	// conservative default (defaultLeeway); negative is treated as zero.
	Leeway time.Duration
	// Replay, when non-nil, enforces single-use tokens by jti (see WithReplayGuard).
	Replay *JTICache
}

// WithReplayGuard returns a copy of o with a bounded jti replay cache attached,
// so a token presented twice (same jti, before exp) is rejected the second time.
// maxEntries caps the cache (AN-7); <=0 selects defaultJTICacheCap.
func (o OIDCMethod) WithReplayGuard(maxEntries int) OIDCMethod {
	o.Replay = NewJTICache(maxEntries)
	return o
}

// Name implements Method.
func (OIDCMethod) Name() string { return "oidc" }

// defaultLeeway is the clock-skew tolerance applied to nbf/iat when Leeway is
// unset. It must be small: a large leeway widens the window in which a not-yet-
// valid (pre-issued) token is accepted.
const defaultLeeway = 60 * time.Second

// Authenticate implements Method.
func (o OIDCMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	raw, err := crypto.VerifyJWTBytes(credential, o.JWKS)
	if err != nil {
		return "", nil, err
	}
	var c struct {
		Iss    string   `json:"iss"`
		Aud    audience `json:"aud"`
		Sub    string   `json:"sub"`
		Exp    int64    `json:"exp"`
		Nbf    int64    `json:"nbf"`
		Iat    int64    `json:"iat"`
		JTI    string   `json:"jti"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", nil, err
	}
	if o.Issuer != "" && c.Iss != o.Issuer {
		return "", nil, fmt.Errorf("unexpected issuer")
	}
	// Audience accepts a single string or an array (RFC 7519 §4.1.3): the token
	// is valid if our expected audience appears among its aud values.
	if o.Audience != "" && !c.Aud.contains(o.Audience) {
		return "", nil, fmt.Errorf("unexpected audience")
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	leeway := o.Leeway
	if leeway <= 0 {
		leeway = defaultLeeway
	}
	nowT := now()
	// exp is mandatory: a token with no expiry is an indefinite, replayable
	// credential. OpenID Connect Core §2 requires exp in an ID token, so reject
	// a missing/zero exp outright rather than treating it as "never expires".
	if c.Exp == 0 {
		return "", nil, fmt.Errorf("token has no exp claim")
	}
	if !nowT.Before(time.Unix(c.Exp, 0)) {
		return "", nil, fmt.Errorf("token expired")
	}
	// nbf: the token is not valid before nbf. Reject a token whose nbf is in the
	// future beyond the leeway — a pre-issued future token must not be usable now.
	if c.Nbf != 0 && nowT.Add(leeway).Before(time.Unix(c.Nbf, 0)) {
		return "", nil, fmt.Errorf("token not yet valid (nbf)")
	}
	// iat: reject a token claiming to be issued in the future beyond the leeway
	// (a forged/skewed issued-at).
	if c.Iat != 0 && nowT.Add(leeway).Before(time.Unix(c.Iat, 0)) {
		return "", nil, fmt.Errorf("token issued in the future (iat)")
	}
	if c.Sub == "" {
		return "", nil, fmt.Errorf("token has no subject")
	}
	// Replay defence: when a cache is configured the token must carry a jti, and a
	// jti seen before (within its validity) is rejected as a replay.
	if o.Replay != nil {
		if c.JTI == "" {
			return "", nil, fmt.Errorf("token has no jti (replay defence requires one)")
		}
		if !o.Replay.Add(c.JTI, time.Unix(c.Exp, 0), nowT) {
			return "", nil, fmt.Errorf("token replayed (jti already seen)")
		}
	}
	return c.Sub, []string(c.Scopes), nil
}

// audience is a JWT aud claim, which RFC 7519 §4.1.3 permits to be either a
// single string or an array of strings. It unmarshals both forms.
type audience []string

// UnmarshalJSON accepts a JSON string or array of strings.
func (a *audience) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*a = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		*a = nil
		return nil
	}
	*a = []string{s}
	return nil
}

func (a audience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}
