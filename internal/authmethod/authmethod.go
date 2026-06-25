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
		switch tm := meth.(type) {
		case TokenMethod:
			if tm.TenantID == "" {
				tm.TenantID = cfg.TenantID
			}
			meth = tm
		case *TokenMethod:
			if tm != nil && tm.TenantID == "" {
				clone := *tm
				clone.TenantID = cfg.TenantID
				meth = &clone
			}
		}
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

const defaultTokenAudience = "machine-login"

// TokenMethod authenticates a bearer token whose tenant-scoped canonical form is
// "v1.<tenant>.<audience>.<principal>.<expUnix>.<hexHMAC>", where the MAC is
// HMAC-SHA256(secret, "v1."+tenant+"."+audience+"."+principal+"."+expUnix)
// computed via the crypto boundary, and expUnix is the token's expiry as a
// Unix-seconds integer. Binding tenant, audience, and expiry into the MAC means a
// captured token cannot be replayed into another tenant, cannot be replayed at a
// different consumer, and stops working at expUnix (WIRE-002, GAP-008). Scopes are
// looked up per principal.
//
// The earlier three-field form "<principal>.<expUnix>.<hexHMAC>" is accepted only
// when TenantID is empty. Served machine login always configures TenantID, so a
// public X-Tenant-ID header is a lookup hint, not a tenant authority.
//
// The legacy two-field form "<principal>.<hexHMAC>" (MAC over the principal alone)
// has no expiry and is therefore an indefinite, replayable credential; it is
// rejected unless AllowUnexpiring is set, so the default is fail-closed against
// never-expiring tokens.
type TokenMethod struct {
	Secret []byte
	// TenantID, when set, is MAC-bound into every token and checked during
	// authentication. It must match the tenant-scoped Manager using this method.
	TenantID string
	// Audience, when set, is MAC-bound into every token. Empty selects the machine
	// login audience so tokens cannot be replayed into future TokenMethod consumers.
	Audience string
	Scopes   map[string][]string
	// AllowUnexpiring, when true, accepts the legacy two-field form with no expiry.
	// Leave it false (the default) so every accepted token is expiry-bound.
	AllowUnexpiring bool
	// Clock overrides the expiry comparison clock (tests); nil selects time.Now.
	Clock func() time.Time
}

// Name implements Method.
func (TokenMethod) Name() string { return "token" }

// Issue mints a canonical, expiry-bound token for principal valid until expiresAt.
// When TenantID is configured, the returned token is tenant/audience-bound. With an
// empty TenantID, Issue retains the older tenantless three-field form for direct
// tests and non-served callers; tenant-scoped Managers reject that form.
func (t TokenMethod) Issue(principal string, expiresAt time.Time) (string, error) {
	if principal == "" || strings.ContainsRune(principal, '.') {
		return "", fmt.Errorf("authmethod: token principal must be non-empty and contain no '.'")
	}
	exp := strconv.FormatInt(expiresAt.Unix(), 10)
	if t.TenantID != "" {
		if strings.ContainsRune(t.TenantID, '.') || strings.ContainsRune(t.audience(), '.') {
			return "", fmt.Errorf("authmethod: token tenant and audience must contain no '.'")
		}
		covered := tokenMACInput([]byte("v1"), []byte(t.TenantID), []byte(t.audience()), []byte(principal), []byte(exp))
		mac := crypto.HMACSHA256(t.Secret, covered)
		return "v1." + t.TenantID + "." + t.audience() + "." + principal + "." + exp + "." + hex.EncodeToString(mac), nil
	}
	mac := crypto.HMACSHA256(t.Secret, []byte(principal+"."+exp))
	return principal + "." + exp + "." + hex.EncodeToString(mac), nil
}

// Authenticate implements Method.
func (t TokenMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	parts := bytes.Split(credential, []byte("."))
	switch len(parts) {
	case 6:
		// Canonical tenant/audience-bound form:
		// v1.tenant.audience.principal.expUnix.hexHMAC.
		version, tenantBytes, audienceBytes, principalBytes, expBytes, macHex := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
		if !bytes.Equal(version, []byte("v1")) || len(tenantBytes) == 0 || len(audienceBytes) == 0 || len(principalBytes) == 0 || len(expBytes) == 0 {
			return "", nil, fmt.Errorf("malformed token")
		}
		if t.TenantID != "" && !bytes.Equal(tenantBytes, []byte(t.TenantID)) {
			return "", nil, fmt.Errorf("token tenant mismatch")
		}
		if !bytes.Equal(audienceBytes, []byte(t.audience())) {
			return "", nil, fmt.Errorf("token audience mismatch")
		}
		exp, err := parseUnixBytes(expBytes)
		if err != nil {
			return "", nil, fmt.Errorf("malformed token expiry")
		}
		mac := make([]byte, hex.DecodedLen(len(macHex)))
		if _, err := hex.Decode(mac, macHex); err != nil {
			return "", nil, fmt.Errorf("malformed token MAC")
		}
		covered := tokenMACInput(version, tenantBytes, audienceBytes, principalBytes, expBytes)
		want := crypto.HMACSHA256(t.Secret, covered)
		if !crypto.ConstantTimeEqual(mac, want) {
			return "", nil, fmt.Errorf("invalid token")
		}
		if !t.now().Before(time.Unix(exp, 0)) {
			return "", nil, fmt.Errorf("token expired")
		}
		principal := string(principalBytes)
		return principal, t.Scopes[principal], nil
	case 3:
		// Canonical expiry-bound form: principal.expUnix.hexHMAC.
		if t.TenantID != "" {
			return "", nil, fmt.Errorf("tenantless token rejected")
		}
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
		if !t.now().Before(time.Unix(exp, 0)) {
			return "", nil, fmt.Errorf("token expired")
		}
		principal := string(principalBytes)
		return principal, t.Scopes[principal], nil
	case 2:
		// Legacy unbounded form: principal.hexHMAC (MAC over the principal only). It
		// never expires, so accept it only when the operator has opted in.
		if t.TenantID != "" {
			return "", nil, fmt.Errorf("tenantless token rejected")
		}
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

func (t TokenMethod) audience() string {
	if t.Audience != "" {
		return t.Audience
	}
	return defaultTokenAudience
}

func (t TokenMethod) now() time.Time {
	if t.Clock != nil {
		return t.Clock()
	}
	return time.Now()
}

func tokenMACInput(parts ...[]byte) []byte {
	n := 0
	for _, part := range parts {
		n += len(part)
	}
	n += len(parts) - 1
	out := make([]byte, 0, n)
	for i, part := range parts {
		if i > 0 {
			out = append(out, '.')
		}
		out = append(out, part...)
	}
	return out
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
	JWKS            crypto.JWKS
	Issuer          string
	Audience        string
	TenantID        string
	TenantClaim     string
	RequiredClaims  map[string]string
	PrincipalPrefix string
	Now             func() time.Time
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
	v, err := authenticateJWT(credential, jwtMethodOptions{
		name:            o.Name(),
		jwks:            o.JWKS,
		issuer:          o.Issuer,
		audience:        o.Audience,
		tenantID:        o.TenantID,
		tenantClaim:     o.TenantClaim,
		requiredClaims:  o.RequiredClaims,
		principalPrefix: o.PrincipalPrefix,
		now:             o.Now,
		leeway:          o.Leeway,
		replay:          o.Replay,
	})
	if err != nil {
		return "", nil, err
	}
	return v.principal, v.scopes, nil
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
