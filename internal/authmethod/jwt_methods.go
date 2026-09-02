// SPDX-License-Identifier: MPL-2.0

package authmethod

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// JWTMethod authenticates a generic signed JWT against an operator-supplied JWKS.
// It is the generic non-human login method for platforms that can mint a workload
// JWT but do not need provider-specific claim rules. Signature verification stays
// behind internal/crypto (AN-3); the optional tenant claim binds the credential to
// the tenant whose login route is being used (AN-1).
type JWTMethod struct {
	NameValue       string
	JWKS            crypto.JWKS
	Issuer          string
	Audience        string
	TenantID        string
	TenantClaim     string
	SubjectClaim    string
	Scopes          []string
	ScopesClaim     string
	RequiredClaims  map[string]string
	PrincipalPrefix string
	Now             func() time.Time
	Leeway          time.Duration
	Replay          *JTICache
}

// Name implements Method.
func (j JWTMethod) Name() string {
	if j.NameValue != "" {
		return j.NameValue
	}
	return "jwt"
}

// WithReplayGuard returns a copy of j with a bounded jti replay cache attached.
func (j JWTMethod) WithReplayGuard(maxEntries int) JWTMethod {
	j.Replay = NewJTICache(maxEntries)
	return j
}

// Authenticate implements Method.
func (j JWTMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	v, err := authenticateJWT(credential, jwtMethodOptions{
		name:            j.Name(),
		jwks:            j.JWKS,
		issuer:          j.Issuer,
		audience:        j.Audience,
		tenantID:        j.TenantID,
		tenantClaim:     j.TenantClaim,
		subjectClaim:    j.SubjectClaim,
		scopes:          j.Scopes,
		scopesClaim:     j.ScopesClaim,
		requiredClaims:  j.RequiredClaims,
		principalPrefix: j.PrincipalPrefix,
		now:             j.Now,
		leeway:          j.Leeway,
		replay:          j.Replay,
	})
	if err != nil {
		return "", nil, err
	}
	defer v.destroy()
	return v.principal, v.scopes, nil
}

// KubernetesSATMethod authenticates a Kubernetes projected ServiceAccount token.
// It verifies the JWT exactly like generic OIDC, then enforces the Kubernetes
// namespace/service-account claims a real API server signs into projected SATs.
type KubernetesSATMethod struct {
	JWKS                   crypto.JWKS
	Issuer                 string
	Audience               string
	TenantID               string
	TenantClaim            string
	AllowedNamespaces      map[string]bool
	AllowedServiceAccounts map[string]bool // "namespace/name"
	Scopes                 []string
	Now                    func() time.Time
	Leeway                 time.Duration
	Replay                 *JTICache
}

// Name implements Method.
func (KubernetesSATMethod) Name() string { return "kubernetes" }

// Authenticate implements Method.
func (k KubernetesSATMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	v, err := authenticateJWT(credential, jwtMethodOptions{
		name:        k.Name(),
		jwks:        k.JWKS,
		issuer:      k.Issuer,
		audience:    k.Audience,
		tenantID:    k.TenantID,
		tenantClaim: k.TenantClaim,
		scopes:      k.Scopes,
		now:         k.Now,
		leeway:      k.Leeway,
		replay:      k.Replay,
	})
	if err != nil {
		return "", nil, err
	}
	defer v.destroy()
	var c struct {
		K8s struct {
			Namespace      string `json:"namespace"`
			ServiceAccount struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"serviceaccount"`
			Pod struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"pod"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(v.raw, &c); err != nil {
		return "", nil, fmt.Errorf("kubernetes: parse claims: %w", err)
	}
	ns := c.K8s.Namespace
	sa := c.K8s.ServiceAccount.Name
	if ns == "" || sa == "" {
		return "", nil, fmt.Errorf("kubernetes: token missing namespace/serviceaccount")
	}
	if len(k.AllowedNamespaces) > 0 && !k.AllowedNamespaces[ns] {
		return "", nil, fmt.Errorf("kubernetes: namespace %s is not allowed", ns)
	}
	saKey := ns + "/" + sa
	if len(k.AllowedServiceAccounts) > 0 && !k.AllowedServiceAccounts[saKey] {
		return "", nil, fmt.Errorf("kubernetes: serviceaccount %s is not allowed", saKey)
	}
	wantSub := "system:serviceaccount:" + ns + ":" + sa
	if v.principal != wantSub {
		return "", nil, fmt.Errorf("kubernetes: subject does not match namespace/serviceaccount")
	}
	return v.principal, v.scopes, nil
}

// GCPMethod authenticates a Google-signed workload identity JWT, including GCE
// metadata identity tokens. It verifies Google-style nested compute_engine claims
// and optionally restricts the projects this tenant accepts.
type GCPMethod struct {
	JWKS            crypto.JWKS
	Issuer          string
	Audience        string
	TenantID        string
	TenantClaim     string
	AllowedProjects map[string]bool
	Scopes          []string
	Now             func() time.Time
	Leeway          time.Duration
	Replay          *JTICache
}

// Name implements Method.
func (GCPMethod) Name() string { return "gcp" }

// Authenticate implements Method.
func (g GCPMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	v, err := authenticateJWT(credential, jwtMethodOptions{
		name:        g.Name(),
		jwks:        g.JWKS,
		issuer:      g.Issuer,
		audience:    g.Audience,
		tenantID:    g.TenantID,
		tenantClaim: g.TenantClaim,
		scopes:      g.Scopes,
		now:         g.Now,
		leeway:      g.Leeway,
		replay:      g.Replay,
	})
	if err != nil {
		return "", nil, err
	}
	defer v.destroy()
	var c struct {
		Google struct {
			ComputeEngine struct {
				InstanceID   string `json:"instance_id"`
				ProjectID    string `json:"project_id"`
				Zone         string `json:"zone"`
				InstanceName string `json:"instance_name"`
			} `json:"compute_engine"`
		} `json:"google"`
	}
	if err := json.Unmarshal(v.raw, &c); err != nil {
		return "", nil, fmt.Errorf("gcp: parse claims: %w", err)
	}
	ce := c.Google.ComputeEngine
	if ce.InstanceID == "" || ce.ProjectID == "" {
		return "", nil, fmt.Errorf("gcp: token missing compute_engine instance/project")
	}
	if len(g.AllowedProjects) > 0 && !g.AllowedProjects[ce.ProjectID] {
		return "", nil, fmt.Errorf("gcp: project %s is not allowed", ce.ProjectID)
	}
	return "gcp:" + ce.ProjectID + "/" + ce.InstanceID, v.scopes, nil
}

// AzureMethod authenticates an Azure workload JWT, such as a managed-identity or
// federated credential token. It checks the issuer/audience/signature, optional
// trstctl tenant claim, and optional Azure tenant allow-list.
type AzureMethod struct {
	JWKS                crypto.JWKS
	Issuer              string
	Audience            string
	TenantID            string
	TenantClaim         string
	AllowedAzureTenants map[string]bool
	PrincipalClaim      string
	Scopes              []string
	Now                 func() time.Time
	Leeway              time.Duration
	Replay              *JTICache
}

// Name implements Method.
func (AzureMethod) Name() string { return "azure" }

// Authenticate implements Method.
func (a AzureMethod) Authenticate(_ context.Context, credential []byte) (string, []string, error) {
	subjectClaim := a.PrincipalClaim
	if subjectClaim == "" {
		subjectClaim = "oid"
	}
	v, err := authenticateJWT(credential, jwtMethodOptions{
		name:         a.Name(),
		jwks:         a.JWKS,
		issuer:       a.Issuer,
		audience:     a.Audience,
		tenantID:     a.TenantID,
		tenantClaim:  a.TenantClaim,
		subjectClaim: subjectClaim,
		scopes:       a.Scopes,
		now:          a.Now,
		leeway:       a.Leeway,
		replay:       a.Replay,
	})
	if err != nil {
		return "", nil, err
	}
	defer v.destroy()
	tid, ok, err := v.claims.string("tid")
	if err != nil {
		return "", nil, fmt.Errorf("azure: parse tid claim: %w", err)
	}
	if len(a.AllowedAzureTenants) > 0 {
		if !ok || !a.AllowedAzureTenants[tid] {
			return "", nil, fmt.Errorf("azure: tenant is not allowed")
		}
	}
	return "azure:" + v.principal, v.scopes, nil
}

type jwtMethodOptions struct {
	name            string
	jwks            crypto.JWKS
	issuer          string
	audience        string
	tenantID        string
	tenantClaim     string
	subjectClaim    string
	scopes          []string
	scopesClaim     string
	requiredClaims  map[string]string
	principalPrefix string
	now             func() time.Time
	leeway          time.Duration
	replay          *JTICache
}

type verifiedJWT struct {
	raw       []byte
	claims    jwtClaimSet
	principal string
	scopes    []string
}

func (v *verifiedJWT) destroy() {
	if v == nil {
		return
	}
	secret.Wipe(v.raw)
	for name, raw := range v.claims {
		secret.Wipe(raw)
		delete(v.claims, name)
	}
	v.raw = nil
	v.claims = nil
}

type registeredJWTClaims struct {
	Iss string   `json:"iss"`
	Aud audience `json:"aud"`
	Sub string   `json:"sub"`
	Exp int64    `json:"exp"`
	Nbf int64    `json:"nbf"`
	Iat int64    `json:"iat"`
	JTI string   `json:"jti"`
}

type jwtClaimSet map[string]json.RawMessage

func authenticateJWT(credential []byte, opts jwtMethodOptions) (verifiedJWT, error) {
	methodName := firstNonEmpty(opts.name, "jwt")
	raw, err := crypto.VerifyJWTBytes(credential, opts.jwks)
	if err != nil {
		return verifiedJWT{}, fmt.Errorf("%s: %w", methodName, err)
	}
	retainRaw := false
	var claims jwtClaimSet
	defer func() {
		if retainRaw {
			return
		}
		secret.Wipe(raw)
		for name, claim := range claims {
			secret.Wipe(claim)
			delete(claims, name)
		}
	}()
	var reg registeredJWTClaims
	if err := json.Unmarshal(raw, &reg); err != nil {
		return verifiedJWT{}, fmt.Errorf("%s: parse claims: %w", methodName, err)
	}
	if opts.issuer != "" && reg.Iss != opts.issuer {
		return verifiedJWT{}, fmt.Errorf("%s: unexpected issuer", methodName)
	}
	if opts.audience != "" && !reg.Aud.contains(opts.audience) {
		return verifiedJWT{}, fmt.Errorf("%s: unexpected audience", methodName)
	}
	now := time.Now
	if opts.now != nil {
		now = opts.now
	}
	leeway := opts.leeway
	if leeway <= 0 {
		leeway = defaultLeeway
	}
	nowT := now()
	if reg.Exp == 0 {
		return verifiedJWT{}, fmt.Errorf("%s: token has no exp claim", methodName)
	}
	if !nowT.Before(time.Unix(reg.Exp, 0)) {
		return verifiedJWT{}, fmt.Errorf("%s: token expired", methodName)
	}
	if reg.Nbf != 0 && nowT.Add(leeway).Before(time.Unix(reg.Nbf, 0)) {
		return verifiedJWT{}, fmt.Errorf("%s: token not yet valid (nbf)", methodName)
	}
	if reg.Iat != 0 && nowT.Add(leeway).Before(time.Unix(reg.Iat, 0)) {
		return verifiedJWT{}, fmt.Errorf("%s: token issued in the future (iat)", methodName)
	}
	if opts.replay != nil {
		if reg.JTI == "" {
			return verifiedJWT{}, fmt.Errorf("%s: token has no jti (replay defence requires one)", methodName)
		}
		if !opts.replay.Add(reg.JTI, time.Unix(reg.Exp, 0), nowT) {
			return verifiedJWT{}, fmt.Errorf("%s: token replayed (jti already seen)", methodName)
		}
	}

	if err := json.Unmarshal(raw, &claims); err != nil {
		return verifiedJWT{}, fmt.Errorf("%s: parse claim map: %w", methodName, err)
	}
	for claim, want := range opts.requiredClaims {
		got, ok, err := claims.string(claim)
		if err != nil {
			return verifiedJWT{}, fmt.Errorf("%s: parse %s claim: %w", methodName, claim, err)
		}
		if !ok || got != want {
			return verifiedJWT{}, fmt.Errorf("%s: required claim %s mismatch", methodName, claim)
		}
	}
	if opts.tenantClaim != "" {
		got, ok, err := claims.string(opts.tenantClaim)
		if err != nil {
			return verifiedJWT{}, fmt.Errorf("%s: parse tenant claim: %w", methodName, err)
		}
		if !ok || opts.tenantID == "" || got != opts.tenantID {
			return verifiedJWT{}, fmt.Errorf("%s: tenant claim mismatch", methodName)
		}
	}
	subjectClaim := firstNonEmpty(opts.subjectClaim, "sub")
	principal := reg.Sub
	if subjectClaim != "sub" {
		var ok bool
		principal, ok, err = claims.string(subjectClaim)
		if err != nil {
			return verifiedJWT{}, fmt.Errorf("%s: parse subject claim: %w", methodName, err)
		}
		if !ok {
			principal = ""
		}
	}
	if principal == "" {
		return verifiedJWT{}, fmt.Errorf("%s: token has no subject", methodName)
	}
	if opts.principalPrefix != "" {
		principal = opts.principalPrefix + principal
	}
	scopes := append([]string(nil), opts.scopes...)
	// A JWT claim is identity-provider data, not permission authority unless the
	// operator explicitly names that claim as the method's scope source. This
	// prevents a workload-controlled `scope`/`scopes` claim from widening a
	// statically configured least-privilege grant.
	if opts.scopesClaim != "" {
		fromToken, ok, claimErr := claims.strings(opts.scopesClaim)
		if claimErr != nil {
			return verifiedJWT{}, fmt.Errorf("%s: parse scopes claim: %w", methodName, claimErr)
		}
		if !ok || len(fromToken) == 0 {
			return verifiedJWT{}, fmt.Errorf("%s: token has no non-empty %s scopes claim", methodName, opts.scopesClaim)
		}
		scopes = fromToken
	}
	retainRaw = true
	return verifiedJWT{raw: raw, claims: claims, principal: principal, scopes: scopes}, nil
}

func (c jwtClaimSet) string(name string) (string, bool, error) {
	raw, ok := c[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, err
	}
	return s, true, nil
}

func (c jwtClaimSet) strings(name string) ([]string, bool, error) {
	raw, ok := c[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, true, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(s) == "" {
		return nil, true, nil
	}
	return strings.Fields(s), true, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
