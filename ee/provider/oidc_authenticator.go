// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// OIDC federation for provider operators (epic L1).
//
// The provider plane's callers are the PROVIDER's staff, and the provider
// already runs an IdP. This authenticator verifies that IdP's bearer tokens
// offline — signature against a pinned JWKS, issuer, audience, expiry — and
// maps VERIFIED claims onto the Operator the service authorizes. Role and MFA
// come from claims the IdP asserted, never from anything the request said
// about itself: the previous defect here was exactly a handler that parsed a
// self-describing token for shape and believed it.

// OIDCAuthenticatorConfig pins what a provider-operator token must prove.
type OIDCAuthenticatorConfig struct {
	Issuer   string
	Audience string
	// JWKS is the IdP's key set, parsed. Pinned offline — this plane must not
	// fetch keys from a URL an attacker who minted the token also controls.
	JWKS crypto.JWKS
	// RoleClaim names the claim carrying role values (e.g. "roles" or
	// "groups"). AdminValues / OperatorValues map its entries onto the two
	// provider roles; a token matching NEITHER is not an operator at all and
	// is refused outright — federation is not enrollment.
	RoleClaim      string
	AdminValues    []string
	OperatorValues []string
	// MFAClaim names the claim proving multi-factor (default "amr");
	// MFAValues are the entries that count (default mfa/otp/hwk/swk). MFA is
	// carried on the Operator, and the service separately refuses mutations
	// without it — an authenticated-but-single-factor operator gets a 403
	// naming the gap, not a 401 that reads as a broken credential.
	MFAClaim  string
	MFAValues []string
	// Now overrides the clock (tests).
	Now func() time.Time
}

// OIDCAuthenticator implements OperatorAuthenticator against a pinned IdP.
type OIDCAuthenticator struct {
	cfg    OIDCAuthenticatorConfig
	admin  map[string]bool
	member map[string]bool
	mfa    map[string]bool
}

// NewOIDCAuthenticator builds the authenticator. It returns nil when the
// pinning is incomplete — and a nil authenticator REFUSES every request,
// which is the provider plane's standing rule: closed until wired.
func NewOIDCAuthenticator(cfg OIDCAuthenticatorConfig) *OIDCAuthenticator {
	if strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Audience) == "" || len(cfg.JWKS.Keys) == 0 {
		return nil
	}
	if strings.TrimSpace(cfg.RoleClaim) == "" {
		cfg.RoleClaim = "roles"
	}
	if strings.TrimSpace(cfg.MFAClaim) == "" {
		cfg.MFAClaim = "amr"
	}
	if len(cfg.MFAValues) == 0 {
		cfg.MFAValues = []string{"mfa", "otp", "hwk", "swk"}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	toSet := func(values []string) map[string]bool {
		out := map[string]bool{}
		for _, v := range values {
			if trimmed := strings.TrimSpace(v); trimmed != "" {
				out[trimmed] = true
			}
		}
		return out
	}
	return &OIDCAuthenticator{
		cfg:    cfg,
		admin:  toSet(cfg.AdminValues),
		member: toSet(cfg.OperatorValues),
		mfa:    toSet(cfg.MFAValues),
	}
}

// AuthenticateOperator verifies the bearer token and maps claims to an
// Operator. ok=false for anything not positively verified: a malformed token,
// a bad signature, the wrong issuer or audience, an expired token, or a token
// whose role claim matches no configured role. Parsing is not verification.
func (a *OIDCAuthenticator) AuthenticateOperator(r *http.Request) (Operator, bool) {
	if a == nil || r == nil {
		return Operator{}, false
	}
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(raw, prefix) {
		return Operator{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(raw, prefix))
	claimsJSON, err := crypto.VerifyJWT(token, a.cfg.JWKS)
	if err != nil {
		return Operator{}, false
	}
	var claims struct {
		Iss   string          `json:"iss"`
		Aud   json.RawMessage `json:"aud"`
		Exp   int64           `json:"exp"`
		Nbf   int64           `json:"nbf"`
		Sub   string          `json:"sub"`
		Email string          `json:"email"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return Operator{}, false
	}
	now := a.cfg.Now().UTC()
	if claims.Iss != a.cfg.Issuer {
		return Operator{}, false
	}
	if !audienceContains(claims.Aud, a.cfg.Audience) {
		return Operator{}, false
	}
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0)) {
		// A token with no expiry is a permanent credential minted by accident;
		// refusing it is kinder than honouring it forever.
		return Operator{}, false
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0)) {
		return Operator{}, false
	}
	if strings.TrimSpace(claims.Sub) == "" {
		return Operator{}, false
	}

	roleValues := stringSliceClaim(claimsJSON, a.cfg.RoleClaim)
	role := OperatorRole("")
	for _, v := range roleValues {
		if a.admin[v] {
			role = OperatorAdmin
			break
		}
		if a.member[v] {
			role = OperatorOperator
		}
	}
	if role == "" {
		// Authenticated by the IdP, but not a provider operator: the IdP
		// vouches for the whole workforce, and federation must not turn every
		// employee into someone who can suspend customers.
		return Operator{}, false
	}
	mfa := false
	for _, v := range stringSliceClaim(claimsJSON, a.cfg.MFAClaim) {
		if a.mfa[v] {
			mfa = true
			break
		}
	}
	return Operator{ID: claims.Sub, Email: strings.TrimSpace(claims.Email), Role: role, MFA: mfa}, true
}

// audienceContains handles both aud shapes: a string and an array.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// stringSliceClaim reads a claim that may be a string or an array of strings.
func stringSliceClaim(claimsJSON []byte, name string) []string {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(claimsJSON, &all); err != nil {
		return nil
	}
	raw, ok := all[name]
	if !ok {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{strings.TrimSpace(single)}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		out := make([]string, 0, len(many))
		for _, v := range many {
			out = append(out, strings.TrimSpace(v))
		}
		return out
	}
	return nil
}
