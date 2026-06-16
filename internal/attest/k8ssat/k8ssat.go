// Package k8ssat is the Kubernetes projected ServiceAccount-token attester
// (S11.7, F30). A pod presents a projected SAT (a JWT bound to a specific
// audience and short TTL); this attester verifies it against the cluster's JWKS,
// checks the issuer, audience, and expiry, and establishes the
// namespace/serviceaccount as a verified subject. A forged, expired, or
// wrong-audience token is rejected (fail-closed).
package k8ssat

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// audience accepts a JWT "aud" claim encoded as either a string or an array.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = audience{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return err
	}
	*a = ss
	return nil
}

func (a audience) contains(x string) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}

// Attestor verifies Kubernetes projected ServiceAccount tokens.
type Attestor struct {
	// JWKS holds the cluster's token-signing public keys (the API server / OIDC issuer).
	JWKS crypto.JWKS
	// Issuer, if set, must equal the token's iss (the cluster issuer URL).
	Issuer string
	// Audience, if set, must be present in the token's aud.
	Audience string
	// AllowedNamespaces, if non-empty, restricts attestation to these namespaces.
	AllowedNamespaces map[string]bool
	// Now overrides the clock for expiry checks (tests).
	Now func() time.Time
}

// Method implements attest.Attestor.
func (a *Attestor) Method() string { return "k8s_sat" }

type k8sClaims struct {
	Iss string   `json:"iss"`
	Aud audience `json:"aud"`
	Exp int64    `json:"exp"`
	Sub string   `json:"sub"`
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

// Attest verifies the projected SAT and returns the attestation.
func (a *Attestor) Attest(_ context.Context, payload []byte) (attest.Attestation, error) {
	raw, err := crypto.VerifyJWT(string(payload), a.JWKS)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("k8s_sat: %w", err)
	}
	var c k8sClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return attest.Attestation{}, fmt.Errorf("k8s_sat: parse claims: %w", err)
	}
	if a.Issuer != "" && c.Iss != a.Issuer {
		return attest.Attestation{}, fmt.Errorf("k8s_sat: unexpected issuer %q", c.Iss)
	}
	if a.Audience != "" && !c.Aud.contains(a.Audience) {
		return attest.Attestation{}, fmt.Errorf("k8s_sat: audience %q not present", a.Audience)
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if c.Exp != 0 && now().Unix() >= c.Exp {
		return attest.Attestation{}, fmt.Errorf("k8s_sat: token expired")
	}
	ns := c.K8s.Namespace
	sa := c.K8s.ServiceAccount.Name
	if ns == "" || sa == "" {
		return attest.Attestation{}, fmt.Errorf("k8s_sat: token missing namespace/serviceaccount")
	}
	if len(a.AllowedNamespaces) > 0 && !a.AllowedNamespaces[ns] {
		return attest.Attestation{}, fmt.Errorf("k8s_sat: namespace %s is not allowed", ns)
	}
	return attest.Attestation{
		Subject: "ns/" + ns + "/sa/" + sa,
		Selectors: []string{
			"k8s:namespace:" + ns,
			"k8s:sa:" + sa,
			"k8s:pod:" + c.K8s.Pod.Name,
		},
		Claims: map[string]string{
			"namespace": ns,
			"sa":        sa,
			"pod":       c.K8s.Pod.Name,
		},
	}, nil
}
