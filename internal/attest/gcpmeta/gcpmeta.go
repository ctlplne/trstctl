// Package gcpmeta is the GCP instance-identity attester (S11.5, F30). A GCE
// instance fetches a Google-signed identity JWT (RS256) from the metadata server;
// this attester verifies that token against Google's JWKS, checks the issuer,
// audience, and expiry, and establishes the instance as a verified subject. A
// forged, expired, or wrong-audience token is rejected (fail-closed).
package gcpmeta

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// Attestor verifies GCP instance identity tokens (JWT / RS256 or ES256).
type Attestor struct {
	// JWKS holds Google's token-signing public keys.
	JWKS crypto.JWKS
	// Issuer, if set, must equal the token's iss (e.g. "https://accounts.google.com").
	Issuer string
	// Audience, if set, must equal the token's aud.
	Audience string
	// AllowedProjects, if non-empty, restricts attestation to these GCP projects.
	AllowedProjects map[string]bool
	// Now overrides the clock for expiry checks (tests).
	Now func() time.Time
}

// Method implements attest.Attestor.
func (a *Attestor) Method() string { return "gcp_iit" }

type gcpClaims struct {
	Iss    string `json:"iss"`
	Aud    string `json:"aud"`
	Exp    int64  `json:"exp"`
	Sub    string `json:"sub"`
	Google struct {
		ComputeEngine struct {
			InstanceID   string `json:"instance_id"`
			ProjectID    string `json:"project_id"`
			Zone         string `json:"zone"`
			InstanceName string `json:"instance_name"`
		} `json:"compute_engine"`
	} `json:"google"`
}

// Attest verifies the Google-signed identity token and returns the attestation.
func (a *Attestor) Attest(_ context.Context, payload []byte) (attest.Attestation, error) {
	raw, err := crypto.VerifyJWT(string(payload), a.JWKS)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("gcp_iit: %w", err)
	}
	var c gcpClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return attest.Attestation{}, fmt.Errorf("gcp_iit: parse claims: %w", err)
	}
	if a.Issuer != "" && c.Iss != a.Issuer {
		return attest.Attestation{}, fmt.Errorf("gcp_iit: unexpected issuer %q", c.Iss)
	}
	if a.Audience != "" && c.Aud != a.Audience {
		return attest.Attestation{}, fmt.Errorf("gcp_iit: unexpected audience %q", c.Aud)
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if c.Exp != 0 && now().Unix() >= c.Exp {
		return attest.Attestation{}, fmt.Errorf("gcp_iit: token expired")
	}
	ce := c.Google.ComputeEngine
	if ce.InstanceID == "" || ce.ProjectID == "" {
		return attest.Attestation{}, fmt.Errorf("gcp_iit: token missing compute_engine instance/project")
	}
	if len(a.AllowedProjects) > 0 && !a.AllowedProjects[ce.ProjectID] {
		return attest.Attestation{}, fmt.Errorf("gcp_iit: project %s is not allowed", ce.ProjectID)
	}
	return attest.Attestation{
		Subject: ce.InstanceID,
		Selectors: []string{
			"gcp:project:" + ce.ProjectID,
			"gcp:zone:" + ce.Zone,
			"gcp:instance-id:" + ce.InstanceID,
			"gcp:instance-name:" + ce.InstanceName,
		},
		Claims: map[string]string{
			"project_id":    ce.ProjectID,
			"zone":          ce.Zone,
			"instance_id":   ce.InstanceID,
			"instance_name": ce.InstanceName,
		},
	}, nil
}
