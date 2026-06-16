// Package githuboidc is the GitHub Actions OIDC attester (S11.8, F30), including
// the Sigstore Fulcio identity mapping. A GitHub Actions workflow presents an
// OIDC token signed by token.actions.githubusercontent.com; this attester
// verifies it against GitHub's JWKS, checks the issuer/audience/expiry, and
// establishes the repository+workflow as a verified subject. It also exposes the
// FulcioBinding — the SAN and issuer that Sigstore Fulcio would certify into a
// short-lived code-signing certificate for this identity. A forged or
// untrusted-repo token is rejected (fail-closed).
package githuboidc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// DefaultIssuer is GitHub Actions' OIDC issuer.
const DefaultIssuer = "https://token.actions.githubusercontent.com"

// Attestor verifies GitHub Actions OIDC tokens.
type Attestor struct {
	// JWKS holds GitHub's OIDC signing keys.
	JWKS crypto.JWKS
	// Issuer overrides the expected iss (defaults to DefaultIssuer).
	Issuer string
	// Audience, if set, must equal the token's aud.
	Audience string
	// AllowedOwners, if non-empty, restricts attestation to these repository owners.
	AllowedOwners map[string]bool
	// Now overrides the clock for expiry checks (tests).
	Now func() time.Time
}

// Method implements attest.Attestor.
func (a *Attestor) Method() string { return "github_oidc" }

type ghClaims struct {
	Iss               string `json:"iss"`
	Aud               string `json:"aud"`
	Exp               int64  `json:"exp"`
	Sub               string `json:"sub"`
	Repository        string `json:"repository"`
	RepositoryOwner   string `json:"repository_owner"`
	Workflow          string `json:"workflow"`
	Ref               string `json:"ref"`
	SHA               string `json:"sha"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
	RunnerEnvironment string `json:"runner_environment"`
}

// FulcioBinding is the identity Sigstore Fulcio would bind into a short-lived
// code-signing certificate for an OIDC identity: the SAN URI and the issuer
// extension.
type FulcioBinding struct {
	SAN    string
	Issuer string
}

// FulcioBindingFrom recovers the Fulcio binding recorded on an attestation.
func FulcioBindingFrom(att attest.Attestation) FulcioBinding {
	return FulcioBinding{SAN: att.Claims["fulcio_san"], Issuer: att.Claims["fulcio_issuer"]}
}

// Attest verifies the OIDC token and returns the attestation (with the Fulcio
// binding recorded in Claims).
func (a *Attestor) Attest(_ context.Context, payload []byte) (attest.Attestation, error) {
	raw, err := crypto.VerifyJWT(string(payload), a.JWKS)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("github_oidc: %w", err)
	}
	var c ghClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return attest.Attestation{}, fmt.Errorf("github_oidc: parse claims: %w", err)
	}
	wantIss := a.Issuer
	if wantIss == "" {
		wantIss = DefaultIssuer
	}
	if c.Iss != wantIss {
		return attest.Attestation{}, fmt.Errorf("github_oidc: unexpected issuer %q", c.Iss)
	}
	if a.Audience != "" && c.Aud != a.Audience {
		return attest.Attestation{}, fmt.Errorf("github_oidc: unexpected audience %q", c.Aud)
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if c.Exp != 0 && now().Unix() >= c.Exp {
		return attest.Attestation{}, fmt.Errorf("github_oidc: token expired")
	}
	if c.Repository == "" {
		return attest.Attestation{}, fmt.Errorf("github_oidc: token missing repository")
	}
	if len(a.AllowedOwners) > 0 && !a.AllowedOwners[c.RepositoryOwner] {
		return attest.Attestation{}, fmt.Errorf("github_oidc: owner %s is not allowed", c.RepositoryOwner)
	}
	// Fulcio binds the SAN to the workflow identity (job_workflow_ref, falling back
	// to the OIDC subject) and records the issuer in an extension.
	san := c.JobWorkflowRef
	if san == "" {
		san = c.Sub
	}
	return attest.Attestation{
		Subject: c.Sub,
		Selectors: []string{
			"github:repository:" + c.Repository,
			"github:owner:" + c.RepositoryOwner,
			"github:workflow:" + c.Workflow,
			"github:ref:" + c.Ref,
			"github:runner-env:" + c.RunnerEnvironment,
		},
		Claims: map[string]string{
			"repository":    c.Repository,
			"owner":         c.RepositoryOwner,
			"workflow":      c.Workflow,
			"ref":           c.Ref,
			"sha":           c.SHA,
			"fulcio_san":    san,
			"fulcio_issuer": c.Iss,
		},
	}, nil
}
