// SPDX-License-Identifier: BUSL-1.1

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
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
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
	Sub               string `json:"sub"`
	Repository        string `json:"repository"`
	RepositoryOwner   string `json:"repository_owner"`
	Workflow          string `json:"workflow"`
	Ref               string `json:"ref"`
	SHA               string `json:"sha"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
	RunnerEnvironment string `json:"runner_environment"`
	RunID             string `json:"run_id"`
	RunAttempt        string `json:"run_attempt"`
}

// ownerAllowed matches the pin the way GitHub treats owner names: without
// regard to case, so a pin typed as "ACME" admits the token GitHub signs for
// "acme" and never silently refuses the operator's own repositories.
func (a *Attestor) ownerAllowed(owner string) bool {
	if a.AllowedOwners[owner] {
		return true
	}
	lower := strings.ToLower(owner)
	for allowed := range a.AllowedOwners {
		if strings.ToLower(allowed) == lower {
			return true
		}
	}
	return false
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
	raw, err := crypto.VerifyJWTBytes(payload, a.JWKS)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("github_oidc: %w", err)
	}
	defer secret.Wipe(raw)
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
	if err := attest.ValidateJWTTimeWindow(raw, now()); err != nil {
		return attest.Attestation{}, fmt.Errorf("github_oidc: %w", err)
	}
	if !validRunID(c.RunID) || !validRunID(c.RunAttempt) {
		return attest.Attestation{}, fmt.Errorf("github_oidc: signed run_id and run_attempt must be canonical positive decimal strings")
	}
	if c.Repository == "" {
		return attest.Attestation{}, fmt.Errorf("github_oidc: token missing repository")
	}
	if len(a.AllowedOwners) > 0 && !a.ownerAllowed(c.RepositoryOwner) {
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
			"run_id":        c.RunID,
			"run_attempt":   c.RunAttempt,
			"owner":         c.RepositoryOwner,
			"workflow":      c.Workflow,
			"ref":           c.Ref,
			"sha":           c.SHA,
			"fulcio_san":    san,
			"fulcio_issuer": c.Iss,
		},
	}, nil
}

// validRunID uses one representation for the signed scope. Leading zeroes,
// signs, whitespace, floats and oversized values must not create aliases.
func validRunID(value string) bool {
	if len(value) == 0 || len(value) > 20 || value[0] == '0' {
		return false
	}
	for _, digit := range []byte(value) {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}
