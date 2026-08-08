// SPDX-License-Identifier: MPL-2.0

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// The GitHub Action's flow, proven against the served binary (I3): the exact
// request shape clients/github-action/action.yml sends — method github_oidc,
// payload_base64 carrying the workflow's OIDC JWT, public_key_pem, ttl — is
// what this test sends, and the certificate that comes back is bound to the
// VERIFIED token claims, not to anything the workflow asserted about itself.
//
// The action is YAML this suite cannot execute; what it proves is that a
// workflow doing exactly what the action does gets a certificate, and that a
// FORK's token — right issuer, right audience, wrong repository owner — is
// refused. The contract guard in docs/ pins the action file to this route and
// these field names, so the two cannot drift apart silently.

func githubWorkflowToken(t *testing.T, signer *crypto.LockedSigner, kid, owner string) []byte {
	t.Helper()
	token, err := crypto.SignJWT(signer, kid, map[string]any{
		"iss": githuboidc.DefaultIssuer, "aud": "trstctl",
		"exp":        time.Now().Add(10 * time.Minute).Unix(),
		"sub":        "repo:" + owner + "/payments:ref:refs/heads/main",
		"repository": owner + "/payments", "repository_owner": owner,
		"workflow": "issue-deploy-cert", "ref": "refs/heads/main",
		"sha":              "0123456789abcdef0123456789abcdef01234567",
		"job_workflow_ref": owner + "/payments/.github/workflows/issue.yml@refs/heads/main",
	})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(token)
}

func TestServedGitHubActionFlowIssuesAndRefusesForeignOwners(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "gha-k1")
	if err != nil {
		t.Fatal(err)
	}

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "ci.example.org",
			DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
			Attestors: []attest.Attestor{
				// AllowedOwners pinned, as the action's README tells the
				// operator to do: an unpinned source attests every repository
				// on GitHub.
				&githuboidc.Attestor{
					JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Audience: "trstctl",
					AllowedOwners: map[string]bool{"acme": true},
				},
			},
		}
	})
	apiToken := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)

	// The upstream repository's workflow: issued, with the identity from the
	// VERIFIED claims.
	issued := servedAttestedIssue(t, h, apiToken, "gha-run-1", "github_oidc",
		githubWorkflowToken(t, signer, "gha-k1", "acme"), publicKeyPEM, http.StatusCreated)
	if issued.Attestation.Method != "github_oidc" {
		t.Fatalf("attestation method = %q", issued.Attestation.Method)
	}
	if !strings.Contains(issued.Subject, "acme/payments") {
		t.Fatalf("subject %q is not bound to the verified repository claim — the identity must come "+
			"from the token GitHub signed, not from anything the workflow typed", issued.Subject)
	}
	if issued.CertificatePEM == "" {
		t.Fatal("no certificate returned; the action's whole output is this PEM")
	}

	// A FORK's token: valid signature, right audience, wrong owner. Refused —
	// this is the property that makes the action safe to use in public repos:
	// AllowedOwners is the pin that stops any repository on GitHub minting
	// under this tenant's trust domain, and if it did not bite here the
	// README's advice would be a placebo.
	servedAttestedIssue(t, h, apiToken, "gha-run-fork", "github_oidc",
		githubWorkflowToken(t, signer, "gha-k1", "attacker"), publicKeyPEM, http.StatusForbidden)
}
