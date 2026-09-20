// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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

func TestShippedGitHubActionRunsAgainstServedDeploymentAUD47(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "gha-aud47")
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "ci.example.org", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
			Attestors: []attest.Attestor{&githuboidc.Attestor{
				JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Audience: "trstctl",
				AllowedOwners: map[string]bool{"acme": true},
			}},
		}
	})
	apiToken := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	jwt := githubWorkflowToken(t, signer, "gha-aud47", "acme")
	oidcReads := 0
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oidcReads++
		if r.Header.Get("Authorization") != "bearer github-oidc-request-token" || r.URL.Query().Get("audience") != "trstctl" {
			t.Errorf("OIDC request authorization=%q query=%v", r.Header.Get("Authorization"), r.URL.Query())
			http.Error(w, "bad OIDC request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": string(jwt)})
	}))
	t.Cleanup(oidc.Close)

	script := shippedGitHubActionScriptAUD47(t)
	eventFile := filepath.Join(t.TempDir(), "push.json")
	if err := os.WriteFile(eventFile, []byte(`{"repository":{"full_name":"acme/payments"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	baseEnv := []string{
		"TRSTCTL_URL=" + h.ts.URL, "TRSTCTL_TOKEN=" + apiToken, "TRSTCTL_AUDIENCE=trstctl", "TRSTCTL_TTL_SECONDS=900",
		"ACTIONS_ID_TOKEN_REQUEST_URL=" + oidc.URL + "?request=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=github-oidc-request-token",
		"GITHUB_RUN_ID=47001", "GITHUB_JOB=issue", "GITHUB_ACTION=ctlplne-trstctl", "GITHUB_EVENT_NAME=push",
		"GITHUB_EVENT_PATH=" + eventFile,
	}
	before := servedCertificateCountAUD47(t, h)
	firstDir := t.TempDir()
	firstOutput := filepath.Join(t.TempDir(), "github-output")
	firstEnv := append(append([]string{}, baseEnv...), "TRSTCTL_OUT_DIR="+firstDir, "GITHUB_OUTPUT="+firstOutput)
	if output, err := runShippedGitHubActionAUD47(t, script, firstEnv); err != nil {
		t.Fatalf("shipped Action against served deployment: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(firstDir, "certificate.pem")); err != nil {
		t.Fatalf("Action certificate output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(firstDir, "key.pem")); err != nil {
		t.Fatalf("Action private-key output: %v", err)
	}
	if after := servedCertificateCountAUD47(t, h); after != before+1 {
		t.Fatalf("certificate rows after Action = %d, want %d", after, before+1)
	}

	// GitHub changes GITHUB_RUN_ATTEMPT on a rerun, but the shipped key does not
	// include it. A fresh runner creates a different public key, so exact request
	// binding rejects the reused key with 409 instead of returning a certificate
	// that cannot match the new private key or minting a second certificate.
	secondDir := t.TempDir()
	secondOutput := filepath.Join(t.TempDir(), "github-output")
	secondEnv := append(append([]string{}, baseEnv...), "TRSTCTL_OUT_DIR="+secondDir, "GITHUB_OUTPUT="+secondOutput, "GITHUB_RUN_ATTEMPT=2")
	output, rerunErr := runShippedGitHubActionAUD47(t, script, secondEnv)
	if rerunErr == nil || !strings.Contains(output, "HTTP 409") {
		t.Fatalf("fresh-runner rerun did not fail closed on its new key: err=%v\n%s", rerunErr, output)
	}
	if after := servedCertificateCountAUD47(t, h); after != before+1 {
		t.Fatalf("rerun minted again: certificate rows=%d want=%d", after, before+1)
	}

	// The local guard is defense in depth before OIDC acquisition; the server's
	// allowed_owners verifier above remains the signed-token boundary.
	forkEvent := filepath.Join(t.TempDir(), "fork.json")
	if err := os.WriteFile(forkEvent, []byte(`{"pull_request":{"head":{"repo":{"fork":true}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	forkEnv := append(append([]string{}, baseEnv...),
		"TRSTCTL_OUT_DIR="+t.TempDir(), "GITHUB_OUTPUT="+filepath.Join(t.TempDir(), "github-output"),
		"GITHUB_EVENT_NAME=pull_request", "GITHUB_EVENT_PATH="+forkEvent)
	output, forkErr := runShippedGitHubActionAUD47(t, script, forkEnv)
	if forkErr == nil || !strings.Contains(output, ".head.repo.fork is true") {
		t.Fatalf("fork pull request was not refused before OIDC: err=%v\n%s", forkErr, output)
	}
	if oidcReads != 2 {
		t.Fatalf("OIDC endpoint read %d times, want only the issued run and its rerun", oidcReads)
	}
}

func shippedGitHubActionScriptAUD47(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../clients/github-action/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	const marker = "      run: |\n"
	parts := strings.SplitN(string(raw), marker, 2)
	if len(parts) != 2 {
		t.Fatal("action.yml has no composite run block")
	}
	lines := strings.Split(parts[1], "\n")
	for i, line := range lines {
		if line != "" && !strings.HasPrefix(line, "        ") {
			lines = lines[:i]
			break
		}
		lines[i] = strings.TrimPrefix(line, "        ")
	}
	return strings.Join(lines, "\n")
}

func runShippedGitHubActionAUD47(t *testing.T, script string, env []string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- the test deliberately executes a generated copy of the fixed shipped action script (CWE-78).
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func servedCertificateCountAUD47(t *testing.T, h *servedHarness) int {
	t.Helper()
	var count int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM certificates WHERE tenant_id = $1`, h.tenant).Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	return count
}
