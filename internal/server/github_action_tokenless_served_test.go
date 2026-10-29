// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// A84: the GitHub Action issues on the OIDC attestation alone. A github_oidc
// trust source flagged self_authenticating (and pinned to allowed_owners) lets
// a workflow present its OIDC token as the bearer credential of
// POST /api/v1/workloads/attested-issuance, naming the tenant with
// X-Tenant-ID. The verified token is the principal (github:<repository>) with
// nothing but certs:issue on this one route; the same token must be the
// attestation payload, so the caller cannot vouch for a different workflow.
// No API token exists in the pipeline any more.

type tokenlessAttestedRequest struct {
	bearer  []byte
	tenant  string
	idemKey string
	payload []byte
	path    string
}

func servedTokenlessAttestedIssue(t *testing.T, h *servedHarness, in tokenlessAttestedRequest, publicKeyPEM string) (int, []byte) {
	t.Helper()
	path := in.path
	if path == "" {
		path = "/api/v1/workloads/attested-issuance"
	}
	payload := in.payload
	if payload == nil {
		payload = in.bearer
	}
	body, _ := json.Marshal(map[string]any{
		"method": "github_oidc", "payload_base64": base64.StdEncoding.EncodeToString(payload),
		"public_key_pem": publicKeyPEM, "ttl_seconds": 600,
	})
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+string(in.bearer))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", in.idemKey)
	if in.tenant != "" {
		req.Header.Set("X-Tenant-ID", in.tenant)
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func servedSelfAuthenticatingGitHubSource(t *testing.T, h *servedHarness, admin, name string, jwk crypto.JWK, body map[string]any) (int, []byte) {
	t.Helper()
	req := map[string]any{
		"name": name, "method": "github_oidc", "issuer": githuboidc.DefaultIssuer, "audience": "trstctl",
		"jwks": map[string]any{"keys": []any{jwk}},
	}
	for k, v := range body {
		req[k] = v
	}
	return secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", admin, "a84-create-"+name, req)
}

func TestServedGitHubActionIssuesOnTheAttestationAloneA84(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "gha-a84")
	if err != nil {
		t.Fatal(err)
	}
	// No process attestor: the tenant's own trust source is the only GitHub
	// trust, exactly as an operator sets it up through the API or console.
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "ci.example.org", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a84-admin@example.test", "certs:issue", "certs:read", "audit:read")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)
	upstream := githubWorkflowToken(t, signer, "gha-a84", "acme")

	// A self-authenticating source without an owner pin would let every
	// repository on GitHub mint under this tenant: refused at creation.
	if status, body := servedSelfAuthenticatingGitHubSource(t, h, admin, "a84-unpinned", jwk, map[string]any{"self_authenticating": true}); status != http.StatusBadRequest || !strings.Contains(string(body), "allowed_owners") {
		t.Fatalf("unpinned self-authenticating source = %d %s, want 400 naming allowed_owners", status, body)
	}
	// Only GitHub OIDC tokens can stand in for an API token.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", admin, "a84-create-k8s", map[string]any{
		"name": "a84-k8s", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc", "audience": "trstctl",
		"jwks": map[string]any{"keys": []any{jwk}}, "self_authenticating": true, "allowed_owners": []string{"acme"},
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "github_oidc") {
		t.Fatalf("self-authenticating k8s_sat source = %d %s, want 400 naming github_oidc", status, body)
	}

	// An ordinary (unflagged) github_oidc source: the OIDC token attests, but it
	// does not authenticate. Tokenless issuance stays 401.
	if status, body := servedSelfAuthenticatingGitHubSource(t, h, admin, "a84-plain", jwk, map[string]any{"allowed_owners": []string{"acme"}}); status != http.StatusCreated {
		t.Fatalf("create plain source: %d %s", status, body)
	}
	if status, body := servedTokenlessAttestedIssue(t, h, tokenlessAttestedRequest{bearer: upstream, tenant: h.tenant, idemKey: "a84-plain-run"}, publicKeyPEM); status != http.StatusUnauthorized {
		t.Fatalf("tokenless issuance against an unflagged source = %d %s, want 401", status, body)
	}

	status, body := servedSelfAuthenticatingGitHubSource(t, h, admin, "a84-self", jwk, map[string]any{"self_authenticating": true, "allowed_owners": []string{"ACME"}})
	if status != http.StatusCreated {
		t.Fatalf("create self-authenticating source: %d %s", status, body)
	}
	var created struct {
		SelfAuthenticating bool     `json:"self_authenticating"`
		AllowedOwners      []string `json:"allowed_owners"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if !created.SelfAuthenticating || len(created.AllowedOwners) != 1 || created.AllowedOwners[0] != "acme" {
		t.Fatalf("created source = %+v, want self_authenticating with the owner pin normalised to lower case", created)
	}

	// The tenant must be named: the token carries no trstctl tenant.
	if status, body := servedTokenlessAttestedIssue(t, h, tokenlessAttestedRequest{bearer: upstream, idemKey: "a84-no-tenant"}, publicKeyPEM); status != http.StatusUnauthorized {
		t.Fatalf("tokenless issuance without X-Tenant-ID = %d %s, want 401", status, body)
	}
	// A fork's token: valid signature, wrong owner. It is not a principal here.
	if status, body := servedTokenlessAttestedIssue(t, h, tokenlessAttestedRequest{bearer: githubWorkflowToken(t, signer, "gha-a84", "attacker"), tenant: h.tenant, idemKey: "a84-fork"}, publicKeyPEM); status != http.StatusUnauthorized {
		t.Fatalf("fork token as bearer = %d %s, want 401", status, body)
	}
	// The bearer must be the attestation payload: a workflow cannot authenticate
	// as itself and have a certificate minted for another token.
	other := githubWorkflowToken(t, signer, "gha-a84", "acme")
	if status, body := servedTokenlessAttestedIssue(t, h, tokenlessAttestedRequest{bearer: upstream, tenant: h.tenant, idemKey: "a84-mismatch", payload: other}, publicKeyPEM); status != http.StatusForbidden || !strings.Contains(string(body), "same") {
		t.Fatalf("bearer/payload mismatch = %d %s, want 403 saying the proof must be the same token", status, body)
	}
	// The token opens exactly one door. Any other route sees no principal.
	for _, path := range []string{"/api/v1/workloads/attester-trust-sources", "/api/v1/certificates"} {
		req, err := http.NewRequest(http.MethodGet, h.ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+string(upstream))
		req.Header.Set("X-Tenant-ID", h.tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET %s with the OIDC token as bearer = %d, want 401", path, resp.StatusCode)
		}
	}

	// The upstream workflow, tokenless: issued, bound to the verified claims,
	// attributed to the repository, and replayable under the same key.
	status, body = servedTokenlessAttestedIssue(t, h, tokenlessAttestedRequest{bearer: upstream, tenant: h.tenant, idemKey: "a84-run-1"}, publicKeyPEM)
	if status != http.StatusCreated {
		t.Fatalf("tokenless issuance = %d %s, want 201", status, body)
	}
	var issued servedAttestedIssueResponse
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Attestation.Method != "github_oidc" || !strings.Contains(issued.Subject, "acme/payments") || issued.CertificatePEM == "" {
		t.Fatalf("tokenless issuance result = %+v", issued)
	}
	if status, again := servedTokenlessAttestedIssue(t, h, tokenlessAttestedRequest{bearer: upstream, tenant: h.tenant, idemKey: "a84-run-1"}, publicKeyPEM); status != http.StatusCreated || !bytes.Equal(again, body) {
		t.Fatalf("replay = %d, same body %v; want the identical 201", status, bytes.Equal(again, body))
	}
	// The event log names the workflow, not an API token subject.
	status, body = secretsReqKey(t, h, http.MethodGet, "/api/v1/audit/events?limit=100", admin, "", nil)
	if status != http.StatusOK || !strings.Contains(string(body), "github:acme/payments") {
		t.Fatalf("audit log = %d %.400s, want the issuance attributed to github:acme/payments", status, body)
	}
	// Disabling the source closes the door again.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources/"+servedTrustSourceID(t, body, h, admin, "a84-self")+"/revoke", admin, "a84-revoke", map[string]any{"reason": "rotate off"}); status != http.StatusOK {
		t.Fatalf("revoke: %d %s", status, body)
	}
	if status, body := servedTokenlessAttestedIssue(t, h, tokenlessAttestedRequest{bearer: upstream, tenant: h.tenant, idemKey: "a84-run-2"}, publicKeyPEM); status != http.StatusUnauthorized {
		t.Fatalf("tokenless issuance after revocation = %d %s, want 401", status, body)
	}
}

func servedTrustSourceID(t *testing.T, _ []byte, h *servedHarness, admin, name string) string {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodGet, "/api/v1/workloads/attester-trust-sources", admin, "", nil)
	if status != http.StatusOK {
		t.Fatalf("list trust sources: %d %s", status, body)
	}
	var list struct {
		Items []servedWorkloadTrustSourceResponse `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	for _, item := range list.Items {
		if item.Name == name {
			return item.ID
		}
	}
	t.Fatalf("trust source %q not listed: %s", name, body)
	return ""
}

// The shipped Action, run without a token input: it sends the OIDC token as
// the bearer, names the tenant, and gets a certificate.
func TestShippedGitHubActionRunsWithoutAnAPITokenA84(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "gha-a84-action")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "ci.example.org", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a84-action-admin@example.test", "certs:issue", "certs:read")
	if status, body := servedSelfAuthenticatingGitHubSource(t, h, admin, "a84-action", jwk, map[string]any{"self_authenticating": true, "allowed_owners": []string{"acme"}}); status != http.StatusCreated {
		t.Fatalf("create self-authenticating source: %d %s", status, body)
	}
	jwt := githubWorkflowAttemptToken(t, signer, "gha-a84-action", "acme", "84001", "1")
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": string(jwt)})
	}))
	t.Cleanup(oidc.Close)
	script := shippedGitHubActionScriptAUD47(t)
	eventFile := filepath.Join(t.TempDir(), "push.json")
	if err := os.WriteFile(eventFile, []byte(`{"repository":{"full_name":"acme/payments"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	env := []string{
		"TRSTCTL_URL=" + h.ts.URL, "TRSTCTL_TOKEN=", "TRSTCTL_TENANT=" + h.tenant, "TRSTCTL_AUDIENCE=trstctl", "TRSTCTL_TTL_SECONDS=900",
		"ACTIONS_ID_TOKEN_REQUEST_URL=" + oidc.URL + "?request=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=github-oidc-request-token",
		"GITHUB_RUN_ID=84001", "GITHUB_RUN_ATTEMPT=1", "GITHUB_JOB=issue", "GITHUB_ACTION=ctlplne-trstctl", "GITHUB_EVENT_NAME=push",
		"GITHUB_EVENT_PATH=" + eventFile, "TRSTCTL_OUT_DIR=" + outDir, "GITHUB_OUTPUT=" + filepath.Join(t.TempDir(), "github-output"),
	}
	before := servedCertificateCountAUD47(t, h)
	if output, err := runShippedGitHubActionAUD47(t, script, env); err != nil {
		t.Fatalf("shipped Action without a token: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(outDir, "certificate.pem")); err != nil {
		t.Fatalf("Action certificate output: %v", err)
	}
	if after := servedCertificateCountAUD47(t, h); after != before+1 {
		t.Fatalf("certificate rows after the tokenless Action = %d, want %d", after, before+1)
	}
	// Neither input: the Action says what it needs instead of sending an
	// anonymous request.
	noTenant := append(append([]string{}, env...), "TRSTCTL_TENANT=", "TRSTCTL_OUT_DIR="+t.TempDir())
	if output, err := runShippedGitHubActionAUD47(t, script, noTenant); err == nil || !strings.Contains(output, "tenant") {
		t.Fatalf("Action with neither token nor tenant: err=%v\n%s", err, output)
	}
}
