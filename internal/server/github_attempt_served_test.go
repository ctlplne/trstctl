// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Q1 changes AUD-47 deliberately: the signed workflow attempt owns the mint.
// A caller-controlled idempotency key or a fresh runner cannot reserve it again.
func newGitHubAttemptHarness(t *testing.T) (*servedHarness, *crypto.LockedSigner) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "a232-attempt")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "ci.example.org", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
			Attestors: []attest.Attestor{&githuboidc.Attestor{
				JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Audience: "trstctl", AllowedOwners: map[string]bool{"acme": true},
			}},
		}
	})
	return h, signer
}

func TestGitHubSignedAttemptOwnsCertificateAcrossCallerKeys(t *testing.T) {
	h, signer := newGitHubAttemptHarness(t)
	apiToken := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	proof := githubWorkflowAttemptToken(t, signer, "a232-attempt", "acme", "23201", "1")
	key := servedAttestedPublicKeyPEM(t)
	first := servedAttestedIssue(t, h, apiToken, "first-caller-key", "github_oidc", proof, key, http.StatusCreated)
	if first.Attestation.Claims["run_id"] != "23201" || first.Attestation.Claims["run_attempt"] != "1" {
		t.Error("certificate response dropped signed run/attempt metadata")
	}
	// Even a different API idempotency key must recover this exact leaf when the
	// signed attempt, public key and effective request are identical.
	retry := servedAttestedIssue(t, h, apiToken, "another-caller-key", "github_oidc", proof, key, http.StatusCreated)
	if retry.CertificatePEM != first.CertificatePEM || retry.CredentialID != first.CredentialID {
		t.Error("changing the caller key minted another leaf for the same signed attempt")
	}
	servedAttestedIssue(t, h, apiToken, "fresh-key-bypass", "github_oidc", proof, servedAttestedPublicKeyPEM(t), http.StatusConflict)
	second := servedAttestedIssue(t, h, apiToken, "new-attempt", "github_oidc",
		githubWorkflowAttemptToken(t, signer, "a232-attempt", "acme", "23201", "2"), servedAttestedPublicKeyPEM(t), http.StatusCreated)
	if second.CredentialID == first.CredentialID || second.Attestation.Claims["run_attempt"] != "2" {
		t.Fatal("new signed attempt did not receive its own certificate")
	}
	rows, err := h.store.ListCertificatesPage(t.Context(), h.tenant, "00000000-0000-0000-0000-000000000000", nil, 10, nil)
	if err != nil || len(rows) != 2 {
		t.Fatalf("attempt inventory rows=%d error=%v, want2", len(rows), err)
	}
	attempts := map[string]bool{}
	var originalKey, originalFingerprint string
	var originalVerifiedAt time.Time
	for _, row := range rows {
		recovery, err := h.store.GetIssuedCertificateRecovery(t.Context(), h.tenant, row.IssuanceIdempotencyKey)
		if err != nil {
			t.Fatal(err)
		}
		var retained struct {
			RunID      string    `json:"run_id"`
			RunAttempt string    `json:"run_attempt"`
			VerifiedAt time.Time `json:"verified_at"`
		}
		if err := json.Unmarshal(recovery.Response, &retained); err != nil {
			t.Fatalf("certificate has no immutable attempt response: %v", err)
		}
		if retained.RunID != "23201" || retained.VerifiedAt.IsZero() || row.IssuanceRequestBinding == "" {
			t.Fatal("retained attempt metadata is not bound to the exact certificate")
		}
		if row.Status != "active" || row.RevokedAt != nil {
			t.Fatal("a rerun revoked a still-valid earlier attempt certificate")
		}
		attempts[retained.RunAttempt] = true
		if retained.RunAttempt == "1" {
			originalKey, originalFingerprint, originalVerifiedAt = row.IssuanceIdempotencyKey, row.Fingerprint, retained.VerifiedAt
		}
	}
	if !attempts["1"] || !attempts["2"] {
		t.Fatal("exact certificate records did not retain both signed attempts")
	}
	// Exercise recovery after public template GC and deliberately corrupt a
	// read-model response. Only the retained source may supply attempt evidence.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `DELETE FROM idempotency_keys WHERE tenant_id=$1 AND key=$2`, h.tenant, "github-attempt-template:v1:"+originalKey); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE certificates SET issuance_response=$3 WHERE tenant_id=$1 AND fingerprint=$2`, h.tenant, originalFingerprint, []byte(`{"run_id":"23201","run_attempt":"9999"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	public, err := crypto.ParsePublicKeyPEM([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	request := api.AttestedSVIDRequest{Method: "github_oidc", Payload: proof, PublicKeyDER: public.DER, TTLSeconds: 600}
	for _, phase := range []string{"after template GC and SQL response tamper", "after complete read-model rebuild"} {
		if phase == "after complete read-model rebuild" {
			if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
				t.Fatal(err)
			}
		}
		recovered, err := h.srv.attestedIssuance.IssueAttestedSVID(t.Context(), h.tenant, phase, request)
		if err != nil || recovered.CertificatePEM != first.CertificatePEM || recovered.CredentialID != first.CredentialID ||
			recovered.Attestation.Claims["run_attempt"] != "1" || !recovered.Attestation.VerifiedAt.Equal(originalVerifiedAt) {
			t.Fatalf("%s failed exact source-backed recovery: %v", phase, err)
		}
	}
	changed, err := crypto.ParsePublicKeyPEM([]byte(servedAttestedPublicKeyPEM(t)))
	if err != nil {
		t.Fatal(err)
	}
	request.PublicKeyDER = changed.DER
	if _, err := h.srv.attestedIssuance.IssueAttestedSVID(t.Context(), h.tenant, "changed after rebuild", request); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("new key after rebuild was not refused: %v", err)
	}
}

func TestGitHubConcurrentIssuersCannotReserveAnotherAttemptSlot(t *testing.T) {
	h, signer := newGitHubAttemptHarness(t)
	proof := githubWorkflowAttemptToken(t, signer, "a232-attempt", "acme", "23202", "1")
	// Separate recorder instances exercise the PostgreSQL claim, rather than a
	// single recorder's in-process flight map. Both use the real signer journal.
	peer := *h.srv.attestedIssuance
	peer.idem = orchestrator.NewIdempotency(h.store)
	services := []*attestedIssuerService{h.srv.attestedIssuance, &peer}
	requests := make([]api.AttestedSVIDRequest, 2)
	for i := range requests {
		public, err := crypto.ParsePublicKeyPEM([]byte(servedAttestedPublicKeyPEM(t)))
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = api.AttestedSVIDRequest{Method: "github_oidc", Payload: proof, PublicKeyDER: public.DER, TTLSeconds: 600}
	}
	type outcome struct {
		issued api.AttestedSVID
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	for i := range requests {
		go func() {
			<-start
			issued, err := services[i].IssueAttestedSVID(t.Context(), h.tenant, "competing caller", requests[i])
			outcomes <- outcome{issued: issued, err: err}
		}()
	}
	close(start)
	issued, refused := 0, 0
	for range requests {
		result := <-outcomes
		switch {
		case result.err == nil && result.issued.CredentialID != "":
			issued++
		case errors.Is(result.err, orchestrator.ErrIdempotencyConflict):
			refused++
		default:
			t.Errorf("unexpected concurrent outcome: %v", result.err)
		}
	}
	if issued != 1 || refused != 1 || servedCertificateCountAUD47(t, h) != 1 {
		t.Fatalf("concurrent mint outcomes issued=%d refused=%d, want one each and one certificate", issued, refused)
	}
	firstTenant := h.tenant
	h.tenant = uuid.NewString()
	registerServedTenant(t, h, "Independent GitHub attempt tenant")
	other, err := peer.IssueAttestedSVID(t.Context(), strings.ToUpper(h.tenant), "competing caller", requests[0])
	if err != nil || other.CredentialID == "" {
		t.Fatalf("another tenant could not use its own attempt slot: %v", err)
	}
	aliasRetry, err := peer.IssueAttestedSVID(t.Context(), h.tenant, "equivalent tenant spelling", requests[0])
	if err != nil || aliasRetry.CredentialID != other.CredentialID || aliasRetry.CertificatePEM != other.CertificatePEM {
		t.Fatalf("equivalent tenant UUID did not recover its exact attempt: %v", err)
	}
	for _, tenantID := range []string{firstTenant, h.tenant} {
		rows, err := h.store.ListCertificatesPage(t.Context(), tenantID, "00000000-0000-0000-0000-000000000000", nil, 10, nil)
		if err != nil || len(rows) != 1 || rows[0].TenantID != tenantID {
			t.Fatalf("tenant-scoped attempt inventory rows=%d error=%v", len(rows), err)
		}
	}
}
