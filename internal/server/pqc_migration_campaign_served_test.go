// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/store"
)

type blockingPQCCampaignSigner struct {
	delegate    *jose.SigningKey
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
	mu          sync.Mutex
	payload     []byte
}

func newBlockingPQCCampaignSigner(delegate *jose.SigningKey) *blockingPQCCampaignSigner {
	return &blockingPQCCampaignSigner{
		delegate: delegate,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (s *blockingPQCCampaignSigner) SignArtifact(kind string, payload []byte) (string, error) {
	s.mu.Lock()
	s.payload = append([]byte(nil), payload...)
	s.mu.Unlock()
	s.enteredOnce.Do(func() { close(s.entered) })
	<-s.release
	return s.delegate.SignArtifact(kind, payload)
}

func (s *blockingPQCCampaignSigner) PublicJWKS() ([]byte, error) {
	return s.delegate.PublicJWKS()
}

func (s *blockingPQCCampaignSigner) unblock() {
	s.releaseOnce.Do(func() { close(s.release) })
}

func (s *blockingPQCCampaignSigner) signedPayload() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.payload...)
}

type pqcCampaignHTTPResult struct {
	status int
	body   []byte
	err    error
}

func asyncPQCCampaignRequest(client *http.Client, baseURL, method, path, token, idem string, body any) <-chan pqcCampaignHTTPResult {
	result := make(chan pqcCampaignHTTPResult, 1)
	go func() {
		payload, err := json.Marshal(body)
		if err != nil {
			result <- pqcCampaignHTTPResult{err: err}
			return
		}
		req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(payload))
		if err != nil {
			result <- pqcCampaignHTTPResult{err: err}
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", idem)
		resp, err := client.Do(req)
		if err != nil {
			result <- pqcCampaignHTTPResult{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		responseBody, err := io.ReadAll(resp.Body)
		result <- pqcCampaignHTTPResult{status: resp.StatusCode, body: responseBody, err: err}
	}()
	return result
}

func TestPQCMigrationCampaignServedManualClosureSignedEvidence(t *testing.T) {
	signingKey, err := jose.GenerateRSASigningKey("pqc-campaign-closure")
	if err != nil {
		t.Fatalf("generate closure signing key: %v", err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditSigningKey = signingKey
	})
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "crypto-owner",
		"risk:read", "discovery:write")
	finding, err := h.store.UpsertCryptoAsset(context.Background(), store.CryptoAsset{
		TenantID: h.tenant, Kind: "certificate-key", Location: "payments.internal:443",
		Algorithm: "RSA", KeyBits: 2048, Strength: "strong",
		QuantumVulnerable: true, OutOfPolicy: true,
		Reasons: []string{"public-key algorithm is vulnerable to a cryptographically relevant quantum computer"},
	})
	if err != nil {
		t.Fatalf("seed CBOM finding: %v", err)
	}

	campaignID := "77777777-7777-4777-8777-777777777777"
	deadline := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	create := map[string]any{
		"id": campaignID, "name": "Payments cryptography migration campaign", "owner": "team:payments",
		"deadline": deadline, "wave": "wave-1",
		"readiness_criteria": []string{"owner approved", "rollback documented"},
		"finding_ids":        []string{finding.ID},
	}
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/pqc/campaigns", tok, "pqc-campaign-create", create)
	if status != http.StatusCreated {
		t.Fatalf("create campaign = %d body %s", status, body)
	}
	var created struct {
		ID                     string   `json:"id"`
		TenantID               string   `json:"tenant_id"`
		Owner                  string   `json:"owner"`
		Wave                   string   `json:"wave"`
		Status                 string   `json:"status"`
		ReadinessStatus        string   `json:"readiness_status"`
		AutomatedExecution     bool     `json:"automated_execution_available"`
		AutomatedExecutionNote string   `json:"automated_execution_note"`
		ReadinessCriteria      []string `json:"readiness_criteria"`
		Findings               []struct {
			FindingID     string `json:"finding_id"`
			FindingDigest string `json:"finding_digest"`
			Disposition   string `json:"disposition"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created campaign: %v", err)
	}
	if created.ID != campaignID || created.TenantID != h.tenant || created.Owner != "team:payments" ||
		created.Wave != "wave-1" || created.Status != "open" || created.ReadinessStatus != "pending" ||
		created.AutomatedExecution || created.AutomatedExecutionNote == "" ||
		len(created.ReadinessCriteria) != 2 || len(created.Findings) != 1 ||
		created.Findings[0].FindingID != finding.ID || created.Findings[0].FindingDigest == "" ||
		created.Findings[0].Disposition != "pending" {
		t.Fatalf("created campaign is not a useful standalone core workflow: %+v", created)
	}

	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/pqc/campaigns", tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("list campaigns = %d body %s", status, body)
	}
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/pqc/campaigns/"+campaignID, tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("get campaign = %d body %s", status, body)
	}

	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/pqc/campaigns/"+campaignID+"/readiness", tok,
		"pqc-campaign-readiness", map[string]any{
			"status": "passed", "evidence_refs": []string{"change:CAB-2048", "runbook:crypto-agility-payments-v3"},
		})
	if status != http.StatusOK {
		t.Fatalf("pass readiness = %d body %s", status, body)
	}

	evidenceDigest := "sha256:3cba1d17d83065bce8a540abfbe4c59ab8b3f4ea3f2f47fc5f99dba9246c1f9a"
	status, body = doBearer(t, h.ts, http.MethodPost,
		"/api/v1/pqc/campaigns/"+campaignID+"/findings/"+finding.ID+"/disposition", tok,
		"pqc-campaign-manual-remediation", map[string]any{
			"disposition": "remediated", "method": "manual",
			"reason":           "operator replaced the certificate through the existing CA workflow",
			"evidence_refs":    []string{"audit:certificate.issued:replacement"},
			"evidence_digests": []string{evidenceDigest},
		})
	if status != http.StatusOK {
		t.Fatalf("record manual remediation = %d body %s", status, body)
	}

	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/pqc/campaigns/"+campaignID+"/close", tok,
		"pqc-campaign-close", map[string]any{"closed_by": "crypto-owner"})
	if status != http.StatusOK {
		t.Fatalf("close campaign = %d body %s", status, body)
	}
	var closed struct {
		Status          string `json:"status"`
		RemediatedCount int    `json:"remediated_count"`
		Closure         struct {
			Format        string          `json:"format"`
			SignedClosure string          `json:"signed_closure"`
			PublicJWKS    json.RawMessage `json:"public_jwks"`
		} `json:"closure"`
	}
	if err := json.Unmarshal(body, &closed); err != nil {
		t.Fatalf("decode closed campaign: %v", err)
	}
	if closed.Status != "closed" || closed.RemediatedCount != 1 ||
		closed.Closure.Format != "trstctl.pqc-migration-campaign-closure.v1" ||
		closed.Closure.SignedClosure == "" || len(closed.Closure.PublicJWKS) == 0 {
		t.Fatalf("closed campaign lacks signed closure: %+v", closed)
	}

	keys, err := jose.ParseJWKSet(closed.Closure.PublicJWKS)
	if err != nil {
		t.Fatalf("parse offline verifier: %v", err)
	}
	payload, err := keys.VerifyArtifact(closed.Closure.SignedClosure, jose.ArtifactPQCCampaignClosure)
	if err != nil {
		t.Fatalf("verify closure offline: %v", err)
	}
	var proof struct {
		Format     string `json:"format"`
		CampaignID string `json:"campaign_id"`
		TenantID   string `json:"tenant_id"`
		Findings   []struct {
			FindingID      string   `json:"finding_id"`
			FindingDigest  string   `json:"finding_digest"`
			Disposition    string   `json:"disposition"`
			EvidenceDigest []string `json:"evidence_digests"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(payload, &proof); err != nil {
		t.Fatalf("decode signed closure: %v", err)
	}
	if proof.Format != closed.Closure.Format || proof.CampaignID != campaignID ||
		proof.TenantID != h.tenant || len(proof.Findings) != 1 ||
		proof.Findings[0].FindingID != finding.ID ||
		proof.Findings[0].FindingDigest == "" ||
		proof.Findings[0].Disposition != "remediated" ||
		len(proof.Findings[0].EvidenceDigest) != 1 ||
		proof.Findings[0].EvidenceDigest[0] != evidenceDigest {
		t.Fatalf("signed closure does not bind campaign findings and evidence: %+v", proof)
	}

	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/pqc/campaigns/"+campaignID+"/evidence", tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("export closure evidence = %d body %s", status, body)
	}
}

func TestPQCMigrationCampaignTenantIsolation(t *testing.T) {
	signingKey, err := jose.GenerateRSASigningKey("pqc-campaign-closure")
	if err != nil {
		t.Fatalf("generate closure signing key: %v", err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditSigningKey = signingKey
	})
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "tenant-a-owner",
		"risk:read", "discovery:write")
	tenantB := "22222222-2222-2222-2222-222222222222"
	foreign, err := h.store.UpsertCryptoAsset(context.Background(), store.CryptoAsset{
		TenantID: tenantB, Kind: "certificate-key", Location: "foreign.internal:443",
		Algorithm: "RSA", KeyBits: 2048, Strength: "strong", QuantumVulnerable: true,
	})
	if err != nil {
		t.Fatalf("seed foreign CBOM finding: %v", err)
	}

	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/pqc/campaigns", tok,
		"pqc-campaign-cross-tenant", map[string]any{
			"name": "must fail", "owner": "tenant-a-owner",
			"deadline": time.Now().UTC().Add(24 * time.Hour), "wave": "wave-1",
			"readiness_criteria": []string{"owner approved"},
			"finding_ids":        []string{foreign.ID},
		})
	if status != http.StatusBadRequest && status != http.StatusNotFound {
		t.Fatalf("cross-tenant campaign = %d body %s, want fail-closed 400/404", status, body)
	}
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/pqc/campaigns", tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("list tenant A campaigns = %d body %s", status, body)
	}
	var list struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode tenant A list: %v", err)
	}
	for _, campaign := range list.Items {
		if campaign.Name == "must fail" {
			t.Fatalf("tenant A can see a campaign created from tenant B finding: %s", body)
		}
	}
}

func TestPQCMigrationCampaignConcurrentCloseSerializesSignedEvidence(t *testing.T) {
	signingKey, err := jose.GenerateRSASigningKey("campaign-concurrency")
	if err != nil {
		t.Fatalf("generate closure signing key: %v", err)
	}
	blockingSigner := newBlockingPQCCampaignSigner(signingKey)
	defer blockingSigner.unblock()
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditSigningKey = signingKey
		// APIOptions are applied after the normal server defaults, so this test
		// signer can pause the exact sign-under-lock point.
		d.APIOptions = append(d.APIOptions, api.WithPQCCampaignClosureSigner(blockingSigner))
	})
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "crypto-owner",
		"risk:read", "discovery:write")
	finding, err := h.store.UpsertCryptoAsset(context.Background(), store.CryptoAsset{
		TenantID: h.tenant, Kind: "certificate-key", Location: "race.internal:443",
		Algorithm: "RSA", KeyBits: 2048, Strength: "strong",
		QuantumVulnerable: true, OutOfPolicy: true,
	})
	if err != nil {
		t.Fatalf("seed CBOM finding: %v", err)
	}

	campaignID := "88888888-8888-4888-8888-888888888888"
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/pqc/campaigns", tok,
		"campaign-race-create", map[string]any{
			"id": campaignID, "name": "Closure serialization proof", "owner": "team:crypto",
			"deadline": time.Now().UTC().Add(24 * time.Hour), "wave": "wave-1",
			"readiness_criteria": []string{"owner approved"}, "finding_ids": []string{finding.ID},
		})
	if status != http.StatusCreated {
		t.Fatalf("create campaign = %d body %s", status, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/pqc/campaigns/"+campaignID+"/readiness", tok,
		"campaign-race-ready", map[string]any{
			"status": "passed", "evidence_refs": []string{"change:CAB-race-proof"},
		})
	if status != http.StatusOK {
		t.Fatalf("pass readiness = %d body %s", status, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost,
		"/api/v1/pqc/campaigns/"+campaignID+"/findings/"+finding.ID+"/disposition", tok,
		"campaign-race-disposition", map[string]any{
			"disposition": "remediated", "method": "manual",
			"reason":           "operator completed the replacement",
			"evidence_refs":    []string{"audit:race-proof"},
			"evidence_digests": []string{"sha256:3cba1d17d83065bce8a540abfbe4c59ab8b3f4ea3f2f47fc5f99dba9246c1f9a"},
		})
	if status != http.StatusOK {
		t.Fatalf("record disposition = %d body %s", status, body)
	}

	closeResult := asyncPQCCampaignRequest(h.ts.Client(), h.ts.URL, http.MethodPost,
		"/api/v1/pqc/campaigns/"+campaignID+"/close", tok, "campaign-race-close",
		map[string]any{"closed_by": "crypto-owner"})
	select {
	case <-blockingSigner.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("closure signer was not reached")
	}

	updateResult := asyncPQCCampaignRequest(h.ts.Client(), h.ts.URL, http.MethodPost,
		"/api/v1/pqc/campaigns/"+campaignID+"/readiness", tok, "campaign-race-late-update",
		map[string]any{"status": "blocked", "evidence_refs": []string{"change:too-late"}})
	select {
	case result := <-updateResult:
		t.Fatalf("concurrent campaign update escaped the close transaction lock: status=%d err=%v body=%s", result.status, result.err, result.body)
	case <-time.After(150 * time.Millisecond):
		// Expected: close owns the per-tenant campaign lock while the exact
		// payload is being signed, so the update cannot append ahead of it.
	}

	blockingSigner.unblock()
	closed := <-closeResult
	if closed.err != nil || closed.status != http.StatusOK {
		t.Fatalf("close campaign = %d err=%v body=%s", closed.status, closed.err, closed.body)
	}
	updated := <-updateResult
	if updated.err != nil || updated.status != http.StatusConflict {
		t.Fatalf("late update = %d err=%v body=%s, want conflict after close", updated.status, updated.err, updated.body)
	}

	var proof struct {
		CampaignID      string `json:"campaign_id"`
		Owner           string `json:"owner"`
		ReadinessStatus string `json:"readiness_status"`
		Findings        []struct {
			Disposition string `json:"disposition"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(blockingSigner.signedPayload(), &proof); err != nil {
		t.Fatalf("decode payload observed by signer: %v", err)
	}
	if proof.CampaignID != campaignID || proof.Owner != "team:crypto" ||
		proof.ReadinessStatus != "passed" || len(proof.Findings) != 1 ||
		proof.Findings[0].Disposition != "remediated" {
		t.Fatalf("signed payload did not preserve the locked close state: %+v", proof)
	}

	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/pqc/campaigns/"+campaignID, tok, "", nil)
	if status != http.StatusOK {
		t.Fatalf("get closed campaign = %d body %s", status, body)
	}
	var final struct {
		Status          string `json:"status"`
		ReadinessStatus string `json:"readiness_status"`
	}
	if err := json.Unmarshal(body, &final); err != nil {
		t.Fatalf("decode final campaign: %v", err)
	}
	if final.Status != "closed" || final.ReadinessStatus != "passed" {
		t.Fatalf("late update changed the state after signed close: %+v", final)
	}
}
