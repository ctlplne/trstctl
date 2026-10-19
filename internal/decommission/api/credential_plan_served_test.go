// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/reprotect"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

func TestReprotectionOperatorRegistersOnlyCurrentCertificateHostAndSuccessor(t *testing.T) {
	ctx := context.Background()
	st := openStoreOn(t, "vdec_api_credential_plan_served")
	oldSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer oldSigner.Destroy()
	oldDER, err := crypto.SelfSignedCACert(oldSigner, "QA predecessor", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldInfo, err := certinfo.Inspect(oldDER)
	if err != nil {
		t.Fatal(err)
	}
	old, err := st.InsertCAAuthority(ctx, corestore.CAAuthority{TenantID: tenantA, Kind: "root", CommonName: "QA predecessor", Status: "superseded", CertificatePEM: string(crypto.EncodeCertificatePEM(oldDER)), SignerHandle: "qa-old-handle", Serial: oldInfo.SerialNumber})
	if err != nil {
		t.Fatal(err)
	}
	successorSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer successorSigner.Destroy()
	successorDER, err := crypto.SelfSignedCACert(successorSigner, "QA successor", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	successorInfo, err := certinfo.Inspect(successorDER)
	if err != nil {
		t.Fatal(err)
	}
	successor, err := st.InsertCAAuthority(ctx, corestore.CAAuthority{TenantID: tenantA, Kind: "root", CommonName: "QA successor", Status: "active", CertificatePEM: string(crypto.EncodeCertificatePEM(successorDER)), SignerHandle: "qa-successor-handle", ReplacesID: &old.ID, Serial: successorInfo.SerialNumber})
	if err != nil {
		t.Fatal(err)
	}
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "ca-reprotect.qa.invalid", DNSNames: []string{"ca-reprotect.qa.invalid"}}, subject)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(oldDER, oldSigner, csr, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := crypto.EncodeCertificatePEM(leafDER)
	info, err := certinfo.Inspect(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := st.UpsertCertificate(ctx, corestore.Certificate{TenantID: tenantA, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, CertificateDER: leafDER, CertificatePEM: leafPEM, KeyOrigin: "host_agent", KeyStorage: "file", Status: "active", IssuanceIdempotencyKey: "issue:transition:ca-reprotect-identity"})
	if err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	if err := st.UpsertAgent(ctx, corestore.Agent{ID: agentID, TenantID: tenantA, Name: "qa-host", Status: "online", Roles: []string{"host"}}); err != nil {
		t.Fatal(err)
	}
	targetID := uuid.NewString()
	if err := st.UpsertDeploymentTarget(ctx, corestore.DeploymentTarget{ID: targetID, TenantID: tenantA, Name: "QA Apache", Type: "apache", Enabled: true, EnabledSet: true, Config: json.RawMessage(`{"executor":"agent","required_agent_role":"host","required_agent_id":"` + agentID + `","cert_path":"/lab/tls/qa.crt","key_path":"/lab/tls/qa.key","verify_address":"127.0.0.1:10443","verify_server_name":"ca-reprotect.qa.invalid"}`)}); err != nil {
		t.Fatal(err)
	}
	target, err := st.GetDeploymentTarget(ctx, tenantA, targetID)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := uuid.NewString()
	if err := st.UpsertOwner(ctx, corestore.Owner{ID: ownerID, TenantID: tenantA, Kind: corestore.OwnerService, Name: "qa-reprotect-owner"}); err != nil {
		t.Fatal(err)
	}
	identityID := uuid.NewString()
	identityAttrs, _ := json.Marshal(map[string]string{"deployment_target_id": targetID, "issuing_authority_source": "private", "issuing_authority_id": old.ID})
	if err := st.UpsertIdentity(ctx, corestore.Identity{ID: identityID, TenantID: tenantA, Kind: corestore.KindX509Certificate, Name: "ca-reprotect.qa.invalid", OwnerID: ownerID, Status: "deployed", Attributes: identityAttrs}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.AppendIdentityTransitionTx(ctx, tx, tenantA, corestore.IdentityTransition{IdentityID: identityID, Seq: 1, FromState: "requested", ToState: "issued", EventType: "identity.issued", IdempotencyKey: "ca-reprotect-identity", OccurredAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	if err := decstore.New(st).RebuildTenant(ctx, tenantA, []eventspec.Event{mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: old.ID, Dependent: dep(depstate.DependentCredential, cert.ID)}, 1)}); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	outbox := orchestrator.NewOutbox(st)
	served := newServedAPI(t, st, outbox, log)
	contract := httptest.NewRecorder()
	served.ServeHTTP(contract, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if contract.Code != http.StatusOK {
		t.Fatalf("served OpenAPI = %d", contract.Code)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			ReadOnly    bool   `json:"x-trstctl-read-only"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(contract.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	previewOp := spec.Paths["/api/v1/ca/keys/{id}/reprotect/plans/preview"]["post"]
	readOp := spec.Paths["/api/v1/ca/keys/{id}/reprotect/plans/{job_id}"]["get"]
	if previewOp.OperationID != "previewCAKeyReprotectionPlan" || !previewOp.ReadOnly || readOp.OperationID != "getCAKeyReprotectionPlan" {
		t.Fatalf("review/readback OpenAPI contracts missing: preview=%+v read=%+v", previewOp, readOp)
	}
	targetRead := httptest.NewRecorder()
	served.ServeHTTP(targetRead, httptest.NewRequest(http.MethodGet, "/api/v1/connectors/targets/"+targetID, nil))
	if targetRead.Code != http.StatusOK {
		t.Fatalf("operator target readback = %d %s", targetRead.Code, targetRead.Body.String())
	}
	var reviewedTarget struct {
		RevisionID string `json:"revision_id"`
	}
	if err := json.Unmarshal(targetRead.Body.Bytes(), &reviewedTarget); err != nil || reviewedTarget.RevisionID != target.RevisionID {
		t.Fatalf("operator cannot obtain target revision for reviewed CA plan: %+v err=%v", reviewedTarget, err)
	}
	post := func(idem, revision, fingerprint, successorID string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"certificate_id": cert.ID, "successor_authority_id": successorID, "target_id": targetID, "expected_target_revision": revision, "expected_fingerprint": fingerprint, "ttl_seconds": 600})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/"+old.ID+"/reprotect/plans", strings.NewReader(string(body)))
		req.Header.Set("Idempotency-Key", idem)
		rr := httptest.NewRecorder()
		served.ServeHTTP(rr, req)
		return rr
	}
	previewBody, _ := json.Marshal(map[string]any{"certificate_id": cert.ID, "successor_authority_id": successor.ID, "target_id": targetID, "expected_target_revision": target.RevisionID, "expected_fingerprint": info.SHA256Fingerprint, "ttl_seconds": 600})
	previewRequest := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/"+old.ID+"/reprotect/plans/preview", strings.NewReader(string(previewBody)))
	preview := httptest.NewRecorder()
	served.ServeHTTP(preview, previewRequest)
	if preview.Code != http.StatusOK {
		t.Fatalf("effect-free reviewed plan preview = %d %s, want 200", preview.Code, preview.Body.String())
	}
	var previewReceipt struct {
		JobID      string `json:"job_id"`
		IdentityID string `json:"identity_id"`
		Ready      bool   `json:"ready"`
		EffectFree bool   `json:"effect_free"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &previewReceipt); err != nil || !previewReceipt.Ready || !previewReceipt.EffectFree || previewReceipt.JobID == "" || previewReceipt.IdentityID != identityID {
		t.Fatalf("preview lost exact derived plan binding: %+v err=%v", previewReceipt, err)
	}
	if _, found, err := reprotect.NewCredentialPlanLedger(log, st).Load(ctx, tenantA, previewReceipt.JobID); err != nil || found {
		t.Fatalf("preview wrote an immutable plan: found=%t err=%v", found, err)
	}
	stalePreview := httptest.NewRecorder()
	staleBody, _ := json.Marshal(map[string]any{"certificate_id": cert.ID, "successor_authority_id": successor.ID, "target_id": targetID, "expected_target_revision": "stale", "expected_fingerprint": info.SHA256Fingerprint, "ttl_seconds": 600})
	served.ServeHTTP(stalePreview, httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/"+old.ID+"/reprotect/plans/preview", strings.NewReader(string(staleBody))))
	if stalePreview.Code != http.StatusConflict {
		t.Fatalf("stale preview = %d %s, want 409", stalePreview.Code, stalePreview.Body.String())
	}
	if rr := post("stale-revision", "stale", info.SHA256Fingerprint, successor.ID); rr.Code != http.StatusConflict {
		t.Fatalf("stale target revision = %d %s, want 409 before plan append", rr.Code, rr.Body.String())
	}
	if rr := post("wrong-cert", target.RevisionID, strings.Repeat("0", 64), successor.ID); rr.Code != http.StatusConflict {
		t.Fatalf("wrong predecessor = %d %s, want 409 before plan append", rr.Code, rr.Body.String())
	}
	first := post("reviewed-plan", target.RevisionID, info.SHA256Fingerprint, successor.ID)
	if first.Code != http.StatusCreated {
		t.Fatalf("reviewed plan = %d %s, want 201", first.Code, first.Body.String())
	}
	var result struct {
		JobID                 string `json:"job_id"`
		IdentityID            string `json:"identity_id"`
		Recorded              bool   `json:"recorded"`
		PredecessorSPKISHA256 string `json:"predecessor_spki_sha256"`
		RequiredAgentID       string `json:"required_agent_id"`
		TargetRevisionID      string `json:"target_revision_id"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &result); err != nil || !result.Recorded || result.JobID == "" || result.IdentityID != identityID || result.PredecessorSPKISHA256 != info.SPKISHA256 || result.RequiredAgentID != agentID || result.TargetRevisionID != target.RevisionID {
		t.Fatalf("reviewed plan lost derived binding: %+v err=%v", result, err)
	}
	if result.JobID != previewReceipt.JobID {
		t.Fatalf("registered job %s differs from reviewed job %s", result.JobID, previewReceipt.JobID)
	}
	readback := httptest.NewRecorder()
	served.ServeHTTP(readback, httptest.NewRequest(http.MethodGet, "/api/v1/ca/keys/"+old.ID+"/reprotect/plans/"+url.PathEscape(result.JobID), nil))
	if readback.Code != http.StatusOK || !strings.Contains(readback.Body.String(), `"recorded":true`) || !strings.Contains(readback.Body.String(), result.JobID) {
		t.Fatalf("durable plan readback = %d %s", readback.Code, readback.Body.String())
	}
	wrongCA := httptest.NewRecorder()
	served.ServeHTTP(wrongCA, httptest.NewRequest(http.MethodGet, "/api/v1/ca/keys/"+successor.ID+"/reprotect/plans/"+url.PathEscape(result.JobID), nil))
	if wrongCA.Code != http.StatusNotFound {
		t.Fatalf("plan readback crossed predecessor CA boundary: %d %s", wrongCA.Code, wrongCA.Body.String())
	}
	if again := post("reviewed-plan-retry", target.RevisionID, info.SHA256Fingerprint, successor.ID); again.Code != http.StatusOK {
		t.Fatalf("exact plan replay = %d %s, want 200", again.Code, again.Body.String())
	}
	if changed := post("changed-successor", target.RevisionID, info.SHA256Fingerprint, old.ID); changed.Code != http.StatusConflict {
		t.Fatalf("changed successor = %d %s, want 409", changed.Code, changed.Body.String())
	}
	plan, found, err := reprotect.NewCredentialPlanLedger(log, st).Load(ctx, tenantA, result.JobID)
	if err != nil || !found || plan.Job.Dependent.ID != cert.ID || plan.IdentityID != identityID || plan.SuccessorAuthorityID != successor.ID || plan.VerifyAddress != "127.0.0.1:10443" || plan.VerifyServerName != "ca-reprotect.qa.invalid" {
		t.Fatalf("immutable plan readback = %+v found=%t err=%v", plan, found, err)
	}
	otherIdentityID := uuid.NewString()
	if err := st.UpsertIdentity(ctx, corestore.Identity{ID: otherIdentityID, TenantID: tenantA, Kind: corestore.KindX509Certificate, Name: "qa-conflicting-identity", OwnerID: ownerID, Status: "deployed", Attributes: identityAttrs}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.AppendIdentityTransitionTx(ctx, tx, tenantA, corestore.IdentityTransition{IdentityID: otherIdentityID, Seq: 1, FromState: "requested", ToState: "issued", EventType: "identity.issued", IdempotencyKey: "ca-reprotect-identity", OccurredAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	if ambiguous := post("ambiguous-identity", target.RevisionID, info.SHA256Fingerprint, successor.ID); ambiguous.Code != http.StatusConflict {
		t.Fatalf("ambiguous certificate identity binding = %d %s, want 409 before new plan append", ambiguous.Code, ambiguous.Body.String())
	}
	start := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/"+old.ID+"/reprotect", nil)
	start.Header.Set("Idempotency-Key", "start-reviewed-plan")
	queued := httptest.NewRecorder()
	served.ServeHTTP(queued, start)
	if queued.Code != http.StatusAccepted {
		t.Fatalf("reviewed plan did not unlock outbox: %d %s", queued.Code, queued.Body.String())
	}
}
