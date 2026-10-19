// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
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
	eedecommission "trstctl.com/trstctl/internal/decommission"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/reprotect"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

func TestReprotectionOperatorRegistersOnlyCurrentCertificateHostAndSuccessor(t *testing.T) {
	ctx := context.Background()
	st := openStoreOn(t, "vdec_api_credential_plan_served")
	if err := st.UpsertTenant(ctx, corestore.Tenant{TenantID: tenantA, Name: "CA re-protection QA"}); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	outbox := orchestrator.NewOutbox(st)
	fixtureOrch := orchestrator.NewOrchestrator(log, st, outbox)
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
	cert, err := fixtureOrch.RecordCertificate(ctx, tenantA, corestore.Certificate{TenantID: tenantA, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, CertificateDER: leafDER, CertificatePEM: leafPEM, KeyOrigin: "host_agent", KeyStorage: "file", Status: "active", IssuanceIdempotencyKey: "issue:transition:ca-reprotect-identity"})
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
	// Another leaf can be released while this active leaf's reviewed plan waits
	// for its host. The unrelated release advances the dependency ledger but
	// must not invalidate the unchanged certificate, successor, or host route.
	releasedOther := dep(depstate.DependentCredential, "qa-unserved-revoked-leaf")
	if err := decstore.New(st).RebuildTenant(ctx, tenantA, []eventspec.Event{
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: old.ID, Dependent: dep(depstate.DependentCredential, cert.ID)}, 1),
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: old.ID, Dependent: releasedOther}, 2),
		mustEncode(t, depstate.DependencyReleasedV1{TenantID: tenantA, KeyID: old.ID, Dependent: releasedOther, Reason: "qa-approved-release"}, 3),
	}); err != nil {
		t.Fatal(err)
	}
	current, found, err := decstore.New(st).FetchKeyState(ctx, tenantA, old.ID)
	if err != nil || !found || len(current.Unaccounted()) != 1 || current.Unaccounted()[0].ID != cert.ID || current.LedgerPosition == plan.Job.LedgerPosition {
		t.Fatalf("unrelated release changed the active certificate dependency: state=%+v found=%t err=%v", current, found, err)
	}
	start := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/"+old.ID+"/reprotect", nil)
	start.Header.Set("Idempotency-Key", "start-reviewed-plan")
	queued := httptest.NewRecorder()
	served.ServeHTTP(queued, start)
	if queued.Code != http.StatusAccepted {
		t.Fatalf("reviewed plan did not unlock outbox: %d %s", queued.Code, queued.Body.String())
	}
	pending, err := outbox.Pending(ctx, tenantA)
	if err != nil || len(pending) != 1 || pending[0].Destination != reprotect.DestinationJob {
		t.Fatalf("reviewed start did not queue one VDEC job: %+v err=%v", pending, err)
	}
	runtime, err := eedecommission.NewRuntime(eedecommission.RuntimeConfig{Store: st, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := runtime.ReprotectionOutboxFactory(editionseam.LicensedOutboxDeps{Store: st, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	handled, err := handler.DeliverLicensed(ctx, orchestrator.Message{ID: pending[0].ID, TenantID: tenantA,
		Destination: pending[0].Destination, IdempotencyKey: pending[0].IdempotencyKey, Payload: pending[0].Payload})
	if !handled || err != nil {
		t.Fatalf("reviewed VDEC job did not dispatch to bound host work: handled=%t err=%v", handled, err)
	}
	pending, err = outbox.Pending(ctx, tenantA)
	if err != nil || len(pending) != 2 {
		t.Fatalf("re-protection did not create one durable host job: %+v err=%v", pending, err)
	}
	var hostJob struct {
		IdentityID               string `json:"identity_id"`
		TargetID                 string `json:"target_id"`
		Revision                 string `json:"target_revision"`
		IssuingAuthorityID       string `json:"issuing_authority_id"`
		PredecessorCertificateID string `json:"predecessor_certificate_id"`
		ReprotectJobID           string `json:"reprotect_job_id"`
	}
	var hostPayload []byte
	var hostKey string
	var hostID int64
	for _, row := range pending {
		if row.Destination != "endpoint.renew" {
			continue
		}
		hostPayload, hostKey, hostID = row.Payload, row.IdempotencyKey, row.ID
		if err := json.Unmarshal(row.Payload, &hostJob); err != nil {
			t.Fatal(err)
		}
	}
	if hostJob.IdentityID != identityID || hostJob.TargetID != targetID || hostJob.Revision != target.RevisionID ||
		hostJob.IssuingAuthorityID != successor.ID || hostJob.PredecessorCertificateID != cert.ID || hostJob.ReprotectJobID != result.JobID {
		t.Fatalf("host job lost immutable VDEC bindings: %+v", hostJob)
	}
	if _, err := reprotect.AuthorizeHostCSR(ctx, st, log, tenantA, agentID, hostKey, hostPayload, csr); err != nil {
		t.Fatalf("bound retained-key CSR refused: %v", err)
	}
	wrongSubject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongSubject.Destroy()
	wrongCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "ca-reprotect.qa.invalid", DNSNames: []string{"ca-reprotect.qa.invalid"}}, wrongSubject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reprotect.AuthorizeHostCSR(ctx, st, log, tenantA, agentID, hostKey, hostPayload, wrongCSR); err == nil {
		t.Fatal("different subject key reached signer")
	}
	newDER, err := crypto.SignLeafFromCSR(successorDER, successorSigner, csr, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newInfo, err := certinfo.Inspect(newDER)
	if err != nil {
		t.Fatal(err)
	}
	newCert, err := fixtureOrch.RecordCertificate(ctx, tenantA, corestore.Certificate{TenantID: tenantA,
		Subject: newInfo.Subject, SANs: newInfo.DNSNames, Issuer: newInfo.Issuer, Serial: newInfo.SerialNumber,
		Fingerprint: newInfo.SHA256Fingerprint, CertificateDER: newDER, CertificatePEM: crypto.EncodeCertificatePEM(newDER),
		KeyOrigin: "host_agent", Status: "active", IssuanceIdempotencyKey: fmt.Sprintf("agentcsr:%d:0:retained", hostID)})
	if err != nil {
		t.Fatal(err)
	}
	cutover, err := reprotect.AuthorizeVerifiedHostResult(ctx, st, log, tenantA, agentID, hostKey, hostID,
		hostPayload, newCert.Fingerprint, 1)
	if err != nil {
		t.Fatalf("signed host result binding: %v", err)
	}
	if cutover.NewCertificateID != newCert.ID || cutover.OldCertificateID != cert.ID {
		t.Fatalf("host cutover identity changed: %+v", cutover)
	}
	if err := fixtureOrch.RecordCertificateReprotectionCutover(ctx, tenantA, cutover); err == nil {
		t.Fatal("cutover without the verified signed receipt was recorded")
	}
	cutover.ReceiptStatement = fmt.Sprintf("trstctl-agent-job-receipt/v2\ntenant=%s\nagent=qa-host\njob=%d\nattempt=1\noutcome=verified\nevidence=qa-probe-digest\ndetail=qa-detail-digest\ncredential_fingerprint=%s\nkey_origin=host_agent\nkey_storage=file\nkey_exportable=yes\nkey_generated_by=qa-host\nissued_at=1\n", tenantA, hostID, newCert.Fingerprint)
	cutover.ReceiptSignature = "cWEtc2lnbmF0dXJl"
	cutover.ReceiptSignerFingerprint = "qa-agent-certificate-fingerprint"
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
	if err := fixtureOrch.RecordCertificateReprotectionCutover(ctx, tenantA, cutover); err != nil {
		t.Fatalf("signed readback did not atomically cut over certificate and CA selection: %v", err)
	}
	if err := fixtureOrch.RecordCertificateReprotectionCutover(ctx, tenantA, cutover); err != nil {
		t.Fatalf("lost-response cutover replay: %v", err)
	}
	freshSignedRetry := cutover
	freshSignedRetry.ReceiptStatement = strings.Replace(cutover.ReceiptStatement, "issued_at=1\n", "issued_at=2\n", 1)
	freshSignedRetry.ReceiptSignature = "bmV3LXFhLXNpZ25hdHVyZQ=="
	if err := fixtureOrch.RecordCertificateReprotectionCutover(ctx, tenantA, freshSignedRetry); err != nil {
		t.Fatalf("fresh signature over the same served observation must recover first writer: %v", err)
	}
	changedObservation := cutover
	changedObservation.ReceiptStatement = strings.Replace(cutover.ReceiptStatement, "evidence=qa-probe-digest", "evidence=another-probe", 1)
	if err := fixtureOrch.RecordCertificateReprotectionCutover(ctx, tenantA, changedObservation); err == nil {
		t.Fatal("different served readback changed the first-writer cutover")
	}
	if err := reprotect.RecordVerifiedHostCompletion(ctx, st, log, tenantA, cutover); err != nil {
		t.Fatalf("verified host cutover did not account for CA dependent: %v", err)
	}
	if err := reprotect.RecordVerifiedHostCompletion(ctx, st, log, tenantA, cutover); err != nil {
		t.Fatalf("lost-response CA completion replay: %v", err)
	}
	var supersessions, completions int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == tenantA && event.Type == reprotect.TypeCredentialSupersession {
			supersessions++
		}
		if event.TenantID == tenantA && event.Type == depstate.TypeReprotectionCompleted {
			completions++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if supersessions != 1 || completions != 1 {
		t.Fatalf("CA retirement evidence: supersessions=%d completions=%d, want one each", supersessions, completions)
	}
	oldAfter, err := st.GetCertificate(ctx, tenantA, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	newAfter, err := st.GetCertificate(ctx, tenantA, newCert.ID)
	if err != nil {
		t.Fatal(err)
	}
	identityAfter, err := st.GetIdentity(ctx, tenantA, identityID)
	if err != nil {
		t.Fatal(err)
	}
	var selection map[string]string
	if err := json.Unmarshal(identityAfter.Attributes, &selection); err != nil {
		t.Fatal(err)
	}
	if oldAfter.Status != "superseded" || newAfter.ReplacesID == nil || *newAfter.ReplacesID != cert.ID ||
		selection["issuing_authority_id"] != successor.ID {
		t.Fatalf("cutover readback: predecessor=%s successor=%v authority=%s", oldAfter.Status, newAfter.ReplacesID, selection["issuing_authority_id"])
	}
}
