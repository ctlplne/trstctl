// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
)

// IAM-06 acceptance: the running control plane serves the recovery-side
// break-glass procedure. A signed offline emergency bundle is POSTed to the served
// API, verified against deployment-pinned break-glass trust anchors, and reconciled
// into the tenant's hash-chained audit log.
func TestServedBreakglassReconcileRecordsAuditChain(t *testing.T) {
	bundle, caDER, pubDER := servedBreakglassBundle(t)
	auditKey, err := jose.GenerateRSASigningKey("iam-06-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}

	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditSigningKey = auditKey
		d.BreakglassCACertDER = caDER
		d.BreakglassPublicKeyDER = pubDER
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "incident-commander", []string{
		string(authz.CertsIssue), string(authz.AuditRead),
	})

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/reconcile", token, "iam-06-breakglass-reconcile", map[string]any{
		"bundles": []breakglass.Bundle{bundle},
	})
	if code != http.StatusOK {
		t.Fatalf("break-glass reconcile = %d body=%s; want 200", code, body)
	}
	var reconcileResp struct {
		Reconciled int `json:"reconciled"`
	}
	if err := json.Unmarshal(body, &reconcileResp); err != nil || reconcileResp.Reconciled != 1 {
		t.Fatalf("decode reconcile response: reconciled=%d err=%v body=%s", reconcileResp.Reconciled, err, body)
	}
	if !h.hasEvent(t, "breakglass.issued") {
		t.Fatal("breakglass.issued was not appended to the event log")
	}

	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/audit/events?type=breakglass.issued", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit search = %d body=%s; want 200", code, body)
	}
	var auditResp struct {
		Events []audit.Record `json:"events"`
		Count  int            `json:"count"`
	}
	if err := json.Unmarshal(body, &auditResp); err != nil || auditResp.Count != 1 || len(auditResp.Events) != 1 {
		t.Fatalf("decode audit response: count=%d len=%d err=%v body=%s", auditResp.Count, len(auditResp.Events), err, body)
	}
	rec := auditResp.Events[0]
	if rec.Type != "breakglass.issued" || rec.TenantID != h.tenant || rec.Hash == "" {
		t.Fatalf("audit record = type %q tenant %q hash %q; want breakglass.issued for tenant with hash", rec.Type, rec.TenantID, rec.Hash)
	}
	if !bytes.Contains(rec.Data, []byte(`"request_id":"iam-06-emergency-1"`)) || !bytes.Contains(rec.Data, []byte(`"approvals":2`)) {
		t.Fatalf("audit data does not describe the reconciled bundle: %s", rec.Data)
	}
	if _, err := audit.VerifyChain(auditResp.Events); err != nil {
		t.Fatalf("break-glass audit record is not chain-verifiable: %v", err)
	}
}

// F34 acceptance: an ordinary deployment with online emergency custody disabled
// still receives an effect-free, machine-readable setup plan. A disabled optional
// subsystem is a blocked prerequisite, not an empty successful response.
func TestServedBreakglassPreviewExplainsUnconfiguredCustody(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		// buildRunDeps historically assigned the nil concrete runtime into these
		// interfaces when online custody was disabled. Preserve that production
		// shape here so this test catches a typed-nil interface escaping into API
		// composition.
		var disabled *configuredBreakglassRuntime
		d.BreakglassIssuer = disabled
		d.BreakglassCeremonies = disabled
		d.BreakglassRotation = disabled
		d.BreakglassReconciler = disabled
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "breakglass-planner", []string{
		string(authz.CertsIssue),
	})
	workload, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate workload key: %v", err)
	}
	t.Cleanup(workload.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "breakglass-disabled.svc.example.test",
		DNSNames:   []string{"breakglass-disabled.svc.example.test"},
	}, workload)
	if err != nil {
		t.Fatalf("create emergency CSR: %v", err)
	}

	eventHeadBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("read event head before preview: %v", err)
	}
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue-ceremonies/preview", token, "", map[string]any{
		"request_id":  "f34-unconfigured-preview",
		"subject":     "breakglass-disabled.svc.example.test",
		"csr_der":     csrDER,
		"reason":      "verify the disabled online-custody setup guidance",
		"ttl_seconds": 900,
	})
	if code != http.StatusOK || len(body) == 0 {
		t.Fatalf("unconfigured break-glass preview = %d body=%q; want non-empty 200 JSON", code, body)
	}
	var preview api.BreakglassIssuePlanPreview
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode unconfigured break-glass preview: %v body=%s", err, body)
	}
	if preview.Ready || !preview.EffectFree || preview.ApprovalThreshold != 0 || preview.ConfiguredOperatorCount != 0 || len(preview.Blockers) != 2 {
		t.Fatalf("unconfigured break-glass preview did not explain both blockers: %+v", preview)
	}
	if preview.PreviewWrites == nil || preview.PreviewExternalEffects == nil || preview.PreviewSignerCalls == nil {
		t.Fatalf("unconfigured preview omitted explicit zero-effect evidence: %+v", preview)
	}
	if eventHeadAfter, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || eventHeadAfter != eventHeadBefore {
		t.Fatalf("unconfigured break-glass preview changed event head: before=%d after=%d err=%v", eventHeadBefore, eventHeadAfter, lastErr)
	}
}

// TRACE-006/F34 acceptance: the served control plane can perform online
// emergency issuance when a signer-backed break-glass issuer is configured. The
// execution request cannot nominate approvers: distinct authenticated ceremony
// events must satisfy the configured m-of-n roster. The certificate is returned as
// a self-verifying bundle, and the served route records the bundle in the
// hash-chained audit log before responding.
func TestServedOnlineBreakglassIssueRequiresQuorumAndRecordsAuditChain(t *testing.T) {
	var caDER, pubDER []byte
	var onlineRuntime *configuredBreakglassRuntime
	auditKey, err := jose.GenerateRSASigningKey("trace-006-breakglass-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		const handle = "breakglass-served-online"
		signer, err := d.Signer.Client().GenerateDualControlKeyHandle(context.Background(), crypto.ECDSAP256, handle,
			[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, d.SignAuthorizer)
		if err != nil {
			t.Fatalf("create persisted break-glass signer: %v", err)
		}
		issued, err := crypto.SelfSignedHierarchyCA(signer, crypto.HierarchyCAProfile{
			CommonName: "Served Breakglass CA", MaxPathLen: 1, TTL: 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("create signer-backed break-glass CA: %v", err)
		}
		caDER = issued.CertificateDER
		pubDER = append([]byte(nil), signer.Public().DER...)
		runtime, err := breakglassRotationFromConfig(context.Background(), config.Breakglass{
			Enabled: true, OnlineEnabled: true, CACertFile: "configured", PublicKeyFile: "configured",
			TenantID: servedTestTenant, SignerHandle: handle, Operators: []string{"op1", "op2", "op3"}, Threshold: 2,
		}, d.Store, d.Log, d.Signer, d.SignAuthorizer, caDER, pubDER)
		if err != nil {
			t.Fatalf("assemble online break-glass runtime: %v", err)
		}
		onlineRuntime = runtime
		d.AuditSigningKey = auditKey
		d.BreakglassCACertDER = caDER
		d.BreakglassPublicKeyDER = pubDER
		d.BreakglassIssuer = runtime
		d.BreakglassCeremonies = runtime
		d.BreakglassRotation = runtime
		d.BreakglassReconciler = runtime
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "online-breakglass-commander", []string{
		string(authz.CertsIssue), string(authz.AuditRead), string(authz.IssuersRead), string(authz.IssuersWrite),
	})
	op1 := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "op1", []string{string(authz.IssuersWrite)})
	op2 := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "op2", []string{string(authz.IssuersWrite)})
	workload, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate workload key: %v", err)
	}
	t.Cleanup(workload.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "breakglass-online.svc.example.test",
		DNSNames:   []string{"breakglass-online.svc.example.test"},
	}, workload)
	if err != nil {
		t.Fatalf("create emergency CSR: %v", err)
	}

	request := map[string]any{
		"request_id":  "trace-006-online-emergency-1",
		"subject":     "breakglass-online.svc.example.test",
		"csr_der":     csrDER,
		"reason":      "regional CA outage while production recovery needs one short-lived certificate",
		"ttl_seconds": 900,
	}
	eventHeadBeforePreview, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("read event head before preview: %v", err)
	}
	invalidRequest := map[string]any{
		"request_id":  request["request_id"],
		"subject":     request["subject"],
		"csr_der":     []byte("not-a-signed-pkcs10-request"),
		"reason":      request["reason"],
		"ttl_seconds": request["ttl_seconds"],
	}
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue-ceremonies/preview", token, "", invalidRequest)
	if code != http.StatusBadRequest || !bytes.Contains(body, []byte("signed PKCS#10")) {
		t.Fatalf("preview malformed CSR = %d body=%s; want fail-closed 400", code, body)
	}
	if eventHeadAfterInvalid, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || eventHeadAfterInvalid != eventHeadBeforePreview {
		t.Fatalf("rejected break-glass preview changed event head: before=%d after=%d err=%v", eventHeadBeforePreview, eventHeadAfterInvalid, lastErr)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue-ceremonies/preview", token, "", request)
	if code != http.StatusOK {
		t.Fatalf("preview online break-glass issue = %d body=%s; want 200", code, body)
	}
	var preview struct {
		Capability              string   `json:"capability"`
		Operation               string   `json:"operation"`
		Ready                   bool     `json:"ready"`
		EffectFree              bool     `json:"effect_free"`
		RequestFingerprint      string   `json:"request_fingerprint"`
		CSRSHA256               string   `json:"csr_sha256"`
		ApprovalThreshold       int      `json:"approval_threshold"`
		ConfiguredOperatorCount int      `json:"configured_operator_count"`
		PreviewWrites           []string `json:"preview_writes"`
		PreviewExternalEffects  []string `json:"preview_external_effects"`
		PreviewSignerCalls      []string `json:"preview_signer_calls"`
		ExecutionWrites         []string `json:"execution_writes"`
		ExecutionSignerCalls    []string `json:"execution_signer_calls"`
		RecoverySteps           []string `json:"recovery_steps"`
		VerificationSteps       []string `json:"verification_steps"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode break-glass preview: %v body=%s", err, body)
	}
	if preview.Capability != "F34" || preview.Operation != "issue_breakglass" || !preview.Ready || !preview.EffectFree ||
		preview.RequestFingerprint == "" || preview.CSRSHA256 == "" || preview.ApprovalThreshold != 2 || preview.ConfiguredOperatorCount != 3 {
		t.Fatalf("break-glass preview identity/readiness is incomplete: %+v", preview)
	}
	if preview.PreviewWrites == nil || len(preview.PreviewWrites) != 0 || preview.PreviewExternalEffects == nil ||
		len(preview.PreviewExternalEffects) != 0 || preview.PreviewSignerCalls == nil || len(preview.PreviewSignerCalls) != 0 ||
		len(preview.ExecutionWrites) < 2 || len(preview.ExecutionSignerCalls) == 0 || len(preview.RecoverySteps) == 0 || len(preview.VerificationSteps) == 0 {
		t.Fatalf("break-glass preview omitted zero-effect or lifecycle evidence: %+v", preview)
	}
	if eventHeadAfterPreview, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || eventHeadAfterPreview != eventHeadBeforePreview {
		t.Fatalf("effect-free break-glass preview changed event head: before=%d after=%d err=%v", eventHeadBeforePreview, eventHeadAfterPreview, lastErr)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue-ceremonies", token, "trace-006-breakglass-ceremony", request)
	if code != http.StatusCreated {
		t.Fatalf("start online break-glass ceremony = %d body=%s", code, body)
	}
	var ceremony api.BreakglassCeremony
	if err := json.Unmarshal(body, &ceremony); err != nil || ceremony.ID == "" || ceremony.Threshold != 2 {
		t.Fatalf("decode exact break-glass ceremony: %+v err=%v body=%s", ceremony, err, body)
	}
	for i, approvalToken := range []string{op1, op2} {
		code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", approvalToken, fmt.Sprintf("trace-006-approval-%d", i), nil)
		if code != http.StatusOK {
			t.Fatalf("approval %d = %d body=%s", i, code, body)
		}
	}
	request["ceremony_id"] = ceremony.ID
	onlineRuntime.issueAfterAppend = func() error { return errors.New("injected transaction abort after durable emergency issue") }
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue", token, "trace-006-breakglass-issue", request)
	onlineRuntime.issueAfterAppend = nil
	if code != http.StatusCreated {
		t.Fatalf("online break-glass issue = %d body=%s; want 201", code, body)
	}
	var issued struct {
		Bundle         breakglass.Bundle `json:"bundle"`
		Reconciled     int               `json:"reconciled"`
		AuditEventType string            `json:"audit_event_type"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode issue response: %v body=%s", err, body)
	}
	if issued.Reconciled != 1 || issued.AuditEventType != "breakglass.issued" {
		t.Fatalf("issue response audit fields = reconciled %d event %q", issued.Reconciled, issued.AuditEventType)
	}
	if issued.Bundle.RequestID != "trace-006-online-emergency-1" || !sameMembers(issued.Bundle.Approvals, []string{"op1", "op2"}) {
		t.Fatalf("issued bundle = %+v", issued.Bundle)
	}
	if err := breakglass.Verify(issued.Bundle, caDER, pubDER); err != nil {
		t.Fatalf("served online bundle does not verify: %v", err)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue", token, "trace-006-breakglass-issue-distinct-retry", request)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("new-key retry of consumed emergency ceremony = %d body=%s; want 422", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/issues?limit=1", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list durable emergency issues = %d body=%s", code, body)
	}
	var listed struct {
		Items []struct {
			CeremonyID string          `json:"ceremony_id"`
			Bundle     json.RawMessage `json:"bundle"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &listed); err != nil || len(listed.Items) != 1 || listed.Items[0].CeremonyID != ceremony.ID || len(listed.Items[0].Bundle) != 0 {
		t.Fatalf("bounded issue list disclosed a bundle or lost the ceremony: %+v err=%v body=%s", listed, err, body)
	}
	if listed.NextCursor == "" {
		t.Fatal("full issue page has no stable keyset cursor")
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/issues?limit=1&cursor="+listed.NextCursor, token, "", nil)
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"items":[]`)) {
		t.Fatalf("issue list after source-sequence cursor = %d body=%s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/issues?cursor=bad", token, "", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("malformed issue cursor = %d body=%s; want 400", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/issues/"+ceremony.ID, token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("recover signed emergency bundle = %d body=%s", code, body)
	}
	var recovered struct {
		Bundle        breakglass.Bundle `json:"bundle"`
		CeremonyID    string            `json:"ceremony_id"`
		EventSequence uint64            `json:"event_sequence"`
	}
	if err := json.Unmarshal(body, &recovered); err != nil || recovered.CeremonyID != ceremony.ID || recovered.EventSequence == 0 || !bytes.Equal(recovered.Bundle.CertDER, issued.Bundle.CertDER) || !bytes.Equal(recovered.Bundle.Signature, issued.Bundle.Signature) {
		t.Fatalf("readback differs from signed issued result: %+v err=%v", recovered, err)
	}
	if err := breakglass.Verify(recovered.Bundle, caDER, pubDER); err != nil {
		t.Fatalf("recovered signed bundle does not verify: %v", err)
	}
	// Simulate an N-1 warm upgrade: the historical issue predates the new SQL
	// receipt, while its immutable event and ceremony remain. Typed catch-up
	// must repopulate the exact bundle and safely replay a partially completed
	// pass without asking the signer to issue again.
	if _, err := h.store.SystemPool().Exec(t.Context(), `DELETE FROM breakglass_issue_receipts
		WHERE tenant_id=$1 AND ceremony_id=$2`, h.tenant, ceremony.ID); err != nil {
		t.Fatalf("simulate old missing receipt: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE projection_checkpoint
		SET breakglass_issue_checked_through=NULL WHERE id=1`); err != nil {
		t.Fatalf("reset backfill cursor: %v", err)
	}
	projector := projections.New(h.store)
	for attempt := 0; attempt < 2; attempt++ {
		if err := projector.ProjectCatchUp(t.Context(), h.log); err != nil {
			t.Fatalf("recover retained online issue attempt %d: %v", attempt+1, err)
		}
		code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/issues/"+ceremony.ID, token, "", nil)
		if code != http.StatusOK {
			t.Fatalf("read recovered issue after pass %d = %d body=%s", attempt+1, code, body)
		}
		var replayed struct {
			Bundle breakglass.Bundle `json:"bundle"`
		}
		if err := json.Unmarshal(body, &replayed); err != nil || !bytes.Equal(replayed.Bundle.CertDER, issued.Bundle.CertDER) || !bytes.Equal(replayed.Bundle.Signature, issued.Bundle.Signature) {
			t.Fatalf("warm recovery pass %d changed signed issue: %+v err=%v", attempt+1, replayed, err)
		}
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/issues/"+ceremony.ID, op1, "", nil)
	if code != http.StatusForbidden {
		t.Fatalf("non-issuer readback = %d body=%s; want 403", code, body)
	}
	if !h.hasEvent(t, "breakglass.issued") {
		t.Fatal("online break-glass issue did not append breakglass.issued")
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/audit/events?type=breakglass.issued", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit search = %d body=%s; want 200", code, body)
	}
	var auditResp struct {
		Events []audit.Record `json:"events"`
		Count  int            `json:"count"`
	}
	if err := json.Unmarshal(body, &auditResp); err != nil || auditResp.Count != 1 || len(auditResp.Events) != 1 {
		t.Fatalf("decode audit response: count=%d len=%d err=%v body=%s", auditResp.Count, len(auditResp.Events), err, body)
	}
	if !bytes.Contains(auditResp.Events[0].Data, []byte(`"request_id":"trace-006-online-emergency-1"`)) ||
		!bytes.Contains(auditResp.Events[0].Data, []byte(`"approvals":2`)) {
		t.Fatalf("audit data does not describe online break-glass issue: %s", auditResp.Events[0].Data)
	}
	if _, err := audit.VerifyChain(auditResp.Events); err != nil {
		t.Fatalf("online break-glass audit record is not chain-verifiable: %v", err)
	}

	subquorum := map[string]any{
		"request_id":  "trace-006-online-emergency-2",
		"subject":     "breakglass-online.svc.example.test",
		"csr_der":     csrDER,
		"reason":      "sub-quorum should fail closed",
		"ttl_seconds": 900,
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue-ceremonies", token, "trace-006-subquorum-ceremony", subquorum)
	if code != http.StatusCreated || json.Unmarshal(body, &ceremony) != nil {
		t.Fatalf("start sub-quorum ceremony = %d body=%s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", op1, "trace-006-subquorum-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("sub-quorum approval = %d body=%s", code, body)
	}
	subquorum["ceremony_id"] = ceremony.ID
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue", token, "trace-006-breakglass-subquorum", subquorum)
	if code != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("quorum not met")) {
		t.Fatalf("sub-quorum online break-glass issue = %d body=%s; want 422 quorum not met", code, body)
	}

	rotationIntent := map[string]any{"reason": "replace the emergency CA after incident recovery", "ttl_seconds": 43200}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/rotation-ceremonies", token, "trace-006-rotation-ceremony", rotationIntent)
	if code != http.StatusCreated || json.Unmarshal(body, &ceremony) != nil {
		t.Fatalf("start rotation ceremony = %d body=%s", code, body)
	}
	for i, approvalToken := range []string{op1, op2} {
		code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", approvalToken, fmt.Sprintf("trace-006-rotation-approval-%d", i), nil)
		if code != http.StatusOK {
			t.Fatalf("rotation approval %d = %d body=%s", i, code, body)
		}
	}
	rotationIntent["ceremony_id"] = ceremony.ID
	onlineRuntime.rotationAfterAppend = func() error { return errors.New("injected transaction abort after durable emergency rotation") }
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/rotate", token, "trace-006-rotation", rotationIntent)
	onlineRuntime.rotationAfterAppend = nil
	if code != http.StatusCreated {
		t.Fatalf("durable emergency rotation after transaction abort = %d body=%s; want 201", code, body)
	}
	var rotation api.BreakglassRotation
	if err := json.Unmarshal(body, &rotation); err != nil || rotation.CeremonyID != ceremony.ID || rotation.ActiveSignerHandle == rotation.PreviousSignerHandle {
		t.Fatalf("decode exact emergency rotation: %+v err=%v", rotation, err)
	}
	rotationCeremonyID := ceremony.ID
	previousDER, err := oneCertificateDER(rotation.PreviousCertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	activeDER, err := oneCertificateDER(rotation.ActiveCertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	newByOldDER, err := oneCertificateDER(rotation.NewSignedByPreviousPEM)
	if err != nil || crypto.VerifyCrossSignedCA(previousDER, activeDER, newByOldDER) != nil {
		t.Fatalf("rotated CA lacks a valid predecessor trust path: %v", err)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/rotate", token, "trace-006-rotation-distinct-retry", rotationIntent)
	if code != http.StatusConflict {
		t.Fatalf("distinct-key retry of consumed rotation = %d body=%s; want 409", code, body)
	}

	targetKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(targetKey.Destroy)
	target, err := crypto.SelfSignedHierarchyCA(targetKey, crypto.HierarchyCAProfile{CommonName: "Recovery peer CA", MaxPathLen: 0, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	crossIntent := map[string]any{"certificate_pem": certificatePEM(target.CertificateDER)}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/cross-sign-ceremonies", token, "trace-006-cross-ceremony", crossIntent)
	if code != http.StatusCreated || json.Unmarshal(body, &ceremony) != nil {
		t.Fatalf("start cross-sign ceremony = %d body=%s", code, body)
	}
	for i, approvalToken := range []string{op1, op2} {
		code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", approvalToken, fmt.Sprintf("trace-006-cross-approval-%d", i), nil)
		if code != http.StatusOK {
			t.Fatalf("cross-sign approval %d = %d body=%s", i, code, body)
		}
	}
	crossIntent["ceremony_id"] = ceremony.ID
	onlineRuntime.crossSignAfterAppend = func() error { return errors.New("injected transaction abort after durable emergency cross-sign") }
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/cross-sign", token, "trace-006-cross-sign", crossIntent)
	onlineRuntime.crossSignAfterAppend = nil
	if code != http.StatusCreated {
		t.Fatalf("durable emergency cross-sign after transaction abort = %d body=%s; want 201", code, body)
	}
	var cross api.BreakglassCrossSign
	if err := json.Unmarshal(body, &cross); err != nil || cross.CeremonyID != ceremony.ID || cross.IssuerSignerHandle != rotation.ActiveSignerHandle {
		t.Fatalf("decode exact emergency cross-sign: %+v err=%v", cross, err)
	}
	crossCeremonyID := ceremony.ID
	crossDER, err := oneCertificateDER(cross.CertificatePEM)
	if err != nil || crypto.VerifyCrossSignedCA(activeDER, target.CertificateDER, crossDER) != nil {
		t.Fatalf("emergency cross-sign has no valid target trust path: %v", err)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/cross-sign", token, "trace-006-cross-distinct-retry", crossIntent)
	if code != http.StatusConflict {
		t.Fatalf("distinct-key retry of consumed cross-sign = %d body=%s; want 409", code, body)
	}
	for _, item := range []struct {
		id   string
		kind string
	}{
		{rotationCeremonyID, "rotation"}, {crossCeremonyID, "cross_sign"},
	} {
		code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/authority-receipts/"+item.id, token, "", nil)
		if code != http.StatusOK {
			t.Fatalf("recover %s authority result = %d body=%s; want 200", item.kind, code, body)
		}
		var receipt struct {
			Kind     string                   `json:"kind"`
			Rotation *api.BreakglassRotation  `json:"rotation"`
			Cross    *api.BreakglassCrossSign `json:"cross_sign"`
		}
		if err := json.Unmarshal(body, &receipt); err != nil || receipt.Kind != item.kind ||
			(item.kind == "rotation" && (receipt.Rotation == nil || receipt.Rotation.ActiveCertificatePEM != rotation.ActiveCertificatePEM)) ||
			(item.kind == "cross_sign" && (receipt.Cross == nil || receipt.Cross.CertificatePEM != cross.CertificatePEM)) {
			t.Fatalf("recovered %s result changed or omitted its exact certificate: %+v err=%v", item.kind, receipt, err)
		}
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/authority-receipts?limit=1", token, "", nil)
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"kind":"cross_sign"`)) || bytes.Contains(body, []byte(`"certificate_pem"`)) {
		t.Fatalf("bounded authority receipt list = %d body=%s; want newest summary without certificate", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/authority-receipts/"+rotationCeremonyID, op1, "", nil)
	if code != http.StatusForbidden {
		t.Fatalf("write-only custodian readback = %d body=%s; want 403", code, body)
	}
	// An N-1 deployment may have the signed events but not the new SQL rows.
	// Indexed catch-up must reconstruct both public results without a signer
	// call, and repeating the pass must preserve their exact certificates.
	if _, err := h.store.SystemPool().Exec(t.Context(), `DELETE FROM breakglass_authority_receipts WHERE tenant_id=$1`, h.tenant); err != nil {
		t.Fatalf("simulate missing historical authority receipts: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE projection_checkpoint SET breakglass_authority_checked_through=NULL WHERE id=1`); err != nil {
		t.Fatalf("reset authority receipt backfill cursor: %v", err)
	}
	for pass := 1; pass <= 2; pass++ {
		if err := projector.ProjectCatchUp(t.Context(), h.log); err != nil {
			t.Fatalf("rebuild historical emergency CA receipts, pass %d: %v", pass, err)
		}
		for _, item := range []string{rotationCeremonyID, crossCeremonyID} {
			code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/breakglass/authority-receipts/"+item, token, "", nil)
			var recovered api.BreakglassAuthorityReceipt
			if code != http.StatusOK || json.Unmarshal(body, &recovered) != nil ||
				(item == rotationCeremonyID && (recovered.Rotation == nil || recovered.Rotation.ActiveCertificatePEM != rotation.ActiveCertificatePEM)) ||
				(item == crossCeremonyID && (recovered.CrossSign == nil || recovered.CrossSign.CertificatePEM != cross.CertificatePEM)) {
				t.Fatalf("historical authority result pass %d = %d body=%s", pass, code, body)
			}
		}
	}
}

func servedBreakglassBundle(t *testing.T) (breakglass.Bundle, []byte, []byte) {
	t.Helper()
	svc, caDER, pubDER := servedBreakglassService(t)
	bundle, err := svc.IssueOffline(breakglass.EmergencyRequest{
		ID:        "iam-06-emergency-1",
		Subject:   "recovery.svc.example.test",
		CSRDer:    servedBreakglassCSR(t, "recovery.svc.example.test"),
		Reason:    "control plane signer unavailable during regional outage",
		Approvals: []string{"op1", "op2"},
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("issue offline bundle: %v", err)
	}
	return bundle, caDER, pubDER
}

func servedBreakglassService(t *testing.T) (*breakglass.Service, []byte, []byte) {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate break-glass CA key: %v", err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "Break-glass Emergency CA", time.Hour)
	if err != nil {
		t.Fatalf("self-sign break-glass CA: %v", err)
	}
	svc, err := breakglass.New(breakglass.Config{
		TenantID:  servedTestTenant,
		CACertDER: caDER,
		CASigner:  ca,
		Quorum:    breakglass.Quorum{Threshold: 2, Operators: []string{"op1", "op2", "op3"}},
		Clock:     func() time.Time { return time.Unix(1_736_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("new break-glass service: %v", err)
	}
	return svc, caDER, svc.PublicKeyDER()
}

func servedBreakglassCSR(t *testing.T, subject string) []byte {
	t.Helper()
	workload, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate workload key: %v", err)
	}
	t.Cleanup(workload.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: subject,
		DNSNames:   []string{subject},
	}, workload)
	if err != nil {
		t.Fatalf("create emergency CSR: %v", err)
	}
	return csrDER
}
