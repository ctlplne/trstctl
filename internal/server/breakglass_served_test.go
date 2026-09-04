// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
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

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
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

// TRACE-006/F34 acceptance: the served control plane can perform online
// emergency issuance when a signer-backed break-glass issuer is configured. The
// execution request cannot nominate approvers: distinct authenticated ceremony
// events must satisfy the configured m-of-n roster. The certificate is returned as
// a self-verifying bundle, and the served route records the bundle in the
// hash-chained audit log before responding.
func TestServedOnlineBreakglassIssueRequiresQuorumAndRecordsAuditChain(t *testing.T) {
	var caDER, pubDER []byte
	auditKey, err := jose.GenerateRSASigningKey("trace-006-breakglass-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		const handle = "breakglass-served-online"
		signer, err := d.Signer.Client().GenerateDualControlKeyHandle(context.Background(), crypto.ECDSAP256, handle,
			[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, d.SignAuthorizer)
		if err != nil {
			t.Fatalf("create persisted break-glass signer: %v", err)
		}
		issued, err := crypto.SelfSignedHierarchyCA(signer, crypto.HierarchyCAProfile{
			CommonName: "Served Breakglass CA", MaxPathLen: 0, TTL: 24 * time.Hour,
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
		d.AuditSigningKey = auditKey
		d.BreakglassCACertDER = caDER
		d.BreakglassPublicKeyDER = pubDER
		d.BreakglassIssuer = runtime
		d.BreakglassCeremonies = runtime
		d.BreakglassRotation = runtime
		d.BreakglassReconciler = runtime
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "online-breakglass-commander", []string{
		string(authz.CertsIssue), string(authz.AuditRead),
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
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/issue", token, "trace-006-breakglass-issue", request)
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
