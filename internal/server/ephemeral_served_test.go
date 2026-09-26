// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// TestServedEphemeralJITIssuesAfterAttestationAndApproval is the NHI-04
// acceptance proof. It drives the assembled HTTP API: a workload presents a valid
// attestation, the served path opens a dual-control approval request and enqueues
// the notification intent through outbox, a distinct approver authorizes it, and
// a fresh idempotent issue call returns a short-TTL signer-backed credential.
func TestServedEphemeralPreviewIsExactEffectFreeAndFailClosed(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EphemeralIssuance = EphemeralIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 2 * time.Second,
			MaxTTL: 5 * time.Second, ApprovalTTL: time.Minute, RequiredApprovals: 1,
			Attestors: []attest.Attestor{servedEphemeralAttestor{}},
		}
	})
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "preview-requester", "certs:request", "certs:read")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)
	body := map[string]any{
		"request_id":     "jit-preview-7",
		"method":         "stub_ephemeral",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"public_key_pem": publicKeyPEM,
		"ttl_seconds":    99,
	}
	headBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("read event head before preview: %v", err)
	}
	stateBefore := ephemeralPreviewMutationState(t, h)
	countedSigner := &countingEphemeralDigestSigner{DigestSigner: h.srv.ephemeralIssuer.caSigner}
	h.srv.ephemeralIssuer.caSigner = countedSigner

	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/preview", requester, "", body)
	if status != http.StatusOK {
		t.Fatalf("ephemeral preview status = %d, want 200; body=%s", status, raw)
	}
	var preview api.EphemeralCredentialPreview
	if err := json.Unmarshal(raw, &preview); err != nil {
		t.Fatalf("decode ephemeral preview: %v; body=%s", err, raw)
	}
	if !preview.Ready || !preview.EffectFree || preview.RequestID != "jit-preview-7" ||
		preview.Method != "stub_ephemeral" || preview.Requester != "preview-requester" ||
		preview.TrustDomain != "served.test" || preview.RequestedTTLSeconds != 99 ||
		preview.EffectiveTTLSeconds != 5 || preview.MaxTTLSeconds != 5 || !preview.TTLClamped ||
		preview.ApprovalTTLSeconds != 60 || preview.RequiredApprovals != 1 ||
		preview.AttestationVerification != "execution_only" {
		t.Fatalf("ephemeral preview = %+v", preview)
	}
	if len(preview.PayloadSHA256) != 64 || len(preview.PublicKeySHA256) != 64 ||
		len(preview.PreviewWrites) != 0 || len(preview.PreviewExternalEffects) != 0 ||
		len(preview.PreviewSignerCalls) != 0 || len(preview.SubmissionWrites) == 0 ||
		len(preview.IssuanceWrites) == 0 || len(preview.Steps) != 3 ||
		len(preview.RecoverySteps) == 0 || len(preview.Blockers) != 0 {
		t.Fatalf("ephemeral preview contract is incomplete: %+v", preview)
	}
	if bytes.Contains(raw, []byte(body["payload_base64"].(string))) ||
		bytes.Contains(raw, []byte("BEGIN PUBLIC KEY")) || bytes.Contains(raw, []byte("genuine")) {
		t.Fatalf("ephemeral preview leaked submitted proof or public-key body: %s", raw)
	}
	if got := countedSigner.calls.Load(); got != 0 {
		t.Fatalf("ephemeral preview signer calls = %d, want 0", got)
	}
	if headAfter, err := h.log.LastSequence(t.Context()); err != nil || headAfter != headBefore {
		t.Fatalf("ephemeral preview event head = (%d, %v), want %d", headAfter, err, headBefore)
	}
	if stateAfter := ephemeralPreviewMutationState(t, h); stateAfter != stateBefore {
		t.Fatalf("ephemeral preview changed durable state: before=%+v after=%+v", stateBefore, stateAfter)
	}

	body["method"] = "not_configured"
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/preview", requester, "", body)
	if status != http.StatusOK {
		t.Fatalf("unsupported-method preview status = %d, want 200; body=%s", status, raw)
	}
	if err := json.Unmarshal(raw, &preview); err != nil {
		t.Fatalf("decode unsupported-method preview: %v", err)
	}
	if preview.Ready || len(preview.Blockers) != 1 || !strings.Contains(preview.Blockers[0], "not configured") {
		t.Fatalf("unsupported method did not fail closed: %+v", preview)
	}
}

func TestServedEphemeralUsesTenantOwnedKubernetesTrustSource(t *testing.T) {
	fixture := servedDynamicK8sTrustFixture(t, "ephemeral-k8s-k1")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EphemeralIssuance = EphemeralIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 2 * time.Minute,
			MaxTTL: 5 * time.Minute, ApprovalTTL: time.Minute, RequiredApprovals: 1,
		}
	})
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "dynamic-requester", "certs:request", "certs:read")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "dynamic-approver", "certs:issue", "certs:read")
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		approver, "ephemeral-trust-create", map[string]any{
			"name": "ephemeral-k8s", "method": "k8s_sat",
			"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": fixture.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create tenant ephemeral trust source: status=%d body=%s", status, raw)
	}
	body := map[string]any{
		"request_id": "dynamic-jit-1", "method": "k8s_sat",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte(fixture.SAT)),
		"public_key_pem": servedAttestedPublicKeyPEM(t), "ttl_seconds": 120,
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/preview", requester, "", body)
	if status != http.StatusOK {
		t.Fatalf("preview tenant-trusted ephemeral request: status=%d body=%s", status, raw)
	}
	var preview api.EphemeralCredentialPreview
	if err := json.Unmarshal(raw, &preview); err != nil {
		t.Fatalf("decode dynamic ephemeral preview: %v", err)
	}
	if !preview.Ready || !slices.Contains(preview.SupportedMethods, "k8s_sat") || len(preview.Blockers) != 0 {
		t.Fatalf("tenant trust source did not make exact preview ready: %+v", preview)
	}
	pending := servedEphemeralIssue(t, h, requester, "dynamic-jit-request", body, http.StatusAccepted)
	servedEphemeralApprove(t, h, approver, "dynamic-jit-approve", pending.ApprovalRequestID, pending.IntentDigest, http.StatusOK)
	issued := servedEphemeralIssue(t, h, requester, "dynamic-jit-issue", body, http.StatusCreated)
	if issued.State != api.EphemeralStateIssued || issued.Subject != "ns/default/sa/web" || issued.Attestation.Method != "k8s_sat" {
		t.Fatalf("tenant-trusted ephemeral issuance = %+v", issued)
	}
}

func TestServedEphemeralJITIssuesAfterAttestationAndApproval(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EphemeralIssuance = EphemeralIssuanceConfig{
			Enabled:           true,
			TrustDomain:       "served.test",
			DefaultTTL:        2 * time.Second,
			MaxTTL:            5 * time.Second,
			ApprovalTTL:       time.Minute,
			RequiredApprovals: 1,
			Attestors:         []attest.Attestor{servedEphemeralAttestor{}},
		}
	})
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "jit-requester", "certs:request", "certs:read")
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "jit-approver", "certs:issue", "certs:read")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)
	body := map[string]any{
		"request_id":     "jit-agent-7",
		"method":         "stub_ephemeral",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"public_key_pem": publicKeyPEM,
		"ttl_seconds":    2,
	}

	pending := servedEphemeralIssue(t, h, requester, "nhi-04-request", body, http.StatusAccepted)
	if pending.State != "awaiting_approval" || pending.RequestID != "jit-agent-7" || pending.RequiredApprovals != 1 ||
		pending.ApprovalRequestID == "" || pending.IntentDigest == "" {
		t.Fatalf("pending JIT response = %+v", pending)
	}
	if pending.CertificatePEM != "" || pending.ExpiresAt.IsZero() || !pending.ExpiresAt.After(time.Now()) {
		t.Fatalf("pending JIT response leaked credential or has no approval expiry: %+v", pending)
	}
	if got := ephemeralApprovalOutboxCount(t, h, "approval-request:"+pending.ApprovalRequestID); got != 1 {
		t.Fatalf("approval outbox rows = %d, want 1", got)
	}
	request, err := h.store.GetOperationApproval(context.Background(), h.tenant, pending.ApprovalRequestID)
	if err != nil {
		t.Fatalf("load exact ephemeral approval request: %v", err)
	}
	expectedEvidencePrefixes := []string{
		"attestation-method:",
		"attestation-selectors-sha256:",
		"attestation-subject-sha256:",
		"client-request-id-sha256:",
		"command-sha256:",
		"ephemeral-ca-certificate-sha256:",
		"ephemeral-ca-id:",
		"not-before-backdate-seconds:",
		"public-key-sha256:",
		"spiffe-id-sha256:",
		"ttl-seconds:",
	}
	if request.IntentDigest != pending.IntentDigest || request.ResourceKind != "ephemeral" ||
		request.ResourceID != "ephemeral:jit-agent-7" || request.Action != "issue" ||
		request.Requester != "jit-requester" || request.FromState != "attested" ||
		!strings.HasPrefix(request.ToState, "issued:sha256:") || request.Status != store.ApprovalStatusPending ||
		len(request.EvidenceRefs) != len(expectedEvidencePrefixes) {
		t.Fatalf("exact ephemeral approval request = %+v", request)
	}
	for _, prefix := range expectedEvidencePrefixes {
		if !slices.ContainsFunc(request.EvidenceRefs, func(ref string) bool { return strings.HasPrefix(ref, prefix) }) {
			t.Fatalf("exact ephemeral approval request is missing %q: %+v", prefix, request)
		}
	}
	if got := legacyEphemeralApprovalRequestCount(t, h, "jit-agent-7"); got != 0 {
		t.Fatalf("legacy inferred ephemeral approval rows = %d, want 0", got)
	}

	replayPending := servedEphemeralIssue(t, h, requester, "nhi-04-request", body, http.StatusAccepted)
	if replayPending.RequestID != pending.RequestID || replayPending.ApprovalRequestID != pending.ApprovalRequestID ||
		replayPending.IntentDigest != pending.IntentDigest || !replayPending.ExpiresAt.Equal(pending.ExpiresAt) {
		t.Fatalf("idempotent pending replay changed: first=%+v replay=%+v", pending, replayPending)
	}

	approval := servedEphemeralApprove(t, h, approver, "nhi-04-approve", pending.ApprovalRequestID, pending.IntentDigest, http.StatusOK)
	if approval.ID != pending.ApprovalRequestID || approval.IntentDigest != pending.IntentDigest ||
		approval.Resource != "ephemeral:jit-agent-7" || approval.Action != "issue" ||
		approval.Approvals != 1 || approval.Status != store.ApprovalStatusApproved {
		t.Fatalf("approval response = %+v", approval)
	}

	issued := servedEphemeralIssue(t, h, requester, "nhi-04-issue", body, http.StatusCreated)
	if issued.State != "issued" || issued.CredentialID == "" || issued.CertificateID == "" || issued.CertificatePEM == "" {
		t.Fatalf("issued JIT response = %+v", issued)
	}
	if issued.ApprovalRequestID != pending.ApprovalRequestID || issued.IntentDigest != pending.IntentDigest {
		t.Fatalf("issued JIT authority changed: pending=%+v issued=%+v", pending, issued)
	}
	if issued.Subject != "jit-agent-7" || issued.Attestation.Method != "stub_ephemeral" {
		t.Fatalf("issued JIT attestation = %+v", issued)
	}
	if issued.NotAfter.IsZero() || issued.NotAfter.After(time.Now().Add(6*time.Second)) {
		t.Fatalf("short TTL was not enforced; not_after=%s", issued.NotAfter)
	}

	replayIssued := servedEphemeralIssue(t, h, requester, "nhi-04-issue", body, http.StatusCreated)
	if replayIssued.CertificatePEM != issued.CertificatePEM || replayIssued.CredentialID != issued.CredentialID {
		t.Fatalf("idempotent issued replay changed: first=%+v replay=%+v", issued, replayIssued)
	}
	consumed, err := h.store.GetOperationApproval(context.Background(), h.tenant, pending.ApprovalRequestID)
	if err != nil {
		t.Fatalf("load consumed ephemeral approval: %v", err)
	}
	if consumed.Status != store.ApprovalStatusConsumed || consumed.ConsumedEventID == "" {
		t.Fatalf("ephemeral approval was not atomically consumed: %+v", consumed)
	}

	for _, eventType := range []string{"attestation.verified", "attestation.bound", "approval.requested", "approval.decision.recorded", "ephemeral.issued", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("served ephemeral JIT did not emit %s", eventType)
		}
	}
}

func TestApprovedEphemeralRetryAfterAppendAndSQLRollbackNeverResigns(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EphemeralIssuance = EphemeralIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 5 * time.Second,
			MaxTTL: 5 * time.Second, ApprovalTTL: time.Minute, RequiredApprovals: 1,
			Attestors: []attest.Attestor{servedEphemeralAttestor{}},
		}
	})
	ctx := context.Background()
	const (
		requestID = "jit-crash-agent"
		requester = "jit-crash-requester"
	)
	requesterToken := seedScopedTokenSubject(t, h.store, h.tenant, requester, "certs:request", "certs:read")
	approverToken := seedScopedTokenSubject(t, h.store, h.tenant, "jit-crash-approver", "certs:issue", "certs:read")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)
	body := map[string]any{
		"request_id": requestID, "method": "stub_ephemeral",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"public_key_pem": publicKeyPEM, "ttl_seconds": 5,
	}
	pending := servedEphemeralIssue(t, h, requesterToken, "jit-crash-request", body, http.StatusAccepted)
	servedEphemeralApprove(t, h, approverToken, "jit-crash-approve",
		pending.ApprovalRequestID, pending.IntentDigest, http.StatusOK)
	approval, err := h.store.GetOperationApproval(ctx, h.tenant, pending.ApprovalRequestID)
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := crypto.ParsePublicKeyPEM([]byte(publicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	req := api.EphemeralCredentialRequest{
		RequestID: requestID, Method: "stub_ephemeral", Payload: []byte("genuine"),
		PublicKeyDER: publicKey.DER, TTLSeconds: 5,
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID: h.tenant, Attestors: h.srv.ephemeralIssuer.attestors,
		Audit: h.srv.ephemeralIssuer.audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := verifier.Verify(ctx, req.Method, req.Payload)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := h.srv.ephemeralIssuer.ephemeralApprovalBinding(h.tenant, req, attestation)
	if err != nil {
		t.Fatal(err)
	}
	requestBinding, err := ephemeralApprovedRequestBinding(requester, req, attestation)
	if err != nil {
		t.Fatal(err)
	}
	countedSigner := &countingEphemeralDigestSigner{DigestSigner: h.srv.ephemeralIssuer.caSigner}
	h.srv.ephemeralIssuer.caSigner = countedSigner
	certificateDER, err := h.srv.ephemeralIssuer.sign(h.tenant)(ctx, attestation, req.PublicKeyDER, h.srv.ephemeralIssuer.ttl(req.TTLSeconds))
	if err != nil {
		t.Fatal(err)
	}
	if countedSigner.calls.Load() != 1 {
		t.Fatalf("first certificate signatures = %d, want 1", countedSigner.calls.Load())
	}
	info, err := certinfo.Inspect(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := info.NotBefore, info.NotAfter
	payload := projections.CertificateRecorded{
		ID: projections.CertificateApprovalRowID(h.tenant, use), CAID: h.srv.ephemeralIssuer.caID,
		Subject: info.Subject, SANs: sansOf(info), Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		NotBefore: &notBefore, NotAfter: &notAfter, Source: "ephemeral:" + attestation.Method,
		CertificateDER: certificateDER, IssuanceIdempotencyKey: "ephemeral-issue:" + approval.ID,
		KeyOrigin: string(custody.OriginRequester), Approval: &use, ApprovalBinding: &binding,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID: orchestrator.CertificateApprovalEventID(h.tenant, use), Type: projections.EventCertificateRecorded,
		TenantID: h.tenant, Time: time.Now().UTC().Truncate(time.Microsecond),
		SchemaVersion: projections.CertificateApprovalEventSchemaVersion, Data: raw,
	}
	if err := projections.ValidateApprovedCertificatePayload(event, payload); err != nil {
		t.Fatal(err)
	}
	semantic, err := projections.ApprovedCertificateSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	fence, created, err := h.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: h.tenant, TargetKind: store.ApprovedTargetEphemeralCertificate,
		CommandKey: binding.ClientRequestIDSHA256, RequestBinding: requestBinding,
		EventID: event.ID, EventType: event.Type, SchemaVersion: event.SchemaVersion,
		EventTime: event.Time, Payload: raw, SemanticDigest: semantic,
	}, use)
	if err != nil || !created {
		t.Fatalf("claim canonical certificate = created %t err=%v", created, err)
	}
	appended, err := h.log.Append(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("simulated certificate projection rollback")
	err = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := projections.New(h.store).ApplyTx(ctx, tx, appended); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("simulate append-success/SQL-rollback = %v", err)
	}
	if _, err := h.store.GetCertificate(ctx, h.tenant, payload.ID); !store.IsNotFound(err) {
		t.Fatalf("rolled-back certificate projection = %v", err)
	}
	if _, err := h.store.GetApprovedTargetFence(ctx, h.tenant, fence.TargetKind, fence.CommandKey); err != nil {
		t.Fatalf("rollback lost certificate fence: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE approved_target_event_fences
		SET created_at = created_at - interval '25 hours', updated_at = updated_at - interval '25 hours'
		WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3`,
		h.tenant, fence.TargetKind, fence.CommandKey); err != nil {
		t.Fatal(err)
	}
	changed := req
	changed.TTLSeconds = 4
	if _, err := h.srv.ephemeralIssuer.IssueEphemeralCredential(ctx, h.tenant, "jit-crash-changed", requester, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed-body retry = %v, want ErrIdempotencyConflict", err)
	}
	restarted, err := Build(ctx, Deps{
		Store: h.store, Log: h.log, Signer: h.signer,
		SignAuthorizer: h.authz, CACertFile: h.caFile,
	})
	if err != nil {
		t.Fatalf("startup reconciliation of approved certificate fence: %v", err)
	}
	cleanupServedServer(t, restarted)
	issued, err := h.srv.ephemeralIssuer.IssueEphemeralCredential(ctx, h.tenant, "jit-crash-retry", requester, req)
	if err != nil {
		t.Fatalf("recover canonical certificate: %v", err)
	}
	if countedSigner.calls.Load() != 1 {
		t.Fatalf("recovery re-signed certificate: signatures=%d, want 1", countedSigner.calls.Load())
	}
	if issued.CertificateID != payload.ID || !bytes.Contains([]byte(issued.CertificatePEM), []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("recovered response differs: %+v", issued)
	}
	recovered, err := h.store.GetCertificate(ctx, h.tenant, payload.ID)
	if err != nil || !bytes.Equal(recovered.CertificateDER, certificateDER) {
		t.Fatalf("recovered certificate = %+v err=%v", recovered, err)
	}
	if _, err := h.store.GetApprovedTargetFence(ctx, h.tenant, fence.TargetKind, fence.CommandKey); !store.IsNotFound(err) {
		t.Fatalf("completed certificate fence remains: %v", err)
	}
	eventCount := 0
	if err := h.log.Replay(ctx, 0, func(got events.Event) error {
		if got.ID == event.ID {
			eventCount++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("canonical certificate events = %d, want 1", eventCount)
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold rebuild approved certificate: %v", err)
	}
	rebuilt, err := h.store.GetCertificate(ctx, h.tenant, payload.ID)
	if err != nil || !bytes.Equal(rebuilt.CertificateDER, certificateDER) || rebuilt.Fingerprint != payload.Fingerprint {
		t.Fatalf("cold-rebuilt certificate = %+v err=%v", rebuilt, err)
	}
}

func TestServedEphemeralApprovalUnknownRequestLeavesZeroState(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EphemeralIssuance = EphemeralIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", ApprovalTTL: time.Minute,
			RequiredApprovals: 1, Attestors: []attest.Attestor{servedEphemeralAttestor{}},
		}
	})
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "jit-preflight-approver", "certs:issue")
	const unknownDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for _, tc := range []struct {
		name      string
		requestID string
		key       string
	}{
		{name: "malformed UUID", requestID: "not-a-request-uuid", key: "ephemeral-malformed-request-id"},
		{name: "valid unknown UUID", requestID: "77000000-0000-4000-8000-000000000799", key: "ephemeral-unknown-request-id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headBefore, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatalf("read event head before refusal: %v", err)
			}
			status, body := secretsReqKey(t, h, http.MethodPost,
				"/api/v1/ephemeral/"+tc.requestID+"/approvals", approver, tc.key,
				map[string]any{"action": "issue", "request_id": tc.requestID, "intent_digest": unknownDigest})
			if status != http.StatusNotFound {
				t.Errorf("approve unknown ephemeral request: status %d body %s, want tenant-safe 404", status, body)
			} else {
				var problem struct {
					Status int    `json:"status"`
					Detail string `json:"detail"`
				}
				if err := json.Unmarshal(body, &problem); err != nil {
					t.Errorf("decode unknown-request problem: %v body=%s", err, body)
				} else if problem.Status != http.StatusNotFound || problem.Detail != "resource not found" {
					t.Errorf("unknown-request problem = %+v, want generic resource-not-found response", problem)
				}
				for _, leaked := range []string{h.tenant, tc.requestID, unknownDigest, "operation_approval_requests"} {
					if strings.Contains(string(body), leaked) {
						t.Errorf("tenant-safe ephemeral 404 leaked %q in body %s", leaked, body)
					}
				}
			}
			requests, decisions, idempotency := ephemeralApprovalRefusalState(t, h, tc.key)
			if requests != 0 || decisions != 0 || idempotency != 0 {
				t.Errorf("refused ephemeral approval persisted requests=%d decisions=%d idempotency=%d, want 0/0/0",
					requests, decisions, idempotency)
			}
			if headAfter, err := h.log.LastSequence(t.Context()); err != nil || headAfter != headBefore {
				t.Errorf("refused ephemeral approval event head = (%d, %v), want %d", headAfter, err, headBefore)
			}
		})
	}
}

// TestServedEphemeralAPIKeyAutoExpires is the SEC-10 acceptance proof: the
// assembled server exposes ephemeral API-key issuance over the authenticated HTTP
// API, returns the raw token once, authenticates with it immediately, and then the
// served leaseworker records automatic expiry as api_token.revoked so the bearer
// token stops working and metadata shows revocation evidence.
func TestServedEphemeralAPIKeyAutoExpires(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.DynamicLeaseWorkerInterval = 10 * time.Millisecond
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "ephemeral-key-admin", "access:read", "access:write")

	worker, ok := any(h.srv).(interface{ RunDynamicLeaseWorker(context.Context) })
	if !ok {
		t.Fatal("served lease worker is not wired")
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.RunDynamicLeaseWorker(workerCtx)
	}()
	t.Cleanup(func() {
		cancelWorker()
		<-workerDone
	})

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys", admin, "sec10-issue-api-key", map[string]any{
		"subject":     "ci-ephemeral-key",
		"scopes":      []string{"access:read"},
		"ttl_seconds": 1,
	})
	if status != http.StatusCreated {
		t.Fatalf("ephemeral API-key issue status = %d, want 201; body=%s", status, body)
	}
	var issued struct {
		ID        string     `json:"id"`
		Subject   string     `json:"subject"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
		Token     string     `json:"token"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("decode ephemeral API-key response: %v; body=%s", err, body)
	}
	if issued.ID == "" || issued.Subject != "ci-ephemeral-key" || issued.ExpiresAt == nil || !strings.HasPrefix(issued.Token, auth.TokenPrefix) {
		t.Fatalf("ephemeral API-key response = %+v", issued)
	}
	if issued.ExpiresAt.After(time.Now().Add(2 * time.Second)) {
		t.Fatalf("ephemeral API-key expiry = %s, want short TTL", issued.ExpiresAt)
	}
	if h.logContains(t, issued.Token) {
		t.Fatal("ephemeral API-key raw token reached the event log")
	}

	code, roleBody := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", issued.Token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("fresh ephemeral API key role read = %d, want 200; body=%s", code, roleBody)
	}

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		code, _ = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", issued.Token, "", nil)
		metaCode, listed := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/api-tokens?subject=ci-ephemeral-key&include_revoked=true", admin, "", nil)
		if code == http.StatusUnauthorized && metaCode == http.StatusOK && bytes.Contains(listed, []byte(`"revoked_at"`)) {
			if !h.hasEvent(t, "api_token.revoked") {
				t.Fatal("ephemeral API-key expiry did not emit api_token.revoked")
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	code, roleBody = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", issued.Token, "", nil)
	metaCode, listed := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/api-tokens?subject=ci-ephemeral-key&include_revoked=true", admin, "", nil)
	t.Fatalf("ephemeral API key did not auto-expire: roles=%d body=%s metadata=%d body=%s", code, roleBody, metaCode, listed)
}

// TestServedEphemeralAPIKeyReviewRecoveryAndRevocation is the complete F38
// vertical-slice proof. The native secret store is intentionally disabled: a
// temporary access token belongs to the access service, but its server-keyed
// review still uses the deployment KEK without exposing or persisting key bytes.
func TestServedEphemeralAPIKeyReviewRecoveryAndRevocation(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "ephemeral-review-admin", "access:read", "access:write")
	const subject = "ci-reviewed-deploy"
	request := map[string]any{
		"subject": subject, "scopes": []string{"access:read"}, "ttl_seconds": 300,
	}

	var tokenRowsBefore, idempotencyRowsBefore int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT
		   (SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject = $2),
		   (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1)`,
		h.tenant, subject).Scan(&tokenRowsBefore, &idempotencyRowsBefore); err != nil {
		t.Fatalf("read F38 preview baseline: %v", err)
	}
	eventHeadBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("read F38 event baseline: %v", err)
	}

	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys/preview", admin, "", request)
	if status != http.StatusOK {
		t.Fatalf("ephemeral API-key preview = %d, want 200: %s", status, raw)
	}
	var plan struct {
		Capability              string   `json:"capability"`
		Operation               string   `json:"operation"`
		Ready                   bool     `json:"ready"`
		EffectFree              bool     `json:"effect_free"`
		Subject                 string   `json:"subject"`
		Scopes                  []string `json:"scopes"`
		RequestedTTLSeconds     int64    `json:"requested_ttl_seconds"`
		EffectiveTTLSeconds     int64    `json:"effective_ttl_seconds"`
		MinimumTTLSeconds       int64    `json:"minimum_ttl_seconds"`
		MaximumTTLSeconds       int64    `json:"maximum_ttl_seconds"`
		RequiredPermission      string   `json:"required_permission"`
		RequestFingerprint      string   `json:"request_fingerprint"`
		Blockers                []string `json:"blockers"`
		PreviewWrites           []string `json:"preview_writes"`
		PreviewExternalEffects  []string `json:"preview_external_effects"`
		ExecuteWrites           []string `json:"execute_writes"`
		ExecuteExternalEffects  []string `json:"execute_external_effects"`
		RecoverySteps           []string `json:"recovery_steps"`
		VerificationSteps       []string `json:"verification_steps"`
		CLIArgv                 []string `json:"cli_argv"`
		TokenDataHandling       string   `json:"token_data_handling"`
		NativeSecretStoreNeeded bool     `json:"native_secret_store_needed"`
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("decode F38 preview: %v (%s)", err, raw)
	}
	if plan.Capability != "F38" || plan.Operation != "issue_ephemeral_api_key" || !plan.Ready || !plan.EffectFree ||
		plan.Subject != subject || !slices.Equal(plan.Scopes, []string{"access:read"}) ||
		plan.RequestedTTLSeconds != 300 || plan.EffectiveTTLSeconds != 300 || plan.MinimumTTLSeconds != 1 ||
		plan.MaximumTTLSeconds != 3600 || plan.RequiredPermission != "access:write" ||
		!strings.HasPrefix(plan.RequestFingerprint, "sha256:") || plan.NativeSecretStoreNeeded {
		t.Fatalf("unexpected F38 preview: %+v", plan)
	}
	if len(plan.Blockers) != 0 || len(plan.PreviewWrites) != 0 || len(plan.PreviewExternalEffects) != 0 ||
		len(plan.ExecuteWrites) == 0 || len(plan.ExecuteExternalEffects) != 0 || len(plan.RecoverySteps) == 0 ||
		len(plan.VerificationSteps) == 0 || len(plan.CLIArgv) == 0 || plan.TokenDataHandling == "" {
		t.Fatalf("F38 preview omitted lifecycle or zero-effect evidence: %+v", plan)
	}
	var tokenRowsAfterPreview, idempotencyRowsAfterPreview int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT
		   (SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject = $2),
		   (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1)`,
		h.tenant, subject).Scan(&tokenRowsAfterPreview, &idempotencyRowsAfterPreview); err != nil {
		t.Fatalf("read F38 preview effects: %v", err)
	}
	if tokenRowsAfterPreview != tokenRowsBefore || idempotencyRowsAfterPreview != idempotencyRowsBefore {
		t.Fatalf("F38 preview changed state: tokens %d -> %d, idempotency %d -> %d",
			tokenRowsBefore, tokenRowsAfterPreview, idempotencyRowsBefore, idempotencyRowsAfterPreview)
	}
	if eventHeadAfter, err := h.log.LastSequence(t.Context()); err != nil || eventHeadAfter != eventHeadBefore {
		t.Fatalf("F38 preview event head = (%d, %v), want %d", eventHeadAfter, err, eventHeadBefore)
	}

	status, repeated := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys/preview", admin, "", request)
	if status != http.StatusOK || !bytes.Contains(repeated, []byte(plan.RequestFingerprint)) {
		t.Fatalf("identical F38 preview was not stable: %d %s", status, repeated)
	}
	changed := map[string]any{"subject": subject, "scopes": []string{"access:read"}, "ttl_seconds": 301}
	status, changedRaw := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys/preview", admin, "", changed)
	if status != http.StatusOK || bytes.Contains(changedRaw, []byte(plan.RequestFingerprint)) {
		t.Fatalf("changed F38 TTL did not invalidate preview: %d %s", status, changedRaw)
	}

	// A holder of access:write cannot mint authority it does not itself possess.
	escalation := map[string]any{"subject": subject, "scopes": []string{"certs:read"}, "ttl_seconds": 300}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys/preview", admin, "", escalation)
	if status != http.StatusForbidden || bytes.Contains(raw, []byte(h.tenant)) {
		t.Fatalf("F38 preview did not refuse scope escalation safely: %d %s", status, raw)
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys", admin, "f38-escalation", escalation)
	if status != http.StatusForbidden {
		t.Fatalf("F38 execution did not refuse scope escalation: %d %s", status, raw)
	}

	stale := map[string]any{
		"subject": subject, "scopes": []string{"access:read"}, "ttl_seconds": 301,
		"preview_fingerprint": plan.RequestFingerprint,
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys", admin, "f38-stale-review", stale)
	if status != http.StatusConflict || bytes.Contains(raw, []byte(plan.RequestFingerprint)) {
		t.Fatalf("F38 stale review did not fail closed: %d %s", status, raw)
	}

	reviewed := map[string]any{
		"subject": subject, "scopes": []string{"access:read"}, "ttl_seconds": 300,
		"preview_fingerprint": plan.RequestFingerprint,
	}
	status, created := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys", admin, "f38-reviewed-issue", reviewed)
	if status != http.StatusCreated {
		t.Fatalf("reviewed F38 issue = %d, want 201: %s", status, created)
	}
	status, recovered := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys", admin, "f38-reviewed-issue", reviewed)
	if status != http.StatusCreated || !bytes.Equal(created, recovered) {
		t.Fatalf("F38 same-key recovery changed result: %d %s", status, recovered)
	}
	var issued struct {
		ID        string     `json:"id"`
		Subject   string     `json:"subject"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
		Token     string     `json:"token"`
	}
	if err := json.Unmarshal(created, &issued); err != nil || issued.ID == "" || issued.Subject != subject ||
		!slices.Equal(issued.Scopes, []string{"access:read"}) || issued.ExpiresAt == nil || !strings.HasPrefix(issued.Token, auth.TokenPrefix) {
		t.Fatalf("decode reviewed F38 issue: %+v err=%v body=%s", issued, err, created)
	}
	if h.logContains(t, issued.Token) {
		t.Fatal("F38 raw bearer reached the event log")
	}

	conflict := map[string]any{
		"subject": subject + "-changed", "scopes": []string{"access:read"}, "ttl_seconds": 300,
		"preview_fingerprint": plan.RequestFingerprint,
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/api-keys", admin, "f38-reviewed-issue", conflict)
	if status != http.StatusConflict {
		t.Fatalf("F38 changed-body retry = %d, want 409: %s", status, raw)
	}
	var issuedRows int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject = $2`, h.tenant, subject).Scan(&issuedRows); err != nil {
		t.Fatalf("count reviewed F38 rows: %v", err)
	}
	if issuedRows != 1 {
		t.Fatalf("reviewed F38 issue rows = %d, want exactly 1", issuedRows)
	}

	status, raw = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", issued.Token, "", nil)
	if status != http.StatusOK || bytes.Contains(raw, []byte(issued.Token)) {
		t.Fatalf("fresh F38 bearer did not authorize its exact access:read route: %d %s", status, raw)
	}
	status, listed := doBearer(t, h.ts, http.MethodGet,
		"/api/v1/access/api-tokens?subject="+subject+"&include_revoked=true", admin, "", nil)
	if status != http.StatusOK || !bytes.Contains(listed, []byte(issued.ID)) || bytes.Contains(listed, []byte(issued.Token)) {
		t.Fatalf("F38 metadata ledger did not observe issued key safely: %d %s", status, listed)
	}
	status, raw = doBearer(t, h.ts, http.MethodDelete, "/api/v1/access/api-tokens/"+issued.ID, admin, "f38-revoke", map[string]string{
		"reason": "reviewed F38 qualification cleanup",
	})
	if status != http.StatusNoContent {
		t.Fatalf("revoke reviewed F38 key = %d, want 204: %s", status, raw)
	}
	status, raw = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", issued.Token, "", nil)
	if status != http.StatusUnauthorized || bytes.Contains(raw, []byte(issued.Token)) {
		t.Fatalf("revoked F38 bearer remained usable or leaked: %d %s", status, raw)
	}
}

type servedEphemeralAttestor struct{}

func (servedEphemeralAttestor) Method() string { return "stub_ephemeral" }

func (servedEphemeralAttestor) Attest(_ context.Context, p []byte) (attest.Attestation, error) {
	if string(p) != "genuine" {
		return attest.Attestation{}, errServedEphemeralForgery
	}
	return attest.Attestation{
		Method:    "stub_ephemeral",
		Subject:   "jit-agent-7",
		Selectors: []string{"jit:test"},
	}, nil
}

var errServedEphemeralForgery = errors.New("forged ephemeral proof")

type countingEphemeralDigestSigner struct {
	crypto.DigestSigner
	calls atomic.Int32
}

func (s *countingEphemeralDigestSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	s.calls.Add(1)
	return s.DigestSigner.SignDigest(digest, opts)
}

type servedEphemeralResponse struct {
	State             string             `json:"state"`
	RequestID         string             `json:"request_id"`
	ApprovalRequestID string             `json:"approval_request_id"`
	IntentDigest      string             `json:"intent_digest"`
	Subject           string             `json:"subject"`
	CredentialID      string             `json:"credential_id"`
	CertificateID     string             `json:"certificate_id"`
	CertificatePEM    string             `json:"certificate_pem"`
	SPIFFEID          string             `json:"spiffe_id"`
	RequiredApprovals int                `json:"required_approvals"`
	Approvals         int                `json:"approvals"`
	ExpiresAt         time.Time          `json:"expires_at"`
	NotAfter          time.Time          `json:"not_after"`
	Attestation       attest.Attestation `json:"attestation"`
}

type servedEphemeralApprovalResponse struct {
	ID                string `json:"id"`
	IntentDigest      string `json:"intent_digest"`
	Resource          string `json:"resource"`
	Action            string `json:"action"`
	Approver          string `json:"approver"`
	Approvals         int    `json:"approvals"`
	ApprovalCount     int    `json:"approval_count"`
	RequiredApprovals int    `json:"required_approvals"`
	Status            string `json:"status"`
}

type ephemeralPreviewDurableState struct {
	Requests     int
	Decisions    int
	Idempotency  int
	Outbox       int
	Certificates int
}

func ephemeralPreviewMutationState(t *testing.T, h *servedHarness) ephemeralPreviewDurableState {
	t.Helper()
	var state ephemeralPreviewDurableState
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT
			  (SELECT count(*) FROM operation_approval_requests WHERE tenant_id = $1),
			  (SELECT count(*) FROM operation_approval_decisions WHERE tenant_id = $1),
			  (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1),
			  (SELECT count(*) FROM outbox WHERE tenant_id = $1),
			  (SELECT count(*) FROM certificates WHERE tenant_id = $1)
		`, h.tenant).Scan(&state.Requests, &state.Decisions, &state.Idempotency, &state.Outbox, &state.Certificates)
	})
	if err != nil {
		t.Fatalf("read ephemeral preview durable state: %v", err)
	}
	return state
}

func servedEphemeralIssue(t *testing.T, h *servedHarness, token, idemKey string, req map[string]any, want int) servedEphemeralResponse {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral", token, idemKey, req)
	if status != want {
		t.Fatalf("ephemeral issue status = %d, want %d; body=%s", status, want, body)
	}
	var out servedEphemeralResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode ephemeral response: %v; body=%s", err, body)
	}
	return out
}

func servedEphemeralApprove(t *testing.T, h *servedHarness, token, idemKey, requestID, intentDigest string, want int) servedEphemeralApprovalResponse {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/"+requestID+"/approvals", token, idemKey, map[string]any{
		"action": "issue", "request_id": requestID, "intent_digest": intentDigest,
	})
	if status != want {
		t.Fatalf("ephemeral approve status = %d, want %d; body=%s", status, want, body)
	}
	var out servedEphemeralApprovalResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode ephemeral approval response: %v; body=%s", err, body)
	}
	return out
}

func ephemeralApprovalOutboxCount(t *testing.T, h *servedHarness, key string) int {
	t.Helper()
	var count int
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT count(*)
			FROM outbox
			WHERE destination = $2
			  AND idempotency_key = $1
		`, key, notify.DestinationApproval).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count ephemeral.approval outbox rows: %v", err)
	}
	return count
}

func ephemeralApprovalRefusalState(t *testing.T, h *servedHarness, idempotencyKey string) (requests, decisions, idempotency int) {
	t.Helper()
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT
			  (SELECT count(*) FROM operation_approval_requests WHERE tenant_id = $1)
			    + (SELECT count(*) FROM issuance_approval_requests WHERE tenant_id = $1),
			  (SELECT count(*) FROM operation_approval_decisions WHERE tenant_id = $1)
			    + (SELECT count(*) FROM issuance_approvals WHERE tenant_id = $1),
			  (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1 AND key = $2)
		`, h.tenant, idempotencyKey).Scan(&requests, &decisions, &idempotency)
	})
	if err != nil {
		t.Fatalf("count ephemeral approval refusal state: %v", err)
	}
	return requests, decisions, idempotency
}

func legacyEphemeralApprovalRequestCount(t *testing.T, h *servedHarness, resource string) int {
	t.Helper()
	var count int
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT count(*) FROM issuance_approval_requests
			 WHERE tenant_id = $1 AND resource = $2 AND action = 'issue'
		`, h.tenant, resource).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count legacy ephemeral approval requests: %v", err)
	}
	return count
}

func seedScopedTokenSubject(t *testing.T, st *store.Store, tenant, subject string, scopes ...string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if _, err := st.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: tenant, TokenHash: hash, Subject: subject, Scopes: scopes,
	}); err != nil {
		t.Fatalf("seed api token: %v", err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
}
