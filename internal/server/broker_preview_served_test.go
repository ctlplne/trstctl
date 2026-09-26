// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
)

func TestServedBrokerPreviewIsExactEffectFreeAndNeverVerifiesTaskOrProof(t *testing.T) {
	attestor := &countingAttestedPreviewAttestor{}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute,
			MaxTTL: time.Hour, PolicyModule: servedBrokerAllowPolicy, Attestors: []attest.Attestor{attestor}}
	})
	owner := seedScopedTokenSubject(t, h.store, h.tenant, "broker-preview-owner", "certs:issue", "certs:read")
	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	signer := &countingEphemeralDigestSigner{DigestSigner: h.srv.agentBroker.caSigner}
	h.srv.agentBroker.caSigner = signer
	body := map[string]any{"agent_id": "agent-7", "method": "k8s_sat", "payload_base64": "b25lLXRpbWUtcHJvb2Y=",
		"public_key_pem": servedAttestedPublicKeyPEM(t), "scopes": []string{"tool:inventory.read"}, "ttl_seconds": int64(math.MaxInt64)}
	headBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stateBefore := ephemeralPreviewMutationState(t, h)
	var preview struct {
		Ready                    bool     `json:"ready"`
		EffectFree               bool     `json:"effect_free"`
		AgentID                  string   `json:"agent_id"`
		Requester                string   `json:"requester"`
		EffectiveTTLSeconds      int64    `json:"effective_ttl_seconds"`
		TTLClamped               bool     `json:"ttl_clamped"`
		PayloadSHA256            string   `json:"payload_sha256"`
		TaskEnvelopeSHA256       string   `json:"task_envelope_sha256"`
		AttestationVerification  string   `json:"attestation_verification"`
		PolicyEvaluation         string   `json:"policy_evaluation"`
		TaskEnvelopeVerification string   `json:"task_envelope_verification"`
		PreviewWrites            []string `json:"preview_writes"`
		PreviewExternalEffects   []string `json:"preview_external_effects"`
		PreviewSignerCalls       []string `json:"preview_signer_calls"`
		Blockers                 []string `json:"blockers"`
		RecoverySteps            []string `json:"recovery_steps"`
	}
	for _, withEnvelope := range []bool{false, true} {
		if withEnvelope {
			body["task_envelope_base64"] = "b25lLXRpbWUtdGFzaw=="
		}
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/broker/agent-identities/preview", owner, "", body)
		if status != http.StatusOK || json.Unmarshal(raw, &preview) != nil {
			t.Fatalf("broker preview status=%d body=%s", status, raw)
		}
		if preview.Ready == withEnvelope || !preview.EffectFree || preview.AgentID != "agent-7" || preview.Requester != "broker-preview-owner" ||
			preview.EffectiveTTLSeconds != 3600 || !preview.TTLClamped || preview.PayloadSHA256 != crypto.SHA256Hex([]byte("one-time-proof")) ||
			preview.AttestationVerification != "execution_only" || preview.PolicyEvaluation != "execution_only" ||
			len(preview.PreviewWrites) != 0 || len(preview.PreviewExternalEffects) != 0 || len(preview.PreviewSignerCalls) != 0 || len(preview.RecoverySteps) == 0 {
			t.Fatalf("incorrect or incomplete broker preview: %+v", preview)
		}
		if withEnvelope && (preview.TaskEnvelopeSHA256 != crypto.SHA256Hex([]byte("one-time-task")) || preview.TaskEnvelopeVerification != "unavailable" || len(preview.Blockers) == 0) {
			t.Fatalf("missing licensed task gate did not block preview: %+v", preview)
		}
		for _, proof := range []string{"one-time-proof", "one-time-task"} {
			encoded := base64.StdEncoding.EncodeToString([]byte(proof))
			if bytes.Contains(raw, []byte(proof)) || bytes.Contains(raw, []byte(encoded)) {
				t.Fatal("preview returned raw or encoded proof")
			}
		}
		if bytes.Contains(raw, []byte("BEGIN PUBLIC KEY")) {
			t.Fatal("preview returned the public key body instead of its fingerprint")
		}
	}

	delete(body, "task_envelope_base64")
	body["method"] = "aws_iid"
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/broker/agent-identities/preview", owner, "", body)
	if status != http.StatusOK || json.Unmarshal(raw, &preview) != nil || preview.Ready || len(preview.Blockers) == 0 {
		t.Fatalf("unconfigured tenant method not blocked: status=%d body=%s", status, raw)
	}
	// An attached gate is still execution-only. A preview must not consume a
	// one-use task envelope just because this process has its verifier wired.
	var gateCalls atomic.Int32
	h.srv.agentBroker.taskEnvelopeGate = func(context.Context, string, []byte, time.Time) ([]byte, error) {
		gateCalls.Add(1)
		return nil, context.Canceled
	}
	body["method"] = "k8s_sat"
	body["task_envelope_base64"] = base64.StdEncoding.EncodeToString([]byte("one-time-task"))
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/broker/agent-identities/preview", owner, "", body)
	if status != http.StatusOK || json.Unmarshal(raw, &preview) != nil || !preview.Ready ||
		preview.TaskEnvelopeVerification != "execution_only" || gateCalls.Load() != 0 {
		t.Fatal("configured task gate was consumed or misrepresented during preview")
	}
	h.srv.agentBroker.taskEnvelopeGate = nil
	delete(body, "task_envelope_base64")
	if signer.calls.Load() != 0 || attestor.calls.Load() != 0 {
		t.Fatal("preview consumed proof or called signer")
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != headBefore {
		t.Fatal("preview appended events")
	}
	if ephemeralPreviewMutationState(t, h) != stateBefore {
		t.Fatal("preview mutated durable state")
	}
	// Actual previews above remain effect-free. Authentication/permission
	// refusals below never enter the preview and produce only the expected audit.
	for token, want := range map[string]int{reader: http.StatusForbidden, "": http.StatusUnauthorized} {
		status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/broker/agent-identities/preview", token, "", body)
		if status != want {
			t.Fatalf("preview permission status=%d want=%d", status, want)
		}
	}
	assertBrokerDenialAuditOnly(t, h, headBefore, "certs:issue", "POST /api/v1/broker/agent-identities/preview")
	if ephemeralPreviewMutationState(t, h) != stateBefore || signer.calls.Load() != 0 || attestor.calls.Load() != 0 || gateCalls.Load() != 0 {
		t.Fatal("permission refusal had preview, proof or signer effects")
	}
	body["method"] = "k8s_sat"
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/broker/agent-identities", owner, "broker-invalid-proof", body)
	if status != http.StatusForbidden || attestor.calls.Load() != 1 || signer.calls.Load() != 0 {
		t.Fatal("preview readiness bypassed proof verification")
	}
}

func TestServedBrokerTenantTrustRotationRevocationAndRequesterCustody(t *testing.T) {
	first := servedDynamicK8sTrustFixture(t, "broker-tenant-k1")
	rotated := servedDynamicK8sTrustFixture(t, "broker-tenant-k2")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy}
	})
	owner := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")
	const otherTenant = "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h, otherTenant, "Broker neighbor")
	neighbor := seedScopedToken(t, h.store, otherTenant, "certs:issue", "certs:read")
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", owner, "broker-tenant-trust", map[string]any{
		"name": "broker-k8s", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": first.JWKS,
	})
	var source servedWorkloadTrustSourceResponse
	if status != http.StatusCreated || json.Unmarshal(raw, &source) != nil {
		t.Fatalf("create tenant trust: status=%d body=%s", status, raw)
	}
	body := map[string]any{"agent_id": "agent-7", "method": "k8s_sat", "payload_base64": base64.StdEncoding.EncodeToString([]byte(first.SAT)),
		"public_key_pem": servedAttestedPublicKeyPEM(t), "scopes": []string{"tool:inventory.read"}, "ttl_seconds": 120}
	servedBrokerIssue(t, h, neighbor, "broker-tenant-isolation", body, http.StatusUnprocessableEntity)
	issued := servedBrokerIssue(t, h, owner, "broker-tenant-issue", body, http.StatusCreated)
	if issued.Subject != "ns/default/sa/web" {
		t.Fatal("broker ignored verified Kubernetes identity")
	}
	cert, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyOrigin != string(custody.OriginRequester) || cert.KeyStorage != "" || cert.KeyExportable != "" {
		t.Fatal("broker did not record honest requester-only key custody")
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources/"+source.ID+"/rotate", owner, "broker-trust-rotate", map[string]any{
		"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": rotated.JWKS, "reason": "rotate cluster public trust",
	})
	if status != http.StatusOK {
		t.Fatalf("rotate trust status=%d body=%s", status, raw)
	}
	servedBrokerIssue(t, h, owner, "broker-old-proof-after-rotation", body, http.StatusForbidden)
	body["payload_base64"] = base64.StdEncoding.EncodeToString([]byte(rotated.SAT))
	servedBrokerIssue(t, h, owner, "broker-rotated-proof", body, http.StatusCreated)
	body["payload_base64"] = base64.StdEncoding.EncodeToString([]byte(rotated.ExpiredSAT))
	servedBrokerIssue(t, h, owner, "broker-expired-proof", body, http.StatusForbidden)
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources/"+source.ID+"/revoke", owner, "broker-trust-revoke", map[string]any{"reason": "offboard workload"})
	if status != http.StatusOK {
		t.Fatalf("revoke trust status=%d body=%s", status, raw)
	}
	body["payload_base64"] = base64.StdEncoding.EncodeToString([]byte(rotated.SAT))
	servedBrokerIssue(t, h, owner, "broker-revoked-trust", body, http.StatusUnprocessableEntity)
	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+issued.CertificateID, owner, nil)
	if status != http.StatusOK || !strings.Contains(string(raw), `"key_origin":"requester"`) {
		t.Fatal("broker custody not exposed through shared certificate inventory")
	}
}
