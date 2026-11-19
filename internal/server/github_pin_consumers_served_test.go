// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedGitHubPinConsumersRequireCurrentTrust(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	const kid = "shared-workload-trust"
	jwk, err := crypto.PublicJWK(key.Public(), kid)
	if err != nil {
		t.Fatal(err)
	}
	jwks := crypto.JWKS{Keys: []crypto.JWK{jwk}}
	rawJWKS, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
		d.EphemeralIssuance = EphemeralIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 2 * time.Minute,
			MaxTTL: 5 * time.Minute, ApprovalTTL: time.Minute, RequiredApprovals: 1,
		}
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy}
		d.PAM = PAMConfig{Enabled: true, MaxTTL: time.Minute, SSHTargets: []PAMSSHTarget{{
			TenantID: servedTestTenant, ID: "workflow-ssh", Host: "lab.example.test", Port: 22, Principals: []string{"acme"},
		}}}
	})
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "workflow-operator", "certs:issue", "certs:read")
	const requesterSubject = "workflow-requester"
	requester := seedScopedTokenSubject(t, h.store, h.tenant, requesterSubject, "certs:request", "certs:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "workflow-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "workflow-reviewer-two", "access:approve")
	good := githubWorkflowAttemptToken(t, key, kid, "acme", "38461", "1")
	outsidePolicy := githubWorkflowAttemptTokenWithIDs(t, key, kid, "acme", "38462", "1", servedGitHubOwnerID, "789")
	payload := base64.StdEncoding.EncodeToString(good)
	public := servedAttestedPublicKeyPEM(t)
	sources := map[string]any{
		"name": "workflow-github", "method": "github_oidc", "audience": "trstctl", "jwks": jwks,
		"allowed_owners": []string{"acme"}, "allowed_owner_ids": []string{servedGitHubOwnerID}, "allowed_repository_ids": []string{"456"},
	}
	const legacyID = "00000000-0000-4000-8000-000000038461"
	legacy, err := json.Marshal(projections.WorkloadAttesterTrustSourceUpserted{
		ID: legacyID, Name: "previous-owner-name", Method: "github_oidc", Audience: "trstctl", JWKS: rawJWKS,
		AllowedOwners: []string{"acme"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{
		Type: projections.EventWorkloadAttesterTrustSourceUpserted, TenantID: h.tenant, Data: legacy,
	}); err != nil {
		t.Fatal(err)
	}
	catchUpServedProjection(t, h)

	ordinary := map[string]any{"method": "github_oidc", "payload_base64": payload, "public_key_pem": public, "ttl_seconds": 600}
	ephemeral := map[string]any{"method": "github_oidc", "payload_base64": payload, "public_key_pem": public, "ttl_seconds": 120, "request_id": "workflow-ephemeral"}
	broker := map[string]any{"method": "github_oidc", "payload_base64": payload, "public_key_pem": public, "ttl_seconds": 120,
		"agent_id": "agent-7", "scopes": []string{"tool:inventory.read"}}
	sshPublic := genSSHKey(t, filepath.Join(t.TempDir(), "workflow-key"))
	ssh := map[string]any{"method": "github_oidc", "payload_base64": payload, "public_key": string(sshPublic), "principals": []string{"acme"}, "ttl_seconds": 120}
	access := map[string]any{"method": "github_oidc", "payload_base64": payload, "ssh_public_key": string(sshPublic), "request_id": "00000000-0000-4000-8000-000000038462",
		"target_type": "ssh", "target_id": "workflow-ssh", "ssh_principal": "acme", "role": "user", "ttl_seconds": 30}
	assertPreviews := func(ready bool) {
		t.Helper()
		for _, surface := range []struct {
			path, token string
			body        map[string]any
		}{
			{"/api/v1/workloads/attested-issuance/preview", operator, ordinary},
			{"/api/v1/ephemeral/preview", requester, ephemeral},
			{"/api/v1/broker/agent-identities/preview", operator, broker},
			{"/api/v1/ssh/attested-user-certs/preview", operator, ssh},
		} {
			status, raw := secretsReqKey(t, h, http.MethodPost, surface.path, surface.token, "", surface.body)
			var view struct {
				Ready            bool     `json:"ready"`
				SupportedMethods []string `json:"supported_methods"`
			}
			if status != http.StatusOK || json.Unmarshal(raw, &view) != nil || view.Ready != ready ||
				slices.Contains(view.SupportedMethods, "github_oidc") != ready {
				t.Errorf("%s: status=%d preview=%s, want ready=%t with matching method availability", surface.path, status, raw, ready)
			}
		}
	}
	assertPreviews(false)
	if t.Failed() {
		return
	}

	// The proof bytes retain the signed IDs across the upgrade. Before the
	// upgrade the verifier did not expose them in its attestation evidence.
	legacyAttestors := []attest.Attestor{legacyGitHubEvidence{&githuboidc.Attestor{JWKS: jwks, Audience: "trstctl"}}}
	oldEphemeral := *h.srv.ephemeralIssuer
	oldEphemeral.attestors = legacyAttestors
	publicKey, err := crypto.ParsePublicKeyPEM([]byte(public))
	if err != nil {
		t.Fatal(err)
	}
	oldRequest, err := oldEphemeral.IssueEphemeralCredential(t.Context(), h.tenant, "legacy-ephemeral-request", requesterSubject,
		api.EphemeralCredentialRequest{
			RequestID: "workflow-ephemeral", Method: "github_oidc", Payload: good, PublicKeyDER: publicKey.DER, TTLSeconds: 120,
		})
	if err != nil || oldRequest.State != api.EphemeralStateAwaitingApproval {
		t.Fatalf("record prior ephemeral review: %v", err)
	}
	servedEphemeralApprove(t, h, operator, "legacy-ephemeral-review", oldRequest.ApprovalRequestID, oldRequest.IntentDigest, http.StatusOK)

	oldPAM := *h.srv.pam
	oldPAM.attestors = legacyAttestors
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: requesterSubject})
	oldAccess, err := oldPAM.RequestPAMSession(ctx, h.tenant, requesterSubject, api.PAMSessionRequest{
		RequestID: access["request_id"].(string), TargetType: "ssh", TargetID: "workflow-ssh", Role: "user",
		Method: "github_oidc", Payload: good, SSHPublicKey: sshPublic, SSHPrincipal: "acme", TTLSeconds: 30,
	})
	if err != nil || oldAccess.ApprovalRequestID == "" {
		t.Fatalf("record prior PAM review: %v", err)
	}
	for i, reviewer := range []string{reviewerOne, reviewerTwo} {
		status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+oldAccess.ApprovalRequestID+"/approvals",
			reviewer, fmt.Sprintf("legacy-pam-approval-%d", i+1), map[string]any{"intent_digest": oldAccess.IntentDigest})
		if status != http.StatusOK {
			t.Fatalf("prior PAM review %d: %d", i+1, status)
		}
	}

	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", operator, "workflow-immutable-trust", sources)
	if status != http.StatusCreated {
		t.Fatalf("configure immutable GitHub trust: %d", status)
	}
	assertPreviews(true)
	if t.Failed() {
		return
	}

	outsidePayload := base64.StdEncoding.EncodeToString(outsidePolicy)
	for _, surface := range []struct {
		path, token, key string
		body             map[string]any
	}{
		{"/api/v1/workloads/attested-issuance", operator, "ordinary-policy-check", ordinary},
		{"/api/v1/ephemeral", requester, "ephemeral-policy-check", ephemeral},
		{"/api/v1/broker/agent-identities", operator, "broker-policy-check", broker},
		{"/api/v1/ssh/attested-user-certs", operator, "ssh-policy-check", ssh},
		{"/api/v1/access/session-requests", requester, "pam-policy-check", access},
	} {
		surface.body["payload_base64"] = outsidePayload
		status, raw := secretsReqKey(t, h, http.MethodPost, surface.path, surface.token, surface.key, surface.body)
		surface.body["payload_base64"] = payload
		if status != http.StatusForbidden {
			t.Errorf("%s must refuse evidence outside its current pin policy, got %d %s", surface.path, status, raw)
		}
	}
	if servedCertificateCountAUD47(t, h) != 0 || h.hasEvent(t, "ssh.attested_cert.issued") || h.hasEvent(t, "pam.session.started") {
		t.Fatal("authorization refusals caused issuance")
	}
	access["approval_request_id"], access["intent_digest"] = oldAccess.ApprovalRequestID, oldAccess.IntentDigest
	access["payload_base64"] = outsidePayload
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester, "pam-activation-policy-check", access)
	access["payload_base64"] = payload
	if status != http.StatusForbidden || !strings.Contains(string(raw), "repository ID did not match") || h.hasEvent(t, "pam.session.started") {
		t.Fatalf("PAM activation failed to recheck the current pin policy before consuming its prior approval: %d %s", status, raw)
	}

	servedAttestedIssue(t, h, operator, "ordinary-workflow", "github_oidc", good, public, http.StatusCreated)
	if issued := servedEphemeralIssue(t, h, requester, "ephemeral-workflow-issue", ephemeral, http.StatusCreated); issued.State != api.EphemeralStateIssued || issued.ApprovalRequestID != oldRequest.ApprovalRequestID {
		t.Fatal("the verified workflow did not receive its ephemeral credential from the prior review")
	}
	servedBrokerIssue(t, h, operator, "broker-workflow", broker, http.StatusCreated)
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/attested-user-certs", operator, "ssh-workflow", ssh)
	if status != http.StatusCreated || !h.hasEvent(t, "ssh.attested_cert.issued") {
		t.Fatalf("configured workflow did not receive its SSH certificate: %d", status)
	}
	if session := servedPAMOpen(t, h, requester, "pam-workflow", access); session.SSH == nil {
		t.Fatal("verified workflow did not receive its SSH access from the prior PAM review")
	}
}

type legacyGitHubEvidence struct{ attest.Attestor }

func (a legacyGitHubEvidence) Attest(ctx context.Context, proof []byte) (attest.Attestation, error) {
	verified, err := a.Attestor.Attest(ctx, proof)
	if err != nil {
		return attest.Attestation{}, err
	}
	delete(verified.Claims, "repository_owner_id")
	delete(verified.Claims, "repository_id")
	verified.Selectors = slices.DeleteFunc(verified.Selectors, func(selector string) bool {
		return strings.HasPrefix(selector, "github:repository_owner_id:") || strings.HasPrefix(selector, "github:repository_id:")
	})
	return verified, nil
}
