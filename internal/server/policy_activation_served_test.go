package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestServedPolicyVersionActivationAndRollbackTRACE006(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnablePolicyGate = true
		d.DefaultProfile = "tls-server"
	})
	policyTok := seedScopedTokenSubject(t, h.store, h.tenant, "policy-author@example.test", "policy:read", "policy:write")
	issuerTok := seedScopedTokenSubject(t, h.store, h.tenant, "issuer@example.test", "owners:write", "identities:write", "certs:issue")

	owner, err := h.store.CreateOwner(context.Background(), store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "payments"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	firstIdentity := createPolicyActivationIdentity(t, h, issuerTok, owner.ID, "trace-006-before")
	if status, body := transitionPolicyActivationIdentity(t, h, issuerTok, firstIdentity, "trace-006-before-issue"); status != http.StatusOK {
		t.Fatalf("issue before live activation = %d, want 200 from boot policy; body=%s", status, body)
	}

	createBody := map[string]any{
		"kind":          "lifecycle",
		"description":   "Deny issue during emergency change freeze",
		"change_ref":    "github:security/policy-freeze#42",
		"evidence_refs": []string{"pr:policy-freeze-42", "cab:2026-07-02"},
		"module": `package trstctl.policy

default allow := false
default reason := "change freeze blocks issuance"

allow if {
	input.action == "revoke"
}
`,
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions", policyTok, "trace-006-policy-create", createBody)
	if status != http.StatusCreated {
		t.Fatalf("create policy version = %d, want 201; body=%s", status, raw)
	}
	var created struct {
		ID           string   `json:"id"`
		Kind         string   `json:"kind"`
		Status       string   `json:"status"`
		ModuleSHA256 string   `json:"module_sha256"`
		AuditEvent   string   `json:"audit_event"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decode created policy version: %v body=%s", err, raw)
	}
	if created.ID == "" || created.Kind != "lifecycle" || created.Status != "draft" || created.ModuleSHA256 == "" || created.AuditEvent != "policy.version.authored" || len(created.EvidenceRefs) != 2 {
		t.Fatalf("created policy version = %+v, want draft lifecycle version with audit/evidence", created)
	}

	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions/"+created.ID+"/activate", policyTok, "trace-006-policy-activate", map[string]any{
		"reason":        "CAB approved emergency freeze",
		"evidence_refs": []string{"cab:2026-07-02"},
	})
	if status != http.StatusOK {
		t.Fatalf("activate policy version = %d, want 200; body=%s", status, raw)
	}
	var activated struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		Active     bool   `json:"active"`
		AuditEvent string `json:"audit_event"`
	}
	if err := json.Unmarshal(raw, &activated); err != nil {
		t.Fatalf("decode activated policy version: %v body=%s", err, raw)
	}
	if activated.ID != created.ID || activated.Status != "active" || !activated.Active || activated.AuditEvent != "policy.version.activated" {
		t.Fatalf("activated policy version = %+v, want active version with audit event", activated)
	}

	blockedIdentity := createPolicyActivationIdentity(t, h, issuerTok, owner.ID, "trace-006-blocked")
	if status, body := transitionPolicyActivationIdentity(t, h, issuerTok, blockedIdentity, "trace-006-blocked-issue"); status != http.StatusForbidden || !bytes.Contains(body, []byte("change freeze blocks issuance")) {
		t.Fatalf("issue after deny policy activation = %d body=%s, want 403 policy denial", status, body)
	}

	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions/"+created.ID+"/rollback", policyTok, "trace-006-policy-rollback", map[string]any{
		"reason":        "freeze lifted after CAB review",
		"evidence_refs": []string{"cab:2026-07-02-closeout"},
	})
	if status != http.StatusOK {
		t.Fatalf("rollback policy version = %d, want 200; body=%s", status, raw)
	}
	var rolledBack struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		Active         bool   `json:"active"`
		RollbackToID   string `json:"rollback_to_id"`
		RollbackFromID string `json:"rollback_from_id"`
		AuditEvent     string `json:"audit_event"`
	}
	if err := json.Unmarshal(raw, &rolledBack); err != nil {
		t.Fatalf("decode rolled-back policy version: %v body=%s", err, raw)
	}
	if rolledBack.Status != "rolled_back" || rolledBack.Active || rolledBack.RollbackToID == "" || rolledBack.RollbackFromID != created.ID || rolledBack.AuditEvent != "policy.version.rolled_back" {
		t.Fatalf("rollback response = %+v, want inactive rolled-back version and replacement target", rolledBack)
	}

	afterRollbackIdentity := createPolicyActivationIdentity(t, h, issuerTok, owner.ID, "trace-006-after-rollback")
	if status, body := transitionPolicyActivationIdentity(t, h, issuerTok, afterRollbackIdentity, "trace-006-after-rollback-issue"); status != http.StatusOK {
		t.Fatalf("issue after policy rollback = %d, want 200 from restored base policy; body=%s", status, body)
	}

	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/policy/versions", policyTok, nil)
	if status != http.StatusOK {
		t.Fatalf("list policy versions = %d, want 200; body=%s", status, raw)
	}
	if !bytes.Contains(raw, []byte(created.ID)) || !bytes.Contains(raw, []byte(rolledBack.RollbackToID)) {
		t.Fatalf("policy version list did not include created and rollback versions: %s", raw)
	}
	for _, eventType := range []string{"policy.version.authored", "policy.version.activated", "policy.version.rolled_back", "policy.decision"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event for served policy activation workflow", eventType)
		}
	}
}

func createPolicyActivationIdentity(t *testing.T, h *servedHarness, token, ownerID, name string) string {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", token, "identity-"+name, map[string]any{
		"kind": "x509_certificate", "name": name + ".example.test", "owner_id": ownerID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity %s = %d, want 201; body=%s", name, status, body)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil || strings.TrimSpace(got.ID) == "" {
		t.Fatalf("decode identity %s: id=%q err=%v body=%s", name, got.ID, err, body)
	}
	return got.ID
}

func transitionPolicyActivationIdentity(t *testing.T, h *servedHarness, token, identityID, idem string) (int, []byte) {
	t.Helper()
	return secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", token, idem, map[string]string{
		"to": "issued", "reason": "TRACE-006 policy activation acceptance",
	})
}
