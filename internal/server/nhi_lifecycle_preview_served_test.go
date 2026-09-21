// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestServedNHILifecyclePlanIsEffectFreeVersionBoundAndVerifiable is the F59
// operator oracle. The console must be able to explain one exact lifecycle
// action before it changes anything, reject a plan reviewed against old state,
// and return enough durable evidence to prove what happened afterward.
func TestServedNHILifecyclePlanIsEffectFreeVersionBoundAndVerifiable(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "F59 lifecycle-plan tenant")
	operator := seedScopedToken(t, h.store, h.tenant,
		"owners:write", "owners:read", "identities:write", "identities:read", "certs:issue")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", operator,
		"f59-owner", map[string]any{"kind": "workload", "name": "Payments platform"})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil || owner.ID == "" {
		t.Fatalf("decode owner: err=%v body=%s", err, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", operator,
		"f59-identity", map[string]any{
			"kind": "x509_certificate", "name": "payments-api", "owner_id": owner.ID,
		})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var identity struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &identity); err != nil || identity.ID == "" || identity.Status != "requested" {
		t.Fatalf("decode requested identity: err=%v identity=%+v body=%s", err, identity, body)
	}

	beforePreview, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"to": "issued", "reason": "approved change CHG-5901"}
	path := "/api/v1/identities/" + identity.ID + "/transitions"
	status, body = secretsReq(t, h, http.MethodPost, path+"/preview", operator, request)
	if status != http.StatusOK {
		t.Fatalf("lifecycle preview: status %d body %s", status, body)
	}
	var preview struct {
		Capability             string   `json:"capability"`
		Ready                  bool     `json:"ready"`
		IdentityID             string   `json:"identity_id"`
		IdentityName           string   `json:"identity_name"`
		IdentityKind           string   `json:"identity_kind"`
		OwnerID                string   `json:"owner_id"`
		OwnerName              string   `json:"owner_name"`
		From                   string   `json:"from"`
		To                     string   `json:"to"`
		ExpectedVersion        uint64   `json:"expected_version"`
		EventType              string   `json:"event_type"`
		SideEffect             bool     `json:"side_effect"`
		SideEffectDestination  string   `json:"side_effect_destination"`
		RequiredPermission     string   `json:"required_permission"`
		Prerequisites          []string `json:"prerequisites"`
		ExecutionWrites        []string `json:"execution_writes"`
		ExecutionEffects       []string `json:"execution_external_effects"`
		VerificationSteps      []string `json:"verification_steps"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
		Guidance               string   `json:"guidance"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if !preview.Ready || preview.Capability != "nhi_lifecycle_transition" ||
		preview.IdentityID != identity.ID || preview.IdentityName != "payments-api" ||
		preview.IdentityKind != "x509_certificate" || preview.OwnerID != owner.ID ||
		preview.OwnerName != "Payments platform" || preview.From != "requested" || preview.To != "issued" ||
		preview.ExpectedVersion != 0 || preview.EventType != "identity.issued" ||
		!preview.SideEffect || preview.SideEffectDestination != "ca.issue" ||
		preview.RequiredPermission != "identities:write" {
		t.Fatalf("lifecycle preview identity/effect = %+v", preview)
	}
	if preview.PreviewWrites == nil || len(preview.PreviewWrites) != 0 ||
		preview.PreviewExternalEffects == nil || len(preview.PreviewExternalEffects) != 0 ||
		len(preview.Prerequisites) < 3 || len(preview.ExecutionWrites) < 2 ||
		len(preview.ExecutionEffects) == 0 || len(preview.VerificationSteps) < 2 ||
		!strings.Contains(strings.ToLower(preview.Guidance), "no write") {
		t.Fatalf("lifecycle preview is not explicit and effect-free: %+v", preview)
	}
	if afterPreview, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || afterPreview != beforePreview {
		t.Fatalf("preview event sequence=(%d,%v), want unchanged %d", afterPreview, lastErr, beforePreview)
	}

	// A reviewed version is authority only for that version. Even with the same
	// current state, an impossible version must fail before an event or outbox
	// intent is recorded.
	stale := map[string]any{"to": "issued", "reason": request["reason"], "expected_version": 9}
	status, staleBody := secretsReqKey(t, h, http.MethodPost, path, operator, "f59-stale-plan", stale)
	if status != http.StatusConflict || !strings.Contains(strings.ToLower(string(staleBody)), "preview") {
		t.Fatalf("stale lifecycle plan: status %d body %s, want explanatory 409", status, staleBody)
	}
	if afterStale, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || afterStale != beforePreview {
		t.Fatalf("stale plan event sequence=(%d,%v), want unchanged %d", afterStale, lastErr, beforePreview)
	}

	execute := map[string]any{
		"to": "issued", "reason": request["reason"], "expected_version": preview.ExpectedVersion,
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path, operator, "f59-reviewed-transition", execute)
	if status != http.StatusOK {
		t.Fatalf("execute reviewed lifecycle transition: status %d body %s", status, body)
	}
	var executed struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &executed); err != nil || executed.ID != identity.ID || executed.Status != "issued" {
		t.Fatalf("reviewed transition response: err=%v result=%+v body=%s", err, executed, body)
	}

	status, retryBody := secretsReqKey(t, h, http.MethodPost, path, operator, "f59-reviewed-transition", execute)
	if status != http.StatusOK || string(retryBody) != string(body) {
		t.Fatalf("reviewed transition replay: status %d body %s, want original %s", status, retryBody, body)
	}
	status, verifiedBody := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identity.ID, operator, nil)
	if status != http.StatusOK {
		t.Fatalf("verify lifecycle state: status %d body %s", status, verifiedBody)
	}
	var verified struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(verifiedBody, &verified); err != nil || verified != executed {
		t.Fatalf("durable verification: err=%v got=%+v want=%+v body=%s", err, verified, executed, verifiedBody)
	}
	if afterExecute, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || afterExecute != beforePreview+1 {
		t.Fatalf("reviewed transition event sequence=(%d,%v), want exactly %d", afterExecute, lastErr, beforePreview+1)
	}
}
