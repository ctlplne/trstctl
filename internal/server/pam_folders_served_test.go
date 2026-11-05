// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

// A folder supplies every account's access policy. Callers cannot choose a
// weaker template or obtain an unrecorded session or check-out when recording
// is required. The proof uses the served HTTP routes and the real event spine.
func TestServedFolderTemplatesApplyToEveryAccountA261(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a261-folder-admin", "access:read", "access:write", "access:targets.write")
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a261-folder-custodian", "secrets:read", "secrets:write")
	call := func(method, path, key string, body any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, method, path, admin, key, body)
	}
	template := func(name string, recording bool) api.PAMAccessTemplate {
		t.Helper()
		status, raw := call(http.MethodPost, "/api/v1/access/templates", "folder-template-"+name, map[string]any{
			"name": name, "reason": "Production incident", "required_approvals": 3, "max_ttl_seconds": 60, "require_recording": recording})
		var v api.PAMAccessTemplate
		if status != http.StatusCreated || json.Unmarshal(raw, &v) != nil || v.RequireRecording != recording {
			t.Fatalf("save template = %d %s", status, raw)
		}
		return v
	}
	policy := template("folder-production", true)
	weaker := template("folder-other", false)
	if status, raw := call(http.MethodPut, "/api/v1/access/folders/missing-template", "folder-missing-template", map[string]any{}); status != http.StatusUnprocessableEntity {
		t.Fatalf("missing template = %d %s", status, raw)
	}
	status, raw := call(http.MethodPut, "/api/v1/access/folders/production", "folder-save", map[string]any{"template_id": policy.ID, "description": "Production accounts"})
	var folder api.PAMFolder
	if status != http.StatusOK || json.Unmarshal(raw, &folder) != nil || folder.Revision != 1 {
		t.Fatalf("save folder = %d %s", status, raw)
	}
	if again, replay := call(http.MethodPut, "/api/v1/access/folders/production", "folder-save", map[string]any{"template_id": policy.ID, "description": "Production accounts"}); again != status || string(replay) != string(raw) {
		t.Fatalf("folder replay = %d %s", again, replay)
	}
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/folders/forbidden", f.requester, "folder-forbidden", map[string]any{"template_id": policy.ID}); status != http.StatusForbidden {
		t.Fatalf("requester changed policy = %d %s", status, raw)
	}
	register := func(id, folder string, gateway bool) (int, []byte) {
		body := map[string]any{"id": id, "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"}, "folder": folder}
		if gateway {
			body["gateway_agent_id"] = agentRowID(servedTestTenant, "role-agent")
			body["gateway_address"] = f.gatewayAddr
		}
		return call(http.MethodPost, "/api/v1/access/targets", "folder-register-"+id, body)
	}
	var firstReview api.PAMApprovalRequest
	for _, id := range []string{"folder-one", "folder-two"} {
		if status, raw := register(id, "production", true); status != http.StatusCreated || !strings.Contains(string(raw), `"folder":"production"`) {
			t.Fatalf("register %s = %d %s", id, status, raw)
		}
	}
	if status, raw := register("folder-missing", "absent", true); status != http.StatusUnprocessableEntity {
		t.Fatalf("missing folder = %d %s", status, raw)
	}
	request := func(target, templateID string) (int, []byte) {
		body := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": target, "role": "readonly", "reason": "INC-261", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 120}
		if templateID != "" {
			body["template_id"] = templateID
		}
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, uuid.NewString(), body)
	}
	for _, id := range []string{"folder-one", "folder-two"} {
		status, raw := request(id, "")
		var approval api.PAMApprovalRequest
		if status != http.StatusAccepted || json.Unmarshal(raw, &approval) != nil || approval.RequiredApprovals != 3 {
			t.Fatalf("folder policy on %s = %d %s", id, status, raw)
		}
		if id == "folder-one" {
			firstReview = approval
		}
		record, err := h.store.GetOperationApproval(t.Context(), h.tenant, approval.ApprovalRequestID)
		if err != nil || record.Reason != "Production incident: INC-261" || !containsExactString(record.EvidenceRefs, "pam-ttl-seconds:60") || !containsExactString(record.EvidenceRefs, "pam-template:folder-production@1") {
			t.Fatalf("folder review on %s = %+v, %v", id, record, err)
		}
		if status, raw := request(id, weaker.ID); status != http.StatusUnprocessableEntity {
			t.Fatalf("different template on %s = %d %s", id, status, raw)
		}
	}
	// The inherited policy governs the real open, not just the review display.
	openBody := map[string]any{"request_id": firstReview.RequestID, "approval_request_id": firstReview.ApprovalRequestID, "intent_digest": firstReview.IntentDigest, "target_type": "postgres", "target_id": "folder-one", "role": "readonly", "reason": "INC-261", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 120}
	third := seedScopedTokenSubject(t, h.store, h.tenant, "a261-folder-third", "access:approve")
	for i, reviewer := range []string{f.reviewerOne, f.reviewerTwo, third} {
		if i == 2 {
			if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", f.requester, "folder-early-open", openBody); status == http.StatusCreated {
				t.Fatalf("folder session opened with only two approvals: %s", raw)
			}
		}
		if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+firstReview.ApprovalRequestID+"/approvals", reviewer, fmt.Sprintf("folder-review-%d", i), map[string]any{"intent_digest": firstReview.IntentDigest}); status != http.StatusOK {
			t.Fatalf("folder review = %d %s", status, raw)
		}
	}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", f.requester, "folder-open", openBody)
	var opened a258Session
	if status != http.StatusCreated || json.Unmarshal(raw, &opened) != nil || opened.Delivery != "gateway" || opened.ExpiresAt.Sub(opened.StartedAt) > 61*time.Second {
		t.Fatalf("folder session = %d %s", status, raw)
	}
	local, stop := f.postgresTunnel(opened.servedPAMSessionResponse)
	defer stop()
	conn, err := pgconn.Connect(f.ctx, "postgres://reader@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("folder session does not reach the database: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if result := conn.ExecParams(f.ctx, "SELECT 1", nil, nil, nil, nil).Read(); result.Err != nil {
		t.Fatalf("folder session query: %v", result.Err)
	}
	status, raw = call(http.MethodGet, "/api/v1/access/folders", "", nil)
	if status != http.StatusOK || !strings.Contains(string(raw), `"targets":2`) {
		t.Fatalf("folder counts = %d %s", status, raw)
	}
	otherTenant := "22222222-2222-2222-2222-222222222222"
	if err := h.store.UpsertTenant(t.Context(), store.Tenant{TenantID: otherTenant, Name: "A261 folder neighbor"}); err != nil {
		t.Fatal(err)
	}
	foreign := seedScopedTokenSubject(t, h.store, otherTenant, "a261-folder-neighbor", "access:read", "access:targets.write")
	if status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/folders", foreign, nil); status != http.StatusOK || strings.Contains(string(raw), "production") {
		t.Fatalf("foreign folder read = %d %s", status, raw)
	}
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/folders/foreign", foreign, "folder-foreign", map[string]any{"template_id": policy.ID}); status != http.StatusNotFound {
		t.Fatalf("foreign template assigned = %d %s", status, raw)
	}
	if status, raw := call(http.MethodDelete, "/api/v1/access/folders/production?revision=1", "folder-nonempty-delete", nil); status != http.StatusConflict {
		t.Fatalf("delete occupied folder = %d %s", status, raw)
	}
	if status, raw := call(http.MethodPut, "/api/v1/access/folders/production", "folder-stale-save", map[string]any{"template_id": policy.ID, "revision": 9}); status != http.StatusConflict {
		t.Fatalf("stale save = %d %s", status, raw)
	}
	// The same recording rule refuses a direct target and a vaulted check-out.
	if status, raw := register("folder-direct", "production", false); status != http.StatusCreated {
		t.Fatalf("register direct = %d %s", status, raw)
	}
	if status, raw := request("folder-direct", ""); status != http.StatusUnprocessableEntity || !strings.Contains(string(raw), "record") {
		t.Fatalf("unrecorded request = %d %s", status, raw)
	}
	responder := seedScopedTokenSubject(t, h.store, h.tenant, "a261-folder-responder", "access:read", "access:sessions.open")
	if status, raw := call(http.MethodPut, "/api/v1/access/emergency/responders", "folder-name-responder", map[string]any{"subjects": []string{"a261-folder-responder"}}); status != http.StatusOK {
		t.Fatalf("name responder = %d %s", status, raw)
	}
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/emergency-sessions", responder, "folder-unrecorded-emergency", map[string]any{"target_type": "postgres", "target_id": "folder-direct", "role": "readonly", "reason": "INC-261", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 120}); status != http.StatusUnprocessableEntity || !strings.Contains(string(raw), "record") {
		t.Fatalf("unrecorded emergency = %d %s", status, raw)
	}
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "folder-vault-seed", map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("vault seed = %d %s", status, raw)
	}
	if status, raw := call(http.MethodPost, "/api/v1/access/targets", "folder-vault-register", map[string]any{"id": "folder-vault", "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole}, "account_secret": twoUserRole, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "folder": "production"}); status != http.StatusCreated {
		t.Fatalf("register vault = %d %s", status, raw)
	}
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", f.requester, "folder-checkout", map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "folder-vault", "reason": "INC-261", "ttl_seconds": 120}); status != http.StatusUnprocessableEntity || !strings.Contains(string(raw), "record") {
		t.Fatalf("unrecorded check-out = %d %s", status, raw)
	}
	// Lack of recording storage fails closed even for a gateway-bound target.
	withoutStorage := *h.srv.pam
	withoutStorage.recordings = nil
	if _, _, _, err := withoutStorage.withTemplate(t.Context(), h.tenant, api.PAMSessionRequest{TargetType: "postgres", TargetID: "folder-one", Reason: "INC-261", TTLSeconds: 120}); err == nil {
		t.Fatal("a template requiring recording accepted an unconfigured recording store")
	}
	// A check-out inherits the same quorum and TTL. Changing a folder's
	// template after its review cannot authorize a reveal under a new policy.
	if status, raw := call(http.MethodPut, "/api/v1/access/folders/checkout-policy", "folder-checkout-policy", map[string]any{"template_id": weaker.ID}); status != http.StatusOK {
		t.Fatalf("checkout folder = %d %s", status, raw)
	}
	if status, raw := call(http.MethodPost, "/api/v1/access/targets/postgres/folder-vault/folder", "folder-vault-move", map[string]any{"folder": "checkout-policy"}); status != http.StatusOK {
		t.Fatalf("move vaulted target = %d %s", status, raw)
	}
	checkoutID := uuid.NewString()
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", f.requester, "folder-reviewed-checkout", map[string]any{"request_id": checkoutID, "target_type": "postgres", "target_id": "folder-vault", "reason": "INC-261", "ttl_seconds": 120})
	var checkoutReview api.PAMCheckoutReview
	if status != http.StatusAccepted || json.Unmarshal(raw, &checkoutReview) != nil || checkoutReview.RequiredApprovals != 3 {
		t.Fatalf("folder checkout review = %d %s", status, raw)
	}
	checkoutApproval, err := h.store.GetOperationApproval(t.Context(), h.tenant, checkoutReview.ApprovalRequestID)
	if err != nil || !containsExactString(checkoutApproval.EvidenceRefs, "pam-checkout-ttl:60") || checkoutApproval.Reason != "Production incident: INC-261" {
		t.Fatalf("checkout policy = %+v, %v", checkoutApproval, err)
	}
	for i, reviewer := range []string{f.reviewerOne, f.reviewerTwo, third} {
		if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+checkoutReview.ApprovalRequestID+"/approvals", reviewer, fmt.Sprintf("folder-checkout-review-%d", i), map[string]any{"intent_digest": checkoutReview.IntentDigest}); status != http.StatusOK {
			t.Fatalf("checkout review = %d %s", status, raw)
		}
	}
	nextPolicy := template("folder-checkout-next", false)
	if status, raw := call(http.MethodPut, "/api/v1/access/folders/checkout-policy", "folder-checkout-policy-change", map[string]any{"template_id": nextPolicy.ID, "revision": 1}); status != http.StatusOK {
		t.Fatalf("change checkout folder = %d %s", status, raw)
	}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+checkoutID+"/reveal", f.requester, "folder-stale-reveal", map[string]any{"approval_request_id": checkoutReview.ApprovalRequestID, "intent_digest": checkoutReview.IntentDigest})
	if status != http.StatusForbidden || !strings.Contains(string(raw), "changed since review") {
		t.Fatalf("a reveal under changed policy returned %d (credential body withheld)", status)
	}
	// The membership/deletion fence rejects another change for this tenant;
	// a neighbor's independent folder is still writable while it is held.
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/templates", foreign, "folder-neighbor-template", map[string]any{"name": "neighbor-policy", "reason": "Neighbor access", "required_approvals": 2, "max_ttl_seconds": 60})
	var neighborPolicy api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(raw, &neighborPolicy) != nil {
		t.Fatalf("neighbor template = %d %s", status, raw)
	}
	if err := h.store.WithPAMCatalogLock(t.Context(), h.tenant, func() error {
		if status, raw := call(http.MethodPost, "/api/v1/access/targets/postgres/folder-one/folder", "folder-busy-move", map[string]any{"folder": ""}); status != http.StatusServiceUnavailable {
			t.Fatalf("catalog contention = %d %s", status, raw)
		}
		if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/folders/neighbor", foreign, "folder-neighbor-write", map[string]any{"template_id": neighborPolicy.ID}); status != http.StatusOK {
			t.Fatalf("neighbor catalog = %d %s", status, raw)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !h.hasEvent(t, "pam.folder.saved") || !h.hasEvent(t, "pam.target.folder_set") {
		t.Fatal("folder changes lack their immutable events")
	}
	// Moving out is explicit; once empty, revision-checked deletion succeeds.
	for _, id := range []string{"folder-one", "folder-two", "folder-direct", "folder-vault"} {
		if status, raw := call(http.MethodPost, fmt.Sprintf("/api/v1/access/targets/postgres/%s/folder", id), "folder-clear-"+id, map[string]any{"folder": ""}); status != http.StatusOK {
			t.Fatalf("clear folder = %d %s", status, raw)
		}
	}
	if status, raw := call(http.MethodDelete, "/api/v1/access/folders/production?revision=1", "folder-delete", nil); status != http.StatusOK {
		t.Fatalf("delete empty folder = %d %s", status, raw)
	}
}
