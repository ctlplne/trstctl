// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

func TestC0004BundleRunOpenerCannotApproveAsItsOwner(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	x := a251Harness{t: t, h: h}
	const owner = "c0004-owner"
	ownerToken := seedScopedTokenSubject(t, h.store, h.tenant, owner,
		"access:read", "access:write", "access:bundle.run", "profiles:read", "profiles:write", "issuers:read", "issuers:write")
	bundle := x.bundle(ownerToken, "c0004-bundle", "c0004-profile-and-ca", "profiles:read", "profiles:write", "issuers:read", "issuers:write")
	x.grant(ownerToken, "c0004-grant", bundle, "machine", owner)
	run := x.run(ownerToken, "c0004-run", map[string]any{"bundle_ids": []string{bundle}, "ttl_seconds": 600})

	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/profiles", run.Token,
		"c0004-profile", map[string]any{"name": "c0004-governed", "spec": map[string]any{"requires_approval": true, "max_validity": "24h"}})
	if status != http.StatusAccepted {
		t.Fatalf("bundle run did not park a governed profile: %d %s", status, body)
	}
	var parked struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(body, &parked); err != nil || parked.ApprovalID == "" {
		t.Fatalf("profile approval ID: %v %s", err, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/profiles/approvals/"+parked.ApprovalID+"/approvals",
		ownerToken, "c0004-profile-self-approval", map[string]any{"reason": "owner of the requesting run"})
	if status != http.StatusForbidden {
		t.Errorf("bundle-run profile approved by its owner: %d %s; want 403", status, body)
	}
	profileApproval, err := h.store.GetProfileEditApproval(t.Context(), h.tenant, parked.ApprovalID)
	if err != nil || len(profileApproval.Approvals) != 0 || profileApproval.State != "awaiting_approval" {
		t.Fatalf("owner vote changed the governed profile: %+v, err=%v", profileApproval, err)
	}

	spec := map[string]any{
		"common_name": "c0004 root", "max_path_len": 1,
		"ttl_seconds":         int64((365 * 24 * time.Hour).Seconds()),
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, run.Token, "create_root", "", spec, 1, "c0004-ceremony")
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals",
		ownerToken, "own-ca", nil)
	if status != http.StatusConflict {
		t.Errorf("bundle-run ceremony approved by its owner: %d %s; want 409", status, body)
	}
	caApproval, err := h.store.GetKeyCeremony(t.Context(), h.tenant, ceremony.ID)
	if err != nil || caApproval.Approvals != 0 || caApproval.Status != "pending" {
		t.Fatalf("owner vote changed the key ceremony: %+v, err=%v", caApproval, err)
	}

	independent := seedScopedTokenSubject(t, h.store, h.tenant, "c0004-reviewer", "profiles:read", "profiles:write", "issuers:read", "issuers:write")
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/profiles/approvals/"+parked.ApprovalID+"/approvals",
		independent, "c0004-profile-independent", map[string]any{"reason": "independent review"})
	if status != http.StatusOK {
		t.Fatalf("independent profile reviewer refused: %d %s", status, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals",
		independent, "c0004-ceremony-independent", nil)
	if status != http.StatusOK {
		t.Fatalf("independent CA custodian refused: %d %s", status, body)
	}
}
