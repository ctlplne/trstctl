// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestC0007RunIssuerCannotReviewItsOperationRequest(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	x := a251Harness{t: t, h: h}
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "c0007-operation-issuer",
		"access:read", "access:write", "access:bundle.run", "certs:issue")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "c0007-operation-reviewer", "certs:issue")
	bundle := x.bundle(issuer, "op-bundle", "c0007-operation", "certs:issue")
	x.grant(issuer, "op-grant", bundle, "machine", "c0007-operation-machine")
	x.run(issuer, "op-run", map[string]any{
		"principal": "c0007-operation-machine", "bundle_ids": []string{bundle}, "ttl_seconds": 600,
	})
	request, err := h.srv.orch.EnsureOperationApprovalRequest(t.Context(), h.tenant, orchestrator.OperationApprovalIntent{
		ResourceKind: "code_signing", ResourceID: "code-signing/c0007", Action: "sign",
		Requester: "bundle-run:c0007-operation-machine", FromState: "requested", ToState: "signed",
		TargetVersion: 1, RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals",
		issuer, "op-review", map[string]any{"intent_digest": request.IntentDigest})
	if status != http.StatusForbidden {
		t.Fatalf("run issuer reviewed its own operation: %d %s; want 403", status, body)
	}
	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/approval-requests/"+request.ID+"/approvals",
		reviewer, "op-independent", map[string]any{"intent_digest": request.IntentDigest})
	if status != http.StatusOK {
		t.Fatalf("independent reviewer could not approve operation: %d %s", status, body)
	}
}
