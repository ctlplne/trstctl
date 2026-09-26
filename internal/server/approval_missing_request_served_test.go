// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestServedApprovalRequiresExistingRequestAUD77 is the assembled RED proof for
// AUD-77. An approval is a decision about an existing immutable request; it must
// never create the request it claims to review. The valid identity below proves the
// 404 is about the absent approval request, not an absent target. PostgreSQL and
// JetStream assertions prove the refused command leaves no request, decision, or
// audit event behind.
func TestServedApprovalRequiresExistingRequestAUD77(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
	})

	creator := seedScopedTokenSubject(t, h.store, h.tenant, "requester@example.test",
		string(authz.OwnersWrite), string(authz.IdentitiesWrite))
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "approver@example.test",
		string(authz.CertsIssue))

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", creator, "aud-77-owner", map[string]any{
		"kind": "workload",
		"name": "aud-77-payments",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil || owner.ID == "" {
		t.Fatalf("decode owner: %v body=%s", err, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", creator, "aud-77-identity", map[string]any{
		"kind":     "x509_certificate",
		"name":     "aud-77-api.example.test",
		"owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &identity); err != nil || identity.ID == "" {
		t.Fatalf("decode identity: %v body=%s", err, body)
	}
	if _, err := h.store.GetIdentity(t.Context(), h.tenant, identity.ID); err != nil {
		t.Fatalf("valid identity is absent from the tenant projection: %v", err)
	}

	requestRows, decisionRows := aud77ApprovalRows(t, h, identity.ID, "issue")
	if requestRows != 0 || decisionRows != 0 {
		t.Fatalf("approval precondition = requests %d decisions %d, want 0/0", requestRows, decisionRows)
	}
	headBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("read JetStream head before approval: %v", err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/identities/"+identity.ID+"/approvals", approver, "aud-77-no-request-approval",
		map[string]string{"action": "issue"})
	if status != http.StatusNotFound {
		t.Errorf("approve without a request: status %d body %s, want tenant-safe 404", status, body)
	} else {
		var problem struct {
			Status int    `json:"status"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(body, &problem); err != nil {
			t.Errorf("decode no-request problem: %v body=%s", err, body)
		} else if problem.Status != http.StatusNotFound || problem.Detail != "resource not found" {
			t.Errorf("no-request problem = %+v, want generic resource-not-found response", problem)
		}
		for _, leaked := range []string{h.tenant, identity.ID, "issuance_approval_requests", "issuance_approvals"} {
			if strings.Contains(string(body), leaked) {
				t.Errorf("tenant-safe 404 leaked %q in body %s", leaked, body)
			}
		}
	}

	requestRows, decisionRows = aud77ApprovalRows(t, h, identity.ID, "issue")
	if requestRows != 0 || decisionRows != 0 {
		t.Errorf("refused approval persisted requests %d decisions %d, want 0/0", requestRows, decisionRows)
	}
	headAfter, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("read JetStream head after approval: %v", err)
	}
	if headAfter != headBefore {
		t.Errorf("refused approval advanced JetStream head from %d to %d; want no event", headBefore, headAfter)
	}

	const unknownDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		name      string
		requestID string
		key       string
	}{
		{name: "malformed UUID", requestID: "not-a-request-uuid", key: "aud-77-malformed-request-id"},
		{name: "valid unknown UUID", requestID: "77000000-0000-4000-8000-000000000299", key: "aud-77-unknown-request-id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headBefore, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatalf("read event head before exact refusal: %v", err)
			}
			status, body := secretsReqKey(t, h, http.MethodPost,
				"/api/v1/approval-requests/"+tc.requestID+"/approvals", approver, tc.key,
				map[string]string{"intent_digest": unknownDigest})
			if status != http.StatusNotFound {
				t.Errorf("canonical approve unknown request: status %d body %s, want tenant-safe 404", status, body)
			} else {
				var problem struct {
					Status int    `json:"status"`
					Detail string `json:"detail"`
				}
				if err := json.Unmarshal(body, &problem); err != nil {
					t.Errorf("decode exact no-request problem: %v body=%s", err, body)
				} else if problem.Status != http.StatusNotFound || problem.Detail != "resource not found" {
					t.Errorf("exact no-request problem = %+v, want generic resource-not-found response", problem)
				}
				for _, leaked := range []string{h.tenant, tc.requestID, unknownDigest, "operation_approval_requests"} {
					if strings.Contains(string(body), leaked) {
						t.Errorf("tenant-safe exact 404 leaked %q in body %s", leaked, body)
					}
				}
			}
			requests, decisions, idem := aud77ExactApprovalState(t, h, tc.key)
			if requests != 0 || decisions != 0 || idem != 0 {
				t.Errorf("refused exact approval persisted requests=%d decisions=%d idempotency=%d, want 0/0/0",
					requests, decisions, idem)
			}
			if headAfter, err := h.log.LastSequence(t.Context()); err != nil || headAfter != headBefore {
				t.Errorf("refused exact approval event head = (%d, %v), want %d", headAfter, err, headBefore)
			}
		})
	}

	identityRow, targetVersion, err := h.store.IdentityApprovalTarget(t.Context(), h.tenant, identity.ID)
	if err != nil {
		t.Fatalf("load known approval target: %v", err)
	}
	known, err := h.srv.orch.EnsureOperationApprovalRequest(t.Context(), h.tenant, orchestrator.OperationApprovalIntent{
		ResourceKind: "identity", ResourceID: identity.ID, ResourceName: identityRow.Name,
		Action: "issue", Requester: "requester@example.test",
		FromState: identityRow.Status, ToState: "issued", TargetVersion: targetVersion,
		Reason: "known compatibility-route binding", EvidenceRefs: []string{"evidence:known-route"},
		RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("create known approval request: %v", err)
	}
	for _, tc := range []struct {
		name       string
		identityID string
		action     string
		key        string
	}{
		{name: "wrong resource", identityID: "77000000-0000-4000-8000-000000000298", action: "issue", key: "aud-77-wrong-resource"},
		{name: "wrong action", identityID: identity.ID, action: "revoke", key: "aud-77-wrong-action"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headBefore, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			status, body := secretsReqKey(t, h, http.MethodPost,
				"/api/v1/identities/"+tc.identityID+"/approvals", approver, tc.key,
				map[string]string{"action": tc.action, "request_id": known.ID, "intent_digest": known.IntentDigest})
			if status != http.StatusNotFound || !strings.Contains(string(body), `"detail":"resource not found"`) {
				t.Errorf("known request with wrong compatibility binding = %d body=%s, want generic 404", status, body)
			}
			requests, decisions, idem := aud77ExactApprovalState(t, h, tc.key)
			if requests != 1 || decisions != 0 || idem != 0 {
				t.Errorf("wrong compatibility binding state = requests=%d decisions=%d idempotency=%d, want 1/0/0",
					requests, decisions, idem)
			}
			if headAfter, err := h.log.LastSequence(t.Context()); err != nil || headAfter != headBefore {
				t.Errorf("wrong compatibility binding event head = (%d, %v), want %d", headAfter, err, headBefore)
			}
		})
	}
}

func aud77ApprovalRows(t *testing.T, h *servedHarness, resource, action string) (requests, decisions int) {
	t.Helper()
	ctx := context.Background()
	err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT
				(SELECT count(*) FROM issuance_approval_requests
				  WHERE tenant_id = $1 AND resource = $2 AND action = $3)
				+ (SELECT count(*) FROM operation_approval_requests
				    WHERE tenant_id = $1 AND resource_kind = 'identity'
				      AND resource_id = $2 AND action = $3),
				(SELECT count(*) FROM issuance_approvals
				  WHERE tenant_id = $1 AND resource = $2 AND action = $3)
				+ (SELECT count(*) FROM operation_approval_decisions d
				    JOIN operation_approval_requests r
				      ON r.tenant_id = d.tenant_id AND r.id = d.request_id
				   WHERE d.tenant_id = $1 AND r.resource_kind = 'identity'
				     AND r.resource_id = $2 AND r.action = $3)
		`, h.tenant, resource, action).Scan(&requests, &decisions)
	})
	if err != nil {
		t.Fatalf("count approval durability rows: %v", err)
	}
	return requests, decisions
}

func aud77ExactApprovalState(t *testing.T, h *servedHarness, idempotencyKey string) (requests, decisions, idempotency int) {
	t.Helper()
	ctx := context.Background()
	err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT
			  (SELECT count(*) FROM operation_approval_requests WHERE tenant_id = $1),
			  (SELECT count(*) FROM operation_approval_decisions WHERE tenant_id = $1),
			  (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1 AND key = $2)
		`, h.tenant, idempotencyKey).Scan(&requests, &decisions, &idempotency)
	})
	if err != nil {
		t.Fatalf("count exact approval refusal state: %v", err)
	}
	return requests, decisions, idempotency
}
