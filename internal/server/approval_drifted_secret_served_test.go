// SPDX-License-Identifier: MPL-2.0

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
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedCanonicalApprovalRejectsDriftedApplicationSecretAUD77 proves the
// canonical reviewer route checks the current application-secret projection at
// decision time. The immutable request below is genuine approval.requested state,
// but a later served rotation moves the target projection from version 1 to
// version 2. Reviewing the stale digest must supersede that request without
// recording an approval.decision_recorded fact.
func TestServedCanonicalApprovalRejectsDriftedApplicationSecretAUD77(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "AUD-77 served approval tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "aud-77-secret-requester", string(authz.SecretsWrite))
	approver := seedScopedTokenSubject(t, h.store, h.tenant, "aud-77-secret-approver", string(authz.SecretsWrite))
	inventoryWriter := seedScopedTokenSubject(t, h.store, h.tenant, "aud-77-inventory-writer",
		string(authz.OwnersWrite), string(authz.IdentitiesWrite))
	certificateReviewer := seedScopedTokenSubject(t, h.store, h.tenant, "aud-77-certificate-reviewer",
		string(authz.CertsIssue))
	const name = "aud-77-drifted-secret"

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", inventoryWriter,
		"aud-77-inventory-owner", map[string]any{"kind": "workload", "name": "aud-77-inventory-only"})
	if status != http.StatusCreated {
		t.Fatalf("create ordinary owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil || owner.ID == "" {
		t.Fatalf("decode ordinary owner: %v body=%s", err, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", inventoryWriter,
		"aud-77-inventory-identity", map[string]any{
			"kind": "x509_certificate", "name": "inventory-only.aud-77.example", "owner_id": owner.ID,
		})
	if status != http.StatusCreated {
		t.Fatalf("create ordinary identity: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/approval-requests?status=pending", certificateReviewer, nil)
	if status != http.StatusOK {
		t.Fatalf("list approval queue for ordinary identity: status %d body %s", status, body)
	}
	var emptyQueue struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &emptyQueue); err != nil {
		t.Fatalf("decode approval queue: %v body=%s", err, body)
	}
	if len(emptyQueue.Items) != 0 {
		t.Fatalf("ordinary identity inventory fabricated %d pending approval rows: %s", len(emptyQueue.Items), body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", requester,
		"aud-77-secret-create", map[string]any{"name": name, "value": "version-one"})
	if status != http.StatusCreated {
		t.Fatalf("create application secret: status %d body %s", status, body)
	}

	// Build the same non-secret binding shape used by a requester-side rotate.
	// The shared binding function proves this is a complete application-secret
	// intent rather than a generic request carrying "secret" as a display label.
	payload := projections.ApplicationSecretMutation{
		Name: name, Action: "rotate", Surface: "native",
		ExpectedVersion: 1, ResultVersion: 2, Sealed: []byte{0x01},
		IdempotencyKeyDigest: strings.Repeat("1", 64),
		RequestBinding:       strings.Repeat("2", 64),
		CommandEvidence:      strings.Repeat("3", 64),
	}
	fromState, toState, evidenceRefs, err := projections.ApplicationSecretApprovalBinding(payload)
	if err != nil {
		t.Fatalf("build exact application-secret approval binding: %v", err)
	}
	request, err := h.srv.orch.EnsureOperationApprovalRequest(t.Context(), h.tenant, orchestrator.OperationApprovalIntent{
		ResourceKind: "secret", ResourceID: "secret:" + name, ResourceName: name,
		Action: "rotate", Requester: "aud-77-secret-requester",
		FromState: fromState, ToState: toState, TargetVersion: 1,
		Reason: "review the exact version-one rotation", EvidenceRefs: evidenceRefs,
		RequiredApprovals: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("create event-projected application-secret approval request: %v", err)
	}
	if request.Status != store.ApprovalStatusPending || request.TargetVersion != 1 {
		t.Fatalf("initial approval request = %+v, want pending version 1", request)
	}

	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+name, requester,
		"aud-77-secret-drift", map[string]any{"value": "version-two"})
	if status != http.StatusOK {
		t.Fatalf("drift application-secret target through served API: status %d body %s", status, body)
	}
	current, err := h.store.GetSecret(t.Context(), h.tenant, name)
	if err != nil || current.Version != 2 {
		t.Fatalf("drifted application-secret projection = %+v err=%v, want version 2", current, err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/approval-requests/"+request.ID+"/approvals", approver,
		"aud-77-approve-drifted-secret", map[string]string{"intent_digest": request.IntentDigest})
	if status != http.StatusConflict {
		t.Fatalf("approve drifted application-secret request: status %d body %s, want 409", status, body)
	}
	var problem struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("decode drift problem: %v body=%s", err, body)
	}
	if problem.Status != http.StatusConflict || problem.Detail != "approval target version or state drifted" {
		t.Fatalf("drift problem = %+v, want exact conflict", problem)
	}

	stale, err := h.store.GetOperationApproval(t.Context(), h.tenant, request.ID)
	if err != nil {
		t.Fatalf("load drifted approval request: %v", err)
	}
	if stale.Status != store.ApprovalStatusSuperseded || stale.ApprovalCount != 0 || stale.ConsumedEventID != "" {
		t.Fatalf("drifted approval request = %+v, want unconsumed superseded request with zero decisions", stale)
	}
	var decisionRows int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `
			SELECT count(*) FROM operation_approval_decisions
			 WHERE tenant_id = $1 AND request_id = $2
		`, h.tenant, request.ID).Scan(&decisionRows)
	}); err != nil {
		t.Fatalf("count approval decision rows: %v", err)
	}
	if decisionRows != 0 {
		t.Fatalf("drifted approval persisted %d decision rows, want 0", decisionRows)
	}

	decisionFacts := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.Type != projections.EventApprovalDecisionRecorded {
			return nil
		}
		var decision projections.ApprovalDecisionRecorded
		if err := json.Unmarshal(event.Data, &decision); err != nil {
			return err
		}
		if event.TenantID == h.tenant && decision.RequestID == request.ID {
			decisionFacts++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay approval events: %v", err)
	}
	if decisionFacts != 0 {
		t.Fatalf("drifted approval emitted %d approval decision facts, want 0", decisionFacts)
	}
}
