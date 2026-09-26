// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// DP2-059: identical in-flight approval decisions (same reviewer, same request,
// same Idempotency-Key, all at once) execute the decision once and every caller
// receives the canonical 200, or the documented in-progress 409 followed by the
// replay. On the starting candidate the decision route ran on the durable path,
// which let every identical caller execute concurrently against the same locked
// request row; under a burst one of them answered 500 (cmd-0106 on g307).
func TestServedIdenticalApprovalDecisionsCoalesce(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
	})
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "identical-requester@example.test",
		string(authz.OwnersWrite), string(authz.IdentitiesWrite), string(authz.CertsRequest), string(authz.CertsIssue), string(authz.IdentitiesRead))
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "identical-reviewer@example.test",
		string(authz.CertsIssue), string(authz.IdentitiesRead))

	st, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", requester, "identical-owner", map[string]any{"kind": "workload", "name": "identical-payments"})
	if st != http.StatusCreated {
		t.Fatalf("create owner: %d %s", st, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil || owner.ID == "" {
		t.Fatalf("decode owner: %v %s", err, body)
	}
	st, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", requester, "identical-identity", map[string]any{"kind": "x509_certificate", "name": "identical-api.example.test", "owner_id": owner.ID})
	if st != http.StatusCreated {
		t.Fatalf("create identity: %d %s", st, body)
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &identity); err != nil || identity.ID == "" {
		t.Fatalf("decode identity: %v %s", err, body)
	}
	// The requester's own attempt is refused under dual control and records the
	// immutable approval request.
	st, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", requester, "identical-issue", map[string]any{"to": "issued", "reason": "identical decisions"})
	if st != http.StatusForbidden || !strings.Contains(string(body), "dual control") {
		t.Fatalf("governed transition attempt: %d %s (want 403 dual control)", st, body)
	}
	st, body = secretsReq(t, h, http.MethodGet, "/api/v1/approval-requests", reviewer, nil)
	if st != http.StatusOK {
		t.Fatalf("list approval requests: %d %s", st, body)
	}
	var listed struct {
		Items []struct {
			ID           string `json:"id"`
			IntentDigest string `json:"intent_digest"`
			ResourceID   string `json:"resource_id"`
			Status       string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	var requestID, digest string
	for _, it := range listed.Items {
		if it.ResourceID == identity.ID {
			requestID, digest = it.ID, it.IntentDigest
		}
	}
	if requestID == "" || digest == "" {
		t.Fatalf("no approval request for the governed identity: %s", body)
	}

	const callers = 12
	statuses := make([]int, callers)
	bodies := make([][]byte, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			statuses[i], bodies[i] = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+requestID+"/approvals", reviewer, "identical-decision", map[string]any{"intent_digest": digest, "reason": "looks right"})
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for i, st := range statuses {
		switch st {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			if !strings.Contains(string(bodies[i]), "still in progress") {
				t.Fatalf("caller %d: 409 that is not the documented in-progress answer: %s", i, bodies[i])
			}
		default:
			t.Fatalf("caller %d: status %d (want 200 or the documented in-progress 409): %s", i, st, bodies[i])
		}
	}
	if ok == 0 {
		t.Fatalf("no identical decision answered 200: %v", statuses)
	}
	// The served surface lists requests (there is no get-by-id route).
	st, body = secretsReq(t, h, http.MethodGet, "/api/v1/approval-requests", reviewer, nil)
	if st != http.StatusOK {
		t.Fatalf("list approval requests after the storm: %d %s", st, body)
	}
	var after struct {
		Items []struct {
			ID            string `json:"id"`
			ApprovalCount int    `json:"approval_count"`
			Status        string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &after); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range after.Items {
		if it.ID == requestID {
			found = true
			if it.ApprovalCount != 1 || it.Status != "approved" {
				t.Fatalf("after the identical-decision storm: approval_count=%d status=%q, want 1/approved: %s", it.ApprovalCount, it.Status, body)
			}
		}
	}
	if !found {
		t.Fatalf("approval request %s vanished from the listing after the storm: %s", requestID, body)
	}
	// A very late identical retry, after the recorder's retention window has
	// reclaimed the key, re-executes the decision on the claim path and finds the
	// decision already recorded: 200, still exactly one decision (review of the
	// move from the durable path to the claim path in g308).
	if _, err := h.store.SystemPool().Exec(t.Context(), `DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = 'identical-decision'`, h.tenant); err != nil {
		t.Fatalf("simulate idempotency retention: %v", err)
	}
	st, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+requestID+"/approvals", reviewer, "identical-decision", map[string]any{"intent_digest": digest, "reason": "looks right"})
	if st != http.StatusOK {
		t.Fatalf("identical decision after retention: %d %s (want 200, the recorded decision)", st, body)
	}
	st, body = secretsReq(t, h, http.MethodGet, "/api/v1/approval-requests", reviewer, nil)
	if st != http.StatusOK {
		t.Fatalf("list after the late retry: %d %s", st, body)
	}
	if err := json.Unmarshal(body, &after); err != nil {
		t.Fatal(err)
	}
	for _, it := range after.Items {
		if it.ID == requestID && it.ApprovalCount != 1 {
			t.Fatalf("late identical retry doubled the decision: approval_count=%d: %s", it.ApprovalCount, body)
		}
	}

	// The requester's replay consumes the authority exactly once.
	st, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", requester, "identical-issue", map[string]any{"to": "issued", "reason": "identical decisions"})
	if st != http.StatusOK {
		t.Fatalf("governed transition replay after approval: %d %s", st, body)
	}
}
