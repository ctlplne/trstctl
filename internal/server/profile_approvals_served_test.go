// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// DP2-057: a profile whose spec carries requires_approval parks its create/edit
// behind dual control and answers 202 with an approval id. The served surface
// must let a distinct reviewer find and approve that request so the profile
// actually comes into being; on the starting candidate no route reached the
// parked request (GET/POST answered 404 for every caller) and a governed
// profile could never be created through the API.
func TestServedGovernedProfileCreateIsApprovedByADistinctReviewer(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "governed profile tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "profile-requester", "profiles:read", "profiles:write")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "profile-reviewer", "profiles:read", "profiles:write")

	body := map[string]any{"name": "governed-web", "spec": map[string]any{"requires_approval": true, "max_validity": "24h"}}
	st, resp := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", requester, "governed-web-create", body)
	if st != http.StatusAccepted {
		t.Fatalf("governed profile create: %d %s (want 202 awaiting approval)", st, resp)
	}
	var accepted struct {
		ApprovalID string `json:"approval_id"`
		State      string `json:"state"`
	}
	if err := json.Unmarshal(resp, &accepted); err != nil || accepted.ApprovalID == "" || accepted.State != "awaiting_approval" {
		t.Fatalf("202 body: %s (%v)", resp, err)
	}

	// The reviewer can find the parked request.
	st, resp = secretsReq(t, h, http.MethodGet, "/api/v1/profiles/approvals", reviewer, nil)
	if st != http.StatusOK || !strings.Contains(string(resp), accepted.ApprovalID) || !strings.Contains(string(resp), `"profile_name":"governed-web"`) {
		t.Fatalf("list profile approvals: %d %s", st, resp)
	}
	st, resp = secretsReq(t, h, http.MethodGet, "/api/v1/profiles/approvals/"+accepted.ApprovalID, reviewer, nil)
	if st != http.StatusOK || !strings.Contains(string(resp), `"state":"awaiting_approval"`) {
		t.Fatalf("get profile approval: %d %s", st, resp)
	}

	// Dual control: the requester cannot approve their own edit.
	st, resp = secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles/approvals/"+accepted.ApprovalID+"/approvals", requester, "self-approve", map[string]any{"reason": "self"})
	if st != http.StatusForbidden || !strings.Contains(string(resp), "dual control") {
		t.Fatalf("self-approval: %d %s (want 403 dual control)", st, resp)
	}

	// Identical concurrent approvals by the reviewer: one decision, no 5xx, and
	// quorum (1) applies the queued spec exactly once.
	const callers = 8
	statuses := make([]int, callers)
	bodies := make([][]byte, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			statuses[i], bodies[i] = secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles/approvals/"+accepted.ApprovalID+"/approvals", reviewer, "reviewer-approve", map[string]any{"reason": "looks right"})
		}(i)
	}
	close(start)
	wg.Wait()
	issued := 0
	for i, st := range statuses {
		switch st {
		case http.StatusOK:
			if !strings.Contains(string(bodies[i]), `"state":"issued"`) {
				t.Fatalf("caller %d: approved but not issued: %s", i, bodies[i])
			}
			issued++
		case http.StatusConflict:
			if !strings.Contains(string(bodies[i]), "still in progress") {
				t.Fatalf("caller %d: 409 that is not the documented in-progress answer: %s", i, bodies[i])
			}
		default:
			t.Fatalf("caller %d: status %d: %s", i, st, bodies[i])
		}
	}
	if issued == 0 {
		t.Fatalf("no identical approval answered 200 issued: %v", statuses)
	}
	st, resp = secretsReq(t, h, http.MethodGet, "/api/v1/profiles/approvals/"+accepted.ApprovalID, reviewer, nil)
	if st != http.StatusOK || strings.Count(string(resp), `"decision":"approve"`) != 1 {
		t.Fatalf("after the identical-approval storm the request must hold exactly one decision: %d %s", st, resp)
	}

	// The governed profile now exists, active, with its spec.
	st, resp = secretsReq(t, h, http.MethodGet, "/api/v1/profiles", requester, nil)
	if st != http.StatusOK {
		t.Fatalf("list profiles: %d %s", st, resp)
	}
	var listed struct {
		Items []struct {
			Name   string          `json:"name"`
			Active bool            `json:"active"`
			Spec   json.RawMessage `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal(resp, &listed); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, it := range listed.Items {
		if it.Name == "governed-web" {
			found++
			if !it.Active || !strings.Contains(string(it.Spec), `"requires_approval":true`) {
				t.Fatalf("governed profile after approval = %+v, want active with requires_approval", it)
			}
		}
	}
	if found != 1 {
		t.Fatalf("governed profiles named governed-web = %d, want exactly one: %s", found, resp)
	}
}
