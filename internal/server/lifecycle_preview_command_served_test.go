// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// The console derives a retry key from the server's effect-free preview. A new
// browser session for the same requester recovers that exact command, while a
// different requester or changed reason cannot inherit its approval authority.
func TestServedLifecyclePreviewBindsRequesterAndRecoversApprovedCommand(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
	})
	scopes := []string{string(authz.OwnersWrite), string(authz.IdentitiesWrite), string(authz.IdentitiesRead), string(authz.CertsRequest), string(authz.CertsIssue)}
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "preview-requester", scopes...)
	newSession := seedScopedTokenSubject(t, h.store, h.tenant, "preview-requester", scopes...)
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "preview-reviewer", scopes...)
	create := func(path, key string, value any) string {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, path, requester, key, value)
		var result struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &result) != nil || result.ID == "" {
			t.Fatalf("create %s: %d %s", path, status, body)
		}
		return result.ID
	}
	owner := create("/api/v1/owners", "preview-command-owner", map[string]any{"kind": "workload", "name": "preview-command"})
	id := create("/api/v1/identities", "preview-command-identity", map[string]any{"kind": "x509_certificate", "name": "preview-command.example.test", "owner_id": owner})
	path := "/api/v1/identities/" + id + "/transitions"
	type plan struct {
		Fingerprint string `json:"request_fingerprint"`
		Version     uint64 `json:"expected_version"`
	}
	preview := func(token, reason string) plan {
		t.Helper()
		before, err := h.log.LastSequence(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		status, body := secretsReq(t, h, http.MethodPost, path+"/preview", token, map[string]any{"to": "issued", "reason": reason})
		var result plan
		if status != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Fingerprint == "" {
			t.Fatalf("preview: %d %s", status, body)
		}
		after, err := h.log.LastSequence(t.Context())
		if err != nil || before != after {
			t.Fatalf("successful preview changed event history: before=%d after=%d err=%v", before, after, err)
		}
		return result
	}
	first := preview(requester, "review this issuance")
	if got := preview(newSession, "review this issuance"); got != first {
		t.Fatalf("same principal in a new session lost its command: %+v != %+v", got, first)
	}
	if preview(reviewer, "review this issuance").Fingerprint == first.Fingerprint {
		t.Fatal("different requester inherited the same command fingerprint")
	}
	if preview(requester, "changed business purpose").Fingerprint == first.Fingerprint {
		t.Fatal("changed intent reused the prior command fingerprint")
	}
	key := "identity-transition:" + first.Fingerprint
	request := map[string]any{"to": "issued", "reason": "review this issuance", "expected_version": first.Version}
	status, body := secretsReqKey(t, h, http.MethodPost, path, requester, key, request)
	var refusal struct {
		ID string `json:"approval_request_id"`
	}
	if status != http.StatusForbidden || json.Unmarshal(body, &refusal) != nil || refusal.ID == "" {
		t.Fatalf("open genuine governed command: %d %s", status, body)
	}
	approval, err := h.store.GetOperationApproval(t.Context(), h.tenant, refusal.ID)
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+approval.ID+"/approvals", reviewer, "preview-independent-review", map[string]any{"intent_digest": approval.IntentDigest})
	if status != http.StatusOK {
		t.Fatalf("independent review: %d %s", status, body)
	}
	reopened := preview(newSession, "review this issuance")
	if reopened != first {
		t.Fatal("approval changed an otherwise identical command preview")
	}
	for range 2 {
		status, body = secretsReqKey(t, h, http.MethodPost, path, newSession, "identity-transition:"+reopened.Fingerprint, request)
		if status != http.StatusOK {
			t.Fatalf("approved retry: %d %s", status, body)
		}
	}
	if count := eventCount(t, h.log, h.tenant, projections.EventIdentityIssued); count != 1 {
		t.Fatalf("approved command recorded %d issuance events; want one", count)
	}
}
