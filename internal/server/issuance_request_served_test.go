// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/issuancerequest"
)

// I3 through the running binary.
//
// The lifecycle rules are unit-tested as pure functions, which proves the rules
// and proves nothing about whether a request can reach them. This drives the
// whole thing over HTTP against the assembled server.

type servedRequest struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	Requester      string `json:"requester"`
	DecidedBy      string `json:"decided_by"`
	DecisionReason string `json:"decision_reason"`
	ExpiresAt      string `json:"expires_at"`
}

func openRequest(t *testing.T, h *servedHarness, tok, key, subject string) servedRequest {
	t.Helper()
	ownerAdmin := seedScopedTokenSubject(t, h.store, h.tenant, "owner-admin:"+key, string(authz.OwnersWrite))
	ownerID := servedCreateID(t, h, ownerAdmin, key+"-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": key + "-owner",
	})
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", tok, key, map[string]any{
		"subject":       subject,
		"owner_id":      ownerID,
		"justification": "renewing the payments gateway leaf",
	})
	if status != http.StatusCreated {
		t.Fatalf("open request: status %d body %s", status, body)
	}
	var out servedRequest
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A requester must not be able to approve their own request over HTTP. The unit
// test proves CanDecide refuses; this proves the served path actually calls it.
func TestServedRequesterCannotApproveTheirOwnRequest(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request", "certs:issue")
	req := openRequest(t, h, tok, "i3-self-approve", "payments.example.com")
	if req.Requester != "alice@example.com" {
		t.Fatalf("requester = %q, want the authenticated principal", req.Requester)
	}

	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/approve", tok, "i3-self-approve-2", nil)
	if status == http.StatusOK {
		t.Fatalf("alice approved her own request (status %d, body %s).\n\n"+
			"That is a bypass of dual control that leaves an approval record looking legitimate: "+
			"the row says somebody approved it, and that somebody is the person who asked.",
			status, body)
	}
}

// A denial must carry a reason, and must be final.
func TestServedDenialCarriesAReasonAndIsFinal(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "bob@example.com", "certs:request", "certs:issue")
	req := openRequest(t, h, alice, "i3-deny", "api.example.com")

	// No reason: refused.
	status, _ := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/deny", bob, "i3-deny-noreason", map[string]any{})
	if status == http.StatusOK {
		t.Fatal("a denial with no reason was accepted. The requester learns only that somebody " +
			"said no, and simply asks again")
	}

	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/deny", bob, "i3-deny-ok", map[string]any{
			"reason": "this hostname is already covered by the wildcard",
		})
	if status != http.StatusOK {
		t.Fatalf("deny: status %d body %s", status, body)
	}
	var denied servedRequest
	if err := json.Unmarshal(body, &denied); err != nil {
		t.Fatal(err)
	}
	if denied.Status != issuancerequest.StateDenied || denied.DecidedBy != "bob@example.com" {
		t.Fatalf("denied request = %+v", denied)
	}

	// A second reviewer must not be able to overturn it.
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/approve", bob, "i3-deny-overturn", nil)
	if status == http.StatusOK {
		t.Fatalf("a denied request was approved (body %s).\n\n"+
			"A closed request that can be re-decided lets a second reviewer overturn the first "+
			"without either of them knowing, and the audit trail shows both with nothing saying "+
			"which one governs.", body)
	}
}

// Only the requester may withdraw. Somebody else closing it is a denial and has
// to be recorded as one, with a reason.
func TestServedOnlyTheRequesterCanCancel(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "bob@example.com", "certs:request", "certs:issue")
	req := openRequest(t, h, alice, "i3-cancel", "cancel.example.com")

	status, _ := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/cancel", bob, "i3-cancel-bob", nil)
	if status == http.StatusOK {
		t.Fatal("bob withdrew alice's request. Someone else closing a request is a DENIAL and " +
			"must be recorded as one, with a reason the requester can act on")
	}
	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/cancel", alice, "i3-cancel-alice", nil)
	if status != http.StatusOK {
		t.Fatalf("alice could not withdraw her own request: %d %s", status, body)
	}
}

// The expiry sweep must close overdue requests with NO decider.
func TestServedExpirySweepClosesWithoutAttributingADecision(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request")
	req := openRequest(t, h, alice, "i3-expiry", "expiring.example.com")

	// Backdate it past due. The sweep's own clock decides; this is the only way
	// to test it without waiting seven days.
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE issuance_requests SET expires_at = $2 WHERE id = $1`,
		req.ID, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := h.srv.RunIssuanceRequestExpiryOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expired %d requests, want 1. Without the sweep a request nobody decided sits in "+
			"the queue forever and the queue's size stops meaning anything", n)
	}
	stored, err := h.store.GetIssuanceRequest(t.Context(), h.tenant, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != issuancerequest.StateExpired {
		t.Fatalf("status = %q, want expired", stored.Status)
	}
	if stored.DecidedBy != "" {
		t.Fatalf("expiry was attributed to %q. Nobody decided it — time ran out — and stamping a "+
			"person on it puts a decision in the audit trail that no human ever made", stored.DecidedBy)
	}
}

// The list surface must serve closed requests too: an auditor asking what was
// DENIED needs them as much as the queue needs the pending ones.
func TestServedListIncludesClosedRequestsAndCountsOpenSeparately(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request", "certs:read")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "bob@example.com", "certs:request", "certs:issue")
	open := openRequest(t, h, alice, "i3-list-open", "open.example.com")
	closed := openRequest(t, h, alice, "i3-list-closed", "closed.example.com")
	_ = open
	if status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+closed.ID+"/deny", bob, "i3-list-deny", map[string]any{
			"reason": "duplicate",
		}); status != http.StatusOK {
		t.Fatalf("deny: %d %s", status, body)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/issuance-requests", alice, nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	var list struct {
		Items []servedRequest `json:"items"`
		Open  int             `json:"open"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("list returned %d items, want both. A list that hides closed requests cannot "+
			"answer what was denied", len(list.Items))
	}
	if list.Open != 1 {
		t.Fatalf("open = %d, want 1. One total cannot say whether a queue needs attention or is "+
			"merely long with history", list.Open)
	}
}
