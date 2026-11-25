// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// CR-972: a retained token minted for a second subject must not create a
// request that its minter can then approve under their own sign-in.
func TestServedHistoricalDelegatedTokenCannotOpenApprovalGatedRequest(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	minter := seedScopedTokenSubject(t, h.store, h.tenant, "cr972-minter", "certs:request", "certs:issue", "owners:read")
	delegated := seedHistoricalDelegatedToken(t, h.srv.orch, h.tenant, "cr972-minter", "cr972-service",
		[]string{"certs:request", "certs:read", "owners:read"})
	ownerAdmin := seedScopedTokenSubject(t, h.store, h.tenant, "cr972-owner-admin", "owners:write")
	ownerID := servedCreateID(t, h, ownerAdmin, "cr972-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": "cr972-owner",
	})
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/owners", delegated, nil); status != http.StatusOK {
		t.Fatalf("retained delegated token cannot read ordinary inventory: %d %s", status, body)
	}
	input := map[string]any{"subject": "cr972.example.test", "owner_id": ownerID, "justification": "reviewed certificate"}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", delegated, "cr972-delegated-open", input)
	if status != http.StatusForbidden || !strings.Contains(string(body), "minted") {
		t.Errorf("delegated token opened an approvable issuance request: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", minter, "cr972-self-open", input)
	if status != http.StatusCreated {
		t.Fatalf("minter's own credential could not open an ordinary issuance request: %d %s", status, body)
	}
}

// A previously opened request has to remain protected after new delegated
// requests are refused. The old event names only the delegated subject, while
// the retained token record identifies who minted that subject's credential.
func TestServedHistoricalDelegatedRequestCannotBeApprovedByItsMinter(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	minter := seedScopedTokenSubject(t, h.store, h.tenant, "cr972-old-minter", "certs:issue")
	independent := seedScopedTokenSubject(t, h.store, h.tenant, "cr972-independent", "certs:issue")
	_ = seedHistoricalDelegatedToken(t, h.srv.orch, h.tenant, "cr972-old-minter", "cr972-old-service",
		[]string{"certs:request"})
	request, err := h.srv.orch.OpenIssuanceRequest(context.Background(), h.tenant, projections.IssuanceRequestOpened{
		Subject: "cr972-old.example.test", Requester: "cr972-old-service", Justification: "retained delegated request",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/issuance-requests/" + request.ID + "/approve"
	status, body := secretsReqKey(t, h, http.MethodPost, path, minter, "cr972-old-minter-decision", nil)
	if status != http.StatusForbidden || !strings.Contains(string(body), "requester") {
		t.Errorf("minter approved a retained delegated request: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path, independent, "cr972-old-independent-decision", nil)
	if status != http.StatusOK {
		t.Fatalf("independent reviewer could not approve retained request: %d %s", status, body)
	}
}
