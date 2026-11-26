// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

func TestIssuanceCancellationRefusesIdentityIDBeforeEventAppend(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "requester@example.test", "certs:request")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "reviewer@example.test", "certs:issue")
	req := openRequest(t, h, requester, "n0003-cancel", "n0003.example.test")
	before := servedEventCount(t, h, projections.EventIssuanceRequestDecided)
	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/cancel", requester, "n0003-invalid",
		map[string]any{"identity_id": "not-a-uuid"})
	if status != http.StatusBadRequest {
		t.Fatalf("invalid identity_id returned %d: %s", status, body)
	}
	if after := servedEventCount(t, h, projections.EventIssuanceRequestDecided); after != before {
		t.Fatalf("invalid identity_id appended %d decision events", after-before)
	}
	for _, identityID := range []string{"not-a-uuid", uuid.NewString()} {
		status, body = secretsReqKey(t, h, http.MethodPost,
			"/api/v1/issuance-requests/"+req.ID+"/approve", reviewer, "n0003-approve-"+identityID,
			map[string]any{"identity_id": identityID})
		if status != http.StatusBadRequest {
			t.Fatalf("approval identity_id %q returned %d: %s", identityID, status, body)
		}
		if after := servedEventCount(t, h, projections.EventIssuanceRequestDecided); after != before {
			t.Fatalf("approval identity_id %q appended %d decision events", identityID, after-before)
		}
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/cancel", requester, "n0003-valid", nil)
	if status != http.StatusOK {
		t.Fatalf("valid cancellation returned %d: %s", status, body)
	}
}
