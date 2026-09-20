// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

func createAUD78Owner(t *testing.T, h *servedHarness, tenantID, name string) string {
	t.Helper()
	writer := seedScopedToken(t, h.store, tenantID, string(authz.OwnersWrite))
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", writer, map[string]any{
		"kind": "team", "name": name, "email": "payments@example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create %s owner: status %d body %s", tenantID, status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil || owner.ID == "" {
		t.Fatalf("decode %s owner: id=%q err=%v body=%s", tenantID, owner.ID, err, body)
	}
	return owner.ID
}

func assertAUD78Problem(t *testing.T, body []byte, wantDetail string) {
	t.Helper()
	var got struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode problem: %v body=%s", err, body)
	}
	if got.Status != http.StatusBadRequest && got.Status != http.StatusUnprocessableEntity {
		t.Fatalf("problem status = %d, want 400 or 422; body=%s", got.Status, body)
	}
	if got.Detail != wantDetail {
		t.Fatalf("problem detail = %q, want %q", got.Detail, wantDetail)
	}
}

func TestSelfServiceIssuanceRequestOwnerContractAUD78(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	const otherTenant = "22222222-2222-2222-2222-222222222222"
	ownerID := createAUD78Owner(t, h, h.tenant, "Payments platform")
	otherOwnerID := createAUD78Owner(t, h, otherTenant, "Other tenant")
	profileAdmin := seedScopedTokenSubject(t, h.store, h.tenant, "profile-admin",
		string(authz.ProfilesWrite))
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", profileAdmin,
		"aud-78-profile", map[string]any{
			"name": "web-server", "spec": map[string]any{"max_ttl_seconds": 2_592_000},
		}); status != http.StatusCreated {
		t.Fatalf("create request profile: status %d body %s", status, body)
	}
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "oidc|dev-1",
		string(authz.CertsRequest), string(authz.CertsRead), string(authz.OwnersRead))
	identityWriter := seedScopedTokenSubject(t, h.store, h.tenant, "oidc|dev-1",
		string(authz.IdentitiesWrite))

	// Keep the original failing surface closed too. Older clients can still call
	// the identity endpoint directly; an OIDC subject must be rejected as a bad
	// relational key instead of reaching PostgreSQL's uuid cast and becoming a
	// generic 500.
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", identityWriter,
		"aud-78-legacy-identity", map[string]any{
			"kind": "x509_certificate", "name": "legacy-payments-api", "owner_id": "oidc|dev-1",
		})
	if status != http.StatusBadRequest {
		t.Fatalf("legacy identity invalid owner: status %d, want 400; body=%s", status, body)
	}
	assertAUD78Problem(t, body, "owner_id must be a valid UUID")

	headBeforeRefusals, err := h.log.LastSequence(context.Background())
	if err != nil {
		t.Fatalf("event head before refusals: %v", err)
	}
	for _, tc := range []struct {
		name       string
		ownerID    string
		wantStatus int
		wantDetail string
	}{
		{name: "missing", wantStatus: http.StatusBadRequest, wantDetail: "owner_id is required"},
		{name: "OIDC subject is not a UUID", ownerID: "oidc|dev-1", wantStatus: http.StatusBadRequest, wantDetail: "owner_id must be a valid UUID"},
		{name: "other tenant", ownerID: otherOwnerID, wantStatus: http.StatusUnprocessableEntity, wantDetail: "owner_id does not reference an existing owner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", requester,
				"aud-78-refuse-"+tc.name, map[string]any{
					"subject": "payments-api", "profile": "web-server:1", "owner_id": tc.ownerID,
				})
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", status, tc.wantStatus, body)
			}
			assertAUD78Problem(t, body, tc.wantDetail)
		})
	}
	headAfterRefusals, err := h.log.LastSequence(context.Background())
	if err != nil {
		t.Fatalf("event head after refusals: %v", err)
	}
	if headAfterRefusals != headBeforeRefusals {
		t.Fatalf("invalid owner requests appended events: head %d -> %d", headBeforeRefusals, headAfterRefusals)
	}

	input := map[string]any{
		"subject": "payments-api", "profile": "web-server:1", "owner_id": ownerID,
		"justification": "staging TLS", "origin": "console",
	}
	status, createdBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", requester,
		"aud-78-create", input)
	if status != http.StatusCreated {
		t.Fatalf("create request: status %d body %s", status, createdBody)
	}
	var created struct {
		ID        string `json:"id"`
		OwnerID   string `json:"owner_id"`
		Requester string `json:"requester"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(createdBody, &created); err != nil {
		t.Fatalf("decode created request: %v body=%s", err, createdBody)
	}
	if created.ID == "" || created.OwnerID != ownerID || created.Requester != "oidc|dev-1" || created.Status != "requested" {
		t.Fatalf("created request = %+v, want bound owner/requester/requested", created)
	}
	headAfterCreate, err := h.log.LastSequence(context.Background())
	if err != nil {
		t.Fatalf("event head after create: %v", err)
	}

	replayStatus, replayBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", requester,
		"aud-78-create", input)
	if replayStatus != http.StatusCreated || !bytes.Equal(replayBody, createdBody) {
		t.Fatalf("idempotent replay = status %d body %s, want original 201 body %s", replayStatus, replayBody, createdBody)
	}
	headAfterReplay, err := h.log.LastSequence(context.Background())
	if err != nil {
		t.Fatalf("event head after replay: %v", err)
	}
	if headAfterReplay != headAfterCreate {
		t.Fatalf("idempotent replay appended event: head %d -> %d", headAfterCreate, headAfterReplay)
	}

	status, inboxBody := secretsReq(t, h, http.MethodGet, "/api/v1/issuance-requests", requester, nil)
	if status != http.StatusOK {
		t.Fatalf("list pending request inbox: status %d body %s", status, inboxBody)
	}
	var inbox struct {
		Open  int `json:"open"`
		Items []struct {
			ID      string `json:"id"`
			OwnerID string `json:"owner_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(inboxBody, &inbox); err != nil {
		t.Fatalf("decode pending request inbox: %v body=%s", err, inboxBody)
	}
	if inbox.Open != 1 || len(inbox.Items) != 1 || inbox.Items[0].ID != created.ID || inbox.Items[0].OwnerID != ownerID {
		t.Fatalf("pending request inbox = %+v, want one owner-bound request %s", inbox, created.ID)
	}
}
