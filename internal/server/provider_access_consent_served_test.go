// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A95: the customer's side of tenant-scoped break-glass with dual consent.
// The tenant sets a policy requiring its own consent, sees the Provider's
// emergency requests (projected from the Provider's authority event recorded
// under this tenant), and its people approve or deny each grant once; the
// decisions are immutable events in the tenant's own history.
func TestServedTenantConsentsToProviderEmergencyAccessA95(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "alice@customer.test", "access:read", "access:write")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "bob@customer.test", "access:read", "access:write")
	carol := seedScopedTokenSubject(t, h.store, h.tenant, "carol@customer.test", "access:read", "access:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "reader@customer.test", "access:read")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/provider-access/policy", admin, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"configured":false`) || !strings.Contains(string(body), `"require_tenant_consent":false`) {
		t.Fatalf("policy before setup = %d %s, want unconfigured and not required", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/provider-access/policy", reader, "a95-policy-reader", map[string]any{"require_tenant_consent": true}); status != http.StatusForbidden {
		t.Fatalf("policy change with access:read = %d %s, want 403", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/provider-access/policy", admin, "a95-policy", map[string]any{"require_tenant_consent": true, "approvals": 2})
	if status != http.StatusOK || !strings.Contains(string(body), `"require_tenant_consent":true`) || !strings.Contains(string(body), `"approvals":2`) || !strings.Contains(string(body), "alice@customer.test") {
		t.Fatalf("set policy = %d %s", status, body)
	}
	if !h.hasEvent(t, "tenant.provider_access.policy_set") {
		t.Fatal("the policy change left no tenant.provider_access.policy_set event")
	}

	// The Provider's request is its own authority event, recorded under this
	// tenant; the licensed Provider projection writes it into the customer's
	// request table (ee/provider eventsource), which this core harness seeds
	// the same way.
	now := time.Now().UTC().Truncate(time.Second)
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyProviderAccessRequestedTx(t.Context(), tx, store.ProviderAccessRequest{
			TenantID: h.tenant, GrantID: "grant-a95-1", OperatorEmail: "oncall@provider.example", Reason: "incident 42",
			RequestedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	}); err != nil {
		t.Fatalf("seed the Provider request: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/provider-access/requests", admin, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "grant-a95-1") || !strings.Contains(string(body), "oncall@provider.example") || !strings.Contains(string(body), `"approvals":0`) {
		t.Fatalf("requests after projection = %d %s", status, body)
	}

	// Decisions: one per subject, approvals counted, a denial named.
	consent := func(token, key string, approve bool, reason string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/provider-access/consents/grant-a95-1", token, key, map[string]any{"approve": approve, "reason": reason})
	}
	if status, body := consent(admin, "a95-unknown", true, ""); status != http.StatusCreated {
		t.Fatalf("first approval = %d %s", status, body)
	}
	if status, body := consent(admin, "a95-again", true, ""); status != http.StatusConflict {
		t.Fatalf("same subject again = %d %s, want 409", status, body)
	}
	if status, body := consent(reader, "a95-reader", true, ""); status != http.StatusForbidden {
		t.Fatalf("consent with access:read = %d %s, want 403", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/provider-access/consents/grant-nope", bob, "a95-nope", map[string]any{"approve": true}); status != http.StatusNotFound {
		t.Fatalf("consent on an unknown grant = %d %s, want 404", status, body)
	}
	if status, body := consent(bob, "a95-bob", true, ""); status != http.StatusCreated {
		t.Fatalf("second approval = %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/provider-access/requests", admin, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"approvals":2`) || !strings.Contains(string(body), `"denied":false`) {
		t.Fatalf("requests after two approvals = %d %s", status, body)
	}
	if status, body := consent(carol, "a95-carol-no-reason", false, ""); status != http.StatusBadRequest {
		t.Fatalf("denial without a reason = %d %s, want 400", status, body)
	}
	if status, body := consent(carol, "a95-carol", false, "change window not approved"); status != http.StatusCreated {
		t.Fatalf("denial = %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/provider-access/consents/grant-a95-1", admin, nil)
	if status != http.StatusOK || strings.Count(string(body), `"subject"`) != 3 || !strings.Contains(string(body), "change window not approved") {
		t.Fatalf("consents list = %d %s, want three decisions with the denial reason", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/provider-access/requests", admin, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"denied":true`) {
		t.Fatalf("requests after a denial = %d %s", status, body)
	}
	if !h.hasEvent(t, "tenant.provider_access.consented") {
		t.Fatal("decisions left no tenant.provider_access.consented event")
	}
}
