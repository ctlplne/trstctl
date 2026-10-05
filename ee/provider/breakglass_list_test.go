// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBreakGlassQueueIsExactCustomerScopedAndPaginated(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)
	store := NewMemStore()
	for _, grant := range []BreakGlassGrant{
		{ID: "alpha-1", TenantID: "alpha", OperatorID: "requester", RequestedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(time.Hour)},
		{ID: "alpha-2", TenantID: "alpha", OperatorID: "requester", RequestedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(time.Hour), ConsentedAt: now.Add(-time.Minute), ConsentedBy: "first"},
		{ID: "alpha-3", TenantID: "alpha", OperatorID: "requester", RequestedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
		{ID: "beta-1", TenantID: "beta", OperatorID: "other", RequestedAt: now, ExpiresAt: now.Add(time.Hour), Reason: "private beta incident"},
	} {
		if _, err := store.CreateBreakGlassGrant(ctx, grant); err != nil {
			t.Fatal(err)
		}
	}
	actor := Operator{ID: "approver", Role: OperatorOperator, MFA: true}
	svc := NewService(Config{License: providerLicense(t, 10), Store: store, Clock: func() time.Time { return now },
		Delegations: StaticDelegations{{OperatorID: actor.ID, CustomerID: "alpha", Operations: []Operation{OpBreakGlass}}}})
	first, err := svc.ListBreakGlassGrants(ctx, actor, "alpha", 2, "")
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != "alpha-3" || first.Items[1].ID != "alpha-2" || first.NextCursor != "alpha-2" {
		t.Fatalf("first exact-customer page = %+v, %v", first, err)
	}
	if first.Items[1].State != GrantAwaitingCoConsent || first.Items[0].State != GrantPending {
		t.Fatalf("queue must expose exact derived states: %+v", first.Items)
	}
	second, err := svc.ListBreakGlassGrants(ctx, actor, "alpha", 2, first.NextCursor)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "alpha-1" || second.NextCursor != "" {
		t.Fatalf("second exact-customer page = %+v, %v", second, err)
	}
	if _, err := svc.ListBreakGlassGrants(ctx, actor, "beta", 2, ""); err == nil {
		t.Fatal("approver learned another customer's emergency queue")
	}
	if _, err := svc.ListBreakGlassGrants(ctx, actor, "alpha", 2, "beta-1"); err == nil {
		t.Fatal("cross-customer cursor was accepted")
	}
	if _, err := svc.ListBreakGlassGrants(ctx, Operator{ID: "no-mfa", Role: OperatorOperator}, "alpha", 2, ""); err == nil {
		t.Fatal("MFA-less operator read an emergency queue")
	}
}

func TestBreakGlassQueueRouteRefusesUndelegatedOperator(t *testing.T) {
	now := time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)
	store := NewMemStore()
	_, _ = store.CreateBreakGlassGrant(context.Background(), BreakGlassGrant{
		ID: "alpha-grant", TenantID: "alpha", OperatorID: "requester", Reason: "incident",
		RequestedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	actor := Operator{ID: "approver", Role: OperatorOperator, MFA: true}
	h := NewHandler(Config{License: providerLicense(t, 10), Store: store,
		Authenticator: consoleAuthorityAuth{actor},
		Delegations:   StaticDelegations{{OperatorID: actor.ID, CustomerID: "alpha", Operations: []Operation{OpBreakGlass}}},
		Clock:         func() time.Time { return now }})
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	good := request("/provider/v1/tenants/alpha/breakglass?limit=25")
	if good.Code != http.StatusOK {
		t.Fatalf("delegated queue = %d: %s", good.Code, good.Body.String())
	}
	var page BreakGlassGrantPage
	if err := json.Unmarshal(good.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].ID != "alpha-grant" {
		t.Fatalf("queue response = %+v, %v", page, err)
	}
	if bad := request("/provider/v1/tenants/beta/breakglass?limit=25"); bad.Code != http.StatusForbidden {
		t.Fatalf("undelegated queue = %d, want 403", bad.Code)
	}
	if bad := request("/provider/v1/tenants/alpha/breakglass?limit=101"); bad.Code != http.StatusBadRequest {
		t.Fatalf("unbounded queue = %d, want 400", bad.Code)
	}
}
