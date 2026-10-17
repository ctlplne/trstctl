// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

// A browser search must search the authenticated tenant before pagination. A
// local filter over the API's default 20 rows hides real records in a large
// estate and makes exact multi-row actions incomplete.
func TestIdentitySearchFiltersBeforeCursorAndBindsTenant(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	ownerA, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "QA Search Operator"})
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantB, Kind: store.OwnerTeam, Name: "QA Search Operator"})
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 30; n++ {
		name := fmt.Sprintf("unrelated-%02d.example.test", n)
		if n == 2 || n == 29 {
			name = fmt.Sprintf("qa-bulk-console-%02d.example.test", n)
		}
		id := fmt.Sprintf("00000000-0000-4000-8000-%012x", n)
		if err := s.UpsertIdentity(ctx, store.Identity{ID: id, TenantID: tenantA, OwnerID: ownerA.ID,
			Kind: store.KindX509Certificate, Name: name, Status: "issued"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertIdentity(ctx, store.Identity{ID: "00000000-0000-4000-8000-00000000001f", TenantID: tenantA,
		OwnerID: ownerA.ID, Kind: store.KindSecret, Name: "qa-bulk-console-secret.example.test", Status: "requested"}); err != nil {
		t.Fatal(err)
	}
	// The same UUID and matching name in another tenant must not leak into A.
	if err := s.UpsertIdentity(ctx, store.Identity{ID: "00000000-0000-4000-8000-00000000001d", TenantID: tenantB,
		OwnerID: ownerB.ID, Kind: store.KindX509Certificate, Name: "qa-bulk-console-foreign.example.test", Status: "issued"}); err != nil {
		t.Fatal(err)
	}
	handler := api.New(s, nil, nil, api.WithInsecureHeaderResolver())
	read := func(tenant, query string) (int, []string, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/identities?"+query, nil)
		req.Header.Set("X-Tenant-ID", tenant)
		req.Header.Set("X-Roles", "admin")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var page struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		if rec.Code == http.StatusOK && json.Unmarshal(rec.Body.Bytes(), &page) != nil {
			t.Fatalf("decode identity search: %s", rec.Body.String())
		}
		names := make([]string, 0, len(page.Items))
		for _, item := range page.Items {
			names = append(names, item.Name)
		}
		return rec.Code, names, page.NextCursor
	}
	query := "q=" + url.QueryEscape("qa-bulk-console") + "&kind=x509_certificate&limit=1"
	code, first, cursor := read(tenantA, query)
	if code != http.StatusOK || len(first) != 1 || first[0] != "qa-bulk-console-02.example.test" || cursor == "" {
		t.Fatalf("first filtered page: http=%d names=%v cursor=%q", code, first, cursor)
	}
	code, second, next := read(tenantA, query+"&cursor="+url.QueryEscape(cursor))
	if code != http.StatusOK || len(second) != 1 || second[0] != "qa-bulk-console-29.example.test" || next != "" {
		t.Fatalf("second filtered page: http=%d names=%v cursor=%q", code, second, next)
	}
	code, foreign, _ := read(tenantB, "q=qa-bulk-console&limit=20")
	if code != http.StatusOK || len(foreign) != 1 || foreign[0] != "qa-bulk-console-foreign.example.test" {
		t.Fatalf("tenant B search: http=%d names=%v", code, foreign)
	}
	code, secrets, _ := read(tenantA, "q=qa-bulk-console&kind=secret&limit=20")
	if code != http.StatusOK || len(secrets) != 1 || secrets[0] != "qa-bulk-console-secret.example.test" {
		t.Fatalf("kind filter: http=%d names=%v", code, secrets)
	}
	code, literal, _ := read(tenantA, "q=%25_%25&limit=20")
	if code != http.StatusOK || len(literal) != 0 {
		t.Fatalf("wildcard characters must be literal: http=%d names=%v", code, literal)
	}
	if code, _, _ := read(tenantA, "kind=unsupported"); code != http.StatusBadRequest {
		t.Fatalf("invalid kind http=%d, want 400", code)
	}
}

// The console's health tiles must use the complete event-derived tenant read
// model, not a default 20-row cursor page presented as estate-wide counts.
func TestIdentitySummaryCoversAllTenantRowsBeyondPage(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "summary owner"})
	if err != nil {
		t.Fatal(err)
	}
	foreignOwner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantB, Kind: store.OwnerTeam, Name: "foreign owner"})
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 30; n++ {
		status := "issued"
		if n > 20 {
			status = "deployed"
		}
		if err := s.UpsertIdentity(ctx, store.Identity{
			ID: fmt.Sprintf("00000000-0000-4000-8000-%012x", n), TenantID: tenantA,
			OwnerID: owner.ID, Kind: store.KindX509Certificate, Name: fmt.Sprintf("summary-%02d", n), Status: status,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertIdentity(ctx, store.Identity{
		ID: "00000000-0000-4000-8000-00000000001f", TenantID: tenantB,
		OwnerID: foreignOwner.ID, Kind: store.KindSecret, Name: "foreign-summary", Status: "revoked",
	}); err != nil {
		t.Fatal(err)
	}
	handler := api.New(s, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/identities?limit=1&include_summary=true", nil)
	req.Header.Set("X-Tenant-ID", tenantA)
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("identity summary http=%d body=%s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items   []json.RawMessage `json:"items"`
		Summary struct {
			Total    int64            `json:"total"`
			ByStatus map[string]int64 `json:"by_status"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Summary.Total != 30 || page.Summary.ByStatus["issued"] != 20 || page.Summary.ByStatus["deployed"] != 10 || page.Summary.ByStatus["revoked"] != 0 {
		t.Fatalf("first page must keep one row while full tenant summary covers 30: page=%s", rec.Body.String())
	}
	filtered := httptest.NewRequest(http.MethodGet, "/api/v1/identities?limit=1&q=no-such-name&kind=secret&include_summary=true", nil)
	filtered.Header.Set("X-Tenant-ID", tenantA)
	filtered.Header.Set("X-Roles", "admin")
	filteredResult := httptest.NewRecorder()
	handler.ServeHTTP(filteredResult, filtered)
	if filteredResult.Code != http.StatusOK || json.Unmarshal(filteredResult.Body.Bytes(), &page) != nil || len(page.Items) != 0 || page.Summary.Total != 30 {
		t.Fatalf("search filter must not shrink full tenant summary: http=%d body=%s", filteredResult.Code, filteredResult.Body.String())
	}
	invalid := httptest.NewRequest(http.MethodGet, "/api/v1/identities?include_summary=maybe", nil)
	invalid.Header.Set("X-Tenant-ID", tenantA)
	invalid.Header.Set("X-Roles", "admin")
	invalidResult := httptest.NewRecorder()
	handler.ServeHTTP(invalidResult, invalid)
	if invalidResult.Code != http.StatusBadRequest {
		t.Fatalf("invalid summary option http=%d, want 400", invalidResult.Code)
	}
}
