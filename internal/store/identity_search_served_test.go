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
