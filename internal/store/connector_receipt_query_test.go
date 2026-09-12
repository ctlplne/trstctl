// SPDX-License-Identifier: MPL-2.0
package store_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/api"
)

// The served read must find an exact preview result even when its UUID sorts
// beyond a full tenant page. Another tenant's identical key must stay invisible.
func TestConnectorReceiptExactKeyReadBeyondTenantPage(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	key := "connector-test:target:review+key:result"
	for tenantIndex, tenant := range []string{tenantA, tenantB} {
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			for i := 1; i <= 25; i++ {
				fixtureKey := fmt.Sprintf("unrelated:%d", i)
				if i == 25 {
					fixtureKey = key
				}
				id := fmt.Sprintf("%08d-0000-4000-8000-%012d", tenantIndex+1, i)
				// Seed read-model fixtures only; no product mutation bypasses events.
				if _, err := tx.Exec(ctx, `INSERT INTO connector_delivery_receipts
				(id,tenant_id,destination,connector,target,status,idempotency_key,created_at,updated_at)
				VALUES($1,$2,'connector.test','caddy','same-target','dry_run_planned',$3,now(),now())`, id, tenant, fixtureKey); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	handler := api.New(s, nil, nil, api.WithInsecureHeaderResolver())
	for _, tenant := range []string{tenantA, tenantB} {
		for _, queryKey := range []string{key, "missing-key"} {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/connectors/deliveries?limit=2&idempotency_key="+url.QueryEscape(queryKey), nil)
			req.Header.Set("X-Tenant-ID", tenant)
			req.Header.Set("X-Roles", "admin")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			var got struct {
				Items []struct {
					TenantID string `json:"tenant_id"`
					Key      string `json:"idempotency_key"`
				} `json:"items"`
				Next string `json:"next_cursor"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			want := 0
			if queryKey == key {
				want = 1
			}
			if len(got.Items) != want || got.Next != "" {
				t.Fatalf("key %q: got %s", queryKey, rec.Body.String())
			}
			if want == 1 && (got.Items[0].TenantID != tenant || got.Items[0].Key != key) {
				t.Fatalf("cross-tenant or wrong-key result: %s", rec.Body.String())
			}
		}
	}
}
