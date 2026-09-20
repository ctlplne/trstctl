// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/api"
)

// Exercise the served page against real PostgreSQL: random identifiers are not
// clocks, a retried old receipt is recent activity, and continuation must not
// depend on retaining the previous page's last row.
func TestConnectorReceiptPagesShowRecentActivity(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identity := "44444444-4444-4444-8444-444444444444"
	type item struct {
		ID       string    `json:"id"`
		Tenant   string    `json:"tenant_id"`
		Identity string    `json:"identity_id"`
		Key      string    `json:"idempotency_key"`
		Updated  time.Time `json:"updated_at"`
	}
	seed := func(tenant, id, key string, created, updated time.Time) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			// Read-model fixtures only; production mutations still emit events.
			_, err := tx.Exec(ctx, `INSERT INTO connector_delivery_receipts
			(id,tenant_id,identity_id,destination,connector,target,status,idempotency_key,created_at,updated_at)
			VALUES($1,$2,$3,'connector.deploy','postgresql','qa-database','delivered',$4,$5,$6)`, id, tenant, identity, key, created, updated)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	var expected []item
	for i := 1; i <= 25; i++ {
		id := fmt.Sprintf("30000000-0000-4000-8000-%012d", 1000-i)
		updated := base.Add(time.Duration(i/2) * time.Minute)
		seed(tenantA, id, fmt.Sprintf("key-%d", i), base.Add(-time.Hour), updated)
		expected = append(expected, item{ID: id, Updated: updated})
	}
	// An old creation updated by a delivery retry must lead the first page.
	oldID := expected[0].ID
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE connector_delivery_receipts SET updated_at=$3, attempts=3 WHERE tenant_id=$1 AND id=$2`, tenantA, oldID, base.Add(time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expected[0].Updated = base.Add(time.Hour)
	sort.Slice(expected, func(i, j int) bool {
		if expected[i].Updated.Equal(expected[j].Updated) {
			return expected[i].ID > expected[j].ID
		}
		return expected[i].Updated.After(expected[j].Updated)
	})
	seed(tenantB, "50000000-0000-4000-8000-000000000001", "key-25", base, base.Add(24*time.Hour))
	handler := api.New(s, nil, nil, api.WithInsecureHeaderResolver())
	read := func(tenant string, values url.Values, wantStatus int) ([]item, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/connectors/deliveries?"+values.Encode(), nil)
		req.Header.Set("X-Tenant-ID", tenant)
		req.Header.Set("X-Roles", "admin")
		r := httptest.NewRecorder()
		handler.ServeHTTP(r, req)
		if r.Code != wantStatus {
			t.Fatalf("status=%d want=%d: %s", r.Code, wantStatus, r.Body.String())
		}
		if wantStatus != http.StatusOK {
			return nil, ""
		}
		var body struct {
			Items []item `json:"items"`
			Next  string `json:"next_cursor"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		for _, row := range body.Items {
			if row.Tenant != tenant {
				t.Fatalf("foreign receipt: %+v", row)
			}
		}
		return body.Items, body.Next
	}
	first, cursor := read(tenantA, url.Values{"limit": {"2"}}, http.StatusOK)
	if len(first) != 2 || first[0].ID != oldID || first[1].ID != expected[1].ID || cursor == "" {
		t.Fatalf("recent page: %+v, cursor=%q; expected retried old receipt %s followed by %s", first, cursor, oldID, expected[1].ID)
	}
	got := []string{first[0].ID, first[1].ID}
	// New activity should appear on refresh without shifting older pages.
	newID := "60000000-0000-4000-8000-000000000001"
	seed(tenantA, newID, "new-arrival", base.Add(2*time.Hour), base.Add(2*time.Hour))
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM connector_delivery_receipts WHERE tenant_id=$1 AND id=$2`, tenantA, first[1].ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for page := 0; cursor != "" && page < 20; page++ {
		rows, next := read(tenantA, url.Values{"limit": {"2"}, "cursor": {cursor}}, http.StatusOK)
		for _, row := range rows {
			got = append(got, row.ID)
		}
		cursor = next
	}
	want := make([]string, len(expected))
	for i, row := range expected {
		want[i] = row.ID
	}
	if cursor != "" || !reflect.DeepEqual(got, want) {
		t.Fatalf("chronological pages got=%v want=%v cursor=%q", got, want, cursor)
	}
	latest, _ := read(tenantA, url.Values{"limit": {"1"}}, http.StatusOK)
	if len(latest) != 1 || latest[0].ID != newID {
		t.Fatalf("refresh missed new activity: %+v", latest)
	}
	filtered, _ := read(tenantA, url.Values{"limit": {"2"}, "identity_id": {identity}, "idempotency_key": {"key-25"}}, http.StatusOK)
	if len(filtered) != 1 || filtered[0].Key != "key-25" || filtered[0].Identity != identity {
		t.Fatalf("exact scoped filter: %+v", filtered)
	}
	missing, _ := read(tenantA, url.Values{"identity_id": {"77777777-7777-4777-8777-777777777777"}}, http.StatusOK)
	if len(missing) != 0 {
		t.Fatalf("identity filter ignored: %+v", missing)
	}
	// Previously issued UUID cursors continue from that tenant's current row.
	legacy := base64.RawURLEncoding.EncodeToString([]byte(oldID))
	legacyRows, _ := read(tenantA, url.Values{"limit": {"100"}, "cursor": {legacy}}, http.StatusOK)
	if len(legacyRows) != 23 {
		t.Fatalf("legacy continuation count=%d want23", len(legacyRows))
	}
	for _, bad := range []string{"not-base64", base64.RawURLEncoding.EncodeToString([]byte("2026-09-01T00:00:00Z|------------------------------------")), base64.RawURLEncoding.EncodeToString([]byte("not-a-time|" + oldID))} {
		read(tenantA, url.Values{"cursor": {bad}}, http.StatusBadRequest)
	}
	foreign := base64.RawURLEncoding.EncodeToString([]byte("50000000-0000-4000-8000-000000000001"))
	read(tenantA, url.Values{"cursor": {foreign}}, http.StatusBadRequest)
}
