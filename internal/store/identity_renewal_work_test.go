// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

func TestRenewalPreviewFollowsExactTenantJobUntilTerminal(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const identityID = "33333333-3333-4333-8333-333333333333"
	for _, tenant := range []string{tenantA, tenantB} {
		owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenant, Kind: store.OwnerTeam, Name: "renewal owner"})
		if err != nil {
			t.Fatal(err)
		}
		// Isolated read fixtures; product lifecycle mutations remain event-sourced.
		if err := s.UpsertIdentity(ctx, store.Identity{ID: identityID, TenantID: tenant, OwnerID: owner.ID,
			Kind: store.KindX509Certificate, Name: "retry.example.test", Status: "renewal_failed"}); err != nil {
			t.Fatal(err)
		}
	}
	handler := api.New(s, nil, nil, api.WithInsecureHeaderResolver())
	for i, tc := range []struct {
		tenant, identity, destination, status string
		blocked                               bool
	}{
		{tenantB, identityID, "endpoint.renew", "pending", false},
		{tenantA, "another-identity", "endpoint.renew", "pending", false},
		{tenantA, identityID, "ca.renew", "pending", true},
		{tenantA, identityID, "ca.renew", "processing", true},
		{tenantA, identityID, "endpoint.renew", "pending", true},
		{tenantA, identityID, "endpoint.renew", "processing", true},
		{tenantA, identityID, "endpoint.renew", "delivered", false},
		{tenantA, identityID, "endpoint.renew", "failed", false},
		{tenantA, identityID, "notification.expiry", "pending", false},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := []byte(fmt.Sprintf(`{"identity_id":%q}`, tc.identity))
			if tc.destination == "notification.expiry" {
				payload = []byte{0xff, 0x00} // Unrelated binary payloads must never be decoded.
			}
			if err := s.WithTenant(ctx, tc.tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key,status)
				VALUES($1,$2,$3,$4,$5)`, tc.tenant, tc.destination,
					payload, fmt.Sprint(i), tc.status)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/identities/"+identityID+"/transitions/preview", strings.NewReader(`{"to":"renewing","reason":"retry"}`))
			req.Header.Set("X-Tenant-ID", tenantA)
			req.Header.Set("X-Roles", "admin")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			want := http.StatusOK
			if tc.blocked {
				want = http.StatusConflict
			}
			if rec.Code != want {
				t.Fatalf("%+v: preview status=%d want=%d body=%s", tc, rec.Code, want, rec.Body.String())
			}
			if tc.blocked && !strings.Contains(rec.Body.String(), "already has a renewal queued or running") {
				t.Fatalf("blocked preview lacks recovery guidance: %s", rec.Body.String())
			}
			// This fixture has exactly one row. Queue counts include host jobs,
			// other identities in this tenant, and no work from another tenant.
			summary, err := s.GetLifecycleAutomationOutboxSummary(ctx, tenantA)
			if err != nil {
				t.Fatal(err)
			}
			var wantSummary store.LifecycleAutomationOutboxSummary
			if tc.tenant == tenantA {
				switch tc.status {
				case "pending":
					wantSummary.Pending = 1
				case "processing":
					wantSummary.Processing = 1
				case "failed":
					wantSummary.Failed = 1
				}
			}
			if summary != wantSummary {
				t.Fatalf("queue counts=%+v want=%+v", summary, wantSummary)
			}
			if err := s.WithTenant(ctx, tc.tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tc.tenant, fmt.Sprint(i))
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
