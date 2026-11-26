// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestHistoricalIssuanceDecisionWithInvalidIdentityReplays(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedAgentJobTenant(t, ctx, st, tenantA)
	now := time.Now().UTC()
	for _, tc := range []struct{ identityID, status string }{
		{"not-a-uuid", "cancelled"},
		{gouuid.NewString(), "cancelled"},
		{gouuid.NewString(), "approved"},
	} {
		id := gouuid.NewString()
		err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return st.ApplyIssuanceRequestOpenedTx(ctx, tx, store.IssuanceRequest{
				ID: id, TenantID: tenantA, Subject: "example.test", Requester: "requester",
				ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		err = st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return st.ApplyIssuanceRequestDecidedTx(ctx, tx, tenantA, id, tc.status, "requester", "decision", tc.identityID, now)
		})
		if err != nil {
			t.Fatalf("historical decision with identity_id %q blocked replay: %v", tc.identityID, err)
		}
		got, err := st.GetIssuanceRequest(ctx, tenantA, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != tc.status || got.IdentityID != "" {
			t.Fatalf("replayed decision = status %q identity %q, want %s with no identity", got.Status, got.IdentityID, tc.status)
		}
	}
}
