// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestCR086FailedCheckoutExpiryDoesNotStarveAnotherTenant(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	otherTenant := uuid.NewString()
	registerServedTenantID(t, h, otherTenant, "Other checkout tenant")
	now := time.Now().UTC()
	seed := func(tenant string, count int, expiresAt time.Time) []string {
		t.Helper()
		ids := make([]string, 0, count)
		err := h.store.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			for range count {
				id := uuid.NewString()
				ids = append(ids, id)
				if err := h.store.ApplyPAMCheckoutRevealedTx(t.Context(), tx, tenant, store.PAMCheckout{
					RequestID: id, TargetType: pamTargetAccount, TargetID: "account", ProviderID: "fixture-provider",
					AccountSecret: "fixture-account", SecretVersion: 1, RequestedBy: "fixture-requester",
					Reason: "fixture", ApprovalRequestID: uuid.NewString(), RevealedAt: expiresAt.Add(-time.Minute), ExpiresAt: expiresAt,
				}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			err := h.store.WithTenant(context.Background(), tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(context.Background(),
					`DELETE FROM pam_checkouts WHERE tenant_id = $1 AND request_id = ANY($2::uuid[])`, tenant, ids)
				return err
			})
			if err != nil {
				t.Errorf("clean up CR-086 checkout fixtures for %s: %v", tenant, err)
			}
		})
		return ids
	}
	stuck := seed(h.tenant, pamCheckoutExpiryBatch, now.Add(-2*time.Hour))
	sameTenantVictim := seed(h.tenant, 1, now.Add(-90*time.Minute))[0]
	victim := seed(otherTenant, 1, now.Add(-time.Hour))[0]
	stuckSet := make(map[string]bool, len(stuck))
	for _, id := range stuck {
		stuckSet[id] = true
	}
	queued := map[string]bool{}
	service := &pamService{
		store: h.store, log: h.log, projector: h.srv.proj, clock: time.Now,
		secretReader: func(context.Context, string, string) ([]byte, int, error) {
			return []byte("fixture-credential"), 1, nil
		},
		rotation: pamAccountRotation{queue: func(_ context.Context, _, _, _, _, requestID string, _ time.Time, _ int) (string, error) {
			if stuckSet[requestID] {
				return "", errors.New("fixture provider cannot rotate this account")
			}
			queued[requestID] = true
			return "fixture-rotation", nil
		}},
	}
	service.expireCheckouts(t.Context(), now)
	got, err := h.store.GetPAMCheckout(t.Context(), otherTenant, victim)
	if err != nil {
		t.Fatal(err)
	}
	if !queued[victim] || got.Status != "expired" || got.RotationCommandID == "" {
		t.Fatalf("later tenant check-out behind %d unendable rows: rotation queued=%v status=%q command=%q",
			len(stuck), queued[victim], got.Status, got.RotationCommandID)
	}
	service.expireCheckouts(t.Context(), now.Add(time.Minute))
	withinTenant, err := h.store.GetPAMCheckout(t.Context(), h.tenant, sameTenantVictim)
	if err != nil {
		t.Fatal(err)
	}
	if !queued[sameTenantVictim] || withinTenant.Status != "expired" || withinTenant.RotationCommandID == "" {
		t.Fatalf("same-tenant check-out beyond failed page: rotation queued=%v status=%q command=%q",
			queued[sameTenantVictim], withinTenant.Status, withinTenant.RotationCommandID)
	}
}
