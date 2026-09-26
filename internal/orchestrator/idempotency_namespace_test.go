// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestApplicationIdempotencyCannotClaimInternalOffboardReceiver(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			idem := orchestrator.NewMemoryIdempotency()
			var st *store.Store
			if backend == "postgres" {
				st = newStore(t)
				idem = orchestrator.NewIdempotency(st)
			}
			ctx := t.Context()
			const tenantID = "e2f3ae18-40a8-499e-94fb-a0d958294cff"
			key := store.TenantOffboardReceiverKeyPrefix + "tenant-offboard-f99220a4-2652-457f-a8d2-0f05b78d290c"
			callback := func(context.Context) ([]byte, error) {
				t.Fatal("caller entered an internal command namespace")
				return nil, nil
			}
			for name, call := range map[string]func() error{
				"ordinary":      func() error { _, err := idem.Do(ctx, tenantID, key, callback); return err },
				"bound":         func() error { _, err := idem.DoBound(ctx, tenantID, key, "binding", callback); return err },
				"durable":       func() error { _, err := idem.DoDurableEffect(ctx, tenantID, key, callback); return err },
				"durable bound": func() error { _, err := idem.DoDurableEffectBound(ctx, tenantID, key, "binding", callback); return err },
				"at most once":  func() error { _, err := idem.DoAtMostOnceEffect(ctx, tenantID, key, callback); return err },
				"result":        func() error { _, err := idem.Result(ctx, tenantID, key); return err },
				"bound result":  func() error { _, err := idem.BoundResult(ctx, tenantID, key, "binding"); return err },
				"completion":    func() error { _, err := idem.BoundResultCompleted(ctx, tenantID, key, "binding"); return err },
				"lookup":        func() error { _, _, err := idem.LookupBound(ctx, tenantID, key, "binding"); return err },
				"prepared": func() error {
					_, err := idem.DoPreparedDurableEffectBound(ctx, tenantID, key, "binding",
						func(context.Context, pgx.Tx) (orchestrator.PreparedDurableEffectClaim, error) {
							t.Fatal("reserved key reached prepare")
							return orchestrator.PreparedDurableEffectClaim{}, nil
						}, func(context.Context, pgx.Tx, []byte) error { t.Fatal("reserved key reached verification"); return nil }, callback)
					return err
				},
			} {
				t.Run(name, func(t *testing.T) {
					if err := call(); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
						t.Fatalf("reserved namespace result=%v", err)
					}
				})
			}
			if st != nil {
				if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
					_, err := idem.PrepareTenantRegistrationTx(ctx, tx, tenantID, key, "binding",
						"tenant-registration-d4c4682c-6472-4242-a265-45200b329f50")
					if !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
						t.Fatalf("registration claimed internal namespace: %v", err)
					}
					var count int
					if err := tx.QueryRow(ctx, `SELECT count(*) FROM idempotency_keys WHERE tenant_id=$1 AND key=$2`, tenantID, key).Scan(&count); err != nil {
						return err
					}
					if count != 0 {
						t.Fatal("refused requests left a false deletion receiver")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
