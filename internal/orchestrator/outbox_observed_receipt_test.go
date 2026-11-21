// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A projected, signed source receipt may retire a recreated intent only after
// the orchestrator has recorded the destination's circuit success. The staging
// state also keeps both dispatchers and agent claimers from performing it again.
func TestObservedReceiptRetiresThroughOrchestratorWithoutRedelivery(t *testing.T) {
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	ob := orchestrator.NewOutbox(st)
	const destination = "connector.deploy"
	const key = "source-observed-after-restore"
	id := enqueue(t, st, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: destination, IdempotencyKey: key, Payload: []byte(`{}`),
	})
	if err := st.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE outbox SET status='receipt_observed'
			WHERE tenant_id=$1 AND id=$2 AND status='pending' AND claimed_by_agent_id IS NULL`, tenantA, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	n, err := ob.DispatchScoped(t.Context(), orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		called = true
		return nil
	}), orchestrator.DestinationScope{IncludeDestinations: []string{destination}})
	if err != nil || n != 0 || called {
		t.Fatalf("receipt-staged intent was dispatched again: n=%d called=%t err=%v", n, called, err)
	}
	completed, err := ob.ReconcileObservedReceipts(t.Context())
	if err != nil || completed != 1 {
		t.Fatalf("orchestrator did not retire exact source receipt: completed=%d err=%v", completed, err)
	}
	row, err := ob.Get(t.Context(), tenantA, id)
	if err != nil || row.Status != "delivered" {
		t.Fatalf("source-observed intent remains unretired: %+v err=%v", row, err)
	}
	var hasDeliveryTime bool
	if err := st.SystemPool().QueryRow(t.Context(),
		`SELECT delivered_at IS NOT NULL FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, id).
		Scan(&hasDeliveryTime); err != nil || !hasDeliveryTime {
		t.Fatalf("source-observed intent has no durable completion time: time=%t err=%v", hasDeliveryTime, err)
	}
	completed, err = ob.ReconcileObservedReceipts(t.Context())
	if err != nil || completed != 0 {
		t.Fatalf("replayed reconciler performed the effect again: completed=%d err=%v", completed, err)
	}
}
