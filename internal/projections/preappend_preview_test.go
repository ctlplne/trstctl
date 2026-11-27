// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestProjectionPreviewUsesCommandTransactionAndRollsBack(t *testing.T) {
	st := newStore(t)
	projector := projections.New(st)
	policyID := uuid.NewString()
	makeEvent := func(name string, sequence uint64) events.Event {
		t.Helper()
		data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
			ID: policyID, Name: name, ScopeKind: "manual",
		})
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{ID: uuid.NewString(), Type: projections.EventNotificationRoutingPolicyUpserted,
			TenantID: tenantA, Sequence: sequence, Time: time.Now().UTC(), SchemaVersion: 1, Data: data}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := projector.ApplyTx(ctx, tx, makeEvent("Current route", 1)); err != nil {
			return err
		}
		var name string
		if err := tx.QueryRow(ctx,
			`SELECT name FROM notification_routing_policies WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			tenantA, policyID).Scan(&name); err != nil {
			return err
		}
		if err := projector.PreviewTx(ctx, tx, makeEvent("Updated route", 2)); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`SELECT name FROM notification_routing_policies WHERE tenant_id=$1 AND id=$2`,
			tenantA, policyID).Scan(&name); err != nil {
			return err
		}
		if name != "Current route" {
			t.Fatalf("preview changed committed route to %q", name)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
