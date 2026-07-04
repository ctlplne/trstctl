// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestOutboxDeliveryTimeoutMetricIsLabeledByTenantAndDestination(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		if m.Destination != "connector.deploy" {
			t.Fatalf("unexpected destination %q", m.Destination)
		}
		<-ctx.Done()
		return ctx.Err()
	})
	srv, err := Build(ctx, Deps{
		Store:                 st,
		Log:                   log,
		OutboxHandler:         handler,
		OutboxDeliveryTimeout: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build control plane: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	const tenantID = "11111111-1111-1111-1111-111111111111"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "timeout-metric"}); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}
	var rowID int64
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var e error
		rowID, e = srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    "connector.deploy",
			IdempotencyKey: "timeout-metric-1",
			Payload:        []byte(`{}`),
		})
		return e
	}); err != nil {
		t.Fatalf("enqueue outbox row: %v", err)
	}

	if n, err := srv.outbox.Dispatch(ctx, srv.obHandler); err != nil || n != 1 {
		t.Fatalf("Dispatch n=%d err=%v, want 1, nil", n, err)
	}
	rec, err := srv.outbox.Get(ctx, tenantID, rowID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "pending" || !strings.Contains(rec.LastError, context.DeadlineExceeded.Error()) {
		t.Fatalf("row = {status:%q last_error:%q}, want pending timeout", rec.Status, rec.LastError)
	}

	var buf bytes.Buffer
	if err := srv.registry.WriteProm(&buf); err != nil {
		t.Fatalf("WriteProm: %v", err)
	}
	want := `trstctl_outbox_delivery_timeouts_total{tenant_id="11111111-1111-1111-1111-111111111111",destination="connector.deploy"} 1`
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("timeout metric missing %q from:\n%s", want, buf.String())
	}
}
