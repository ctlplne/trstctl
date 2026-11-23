// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
	"trstctl.com/trstctl/internal/projections"
)

func TestDirectCertificateMetadataProducerWaitsForOrderBeforeAppend(t *testing.T) {
	st := newServerTestStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	held := make(chan struct{})
	release := make(chan struct{})
	ownerDone := make(chan error, 1)
	go func() {
		ownerDone <- st.WithTenant(ctx, servedTestTenant, func(tx pgx.Tx) error {
			if err := st.LockCertificateMetadataOrderTx(ctx, tx, servedTestTenant); err != nil {
				return err
			}
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	select {
	case <-held:
	case err := <-ownerDone:
		t.Fatalf("hold metadata order: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(projections.CertificateRevoked{
		Fingerprint: "direct-metadata-order-fixture", Serial: "1", Reason: "cessationOfOperation", RevokedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- (&secretRevocationSink{store: st, log: log}).appendAndProject(ctx, events.Event{
			TenantID: servedTestTenant, Type: projections.EventCertificateRevoked, Data: raw,
		})
	}()

	blocked := 0
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		select {
		case err := <-done:
			t.Fatalf("direct producer crossed the held metadata order: %v", err)
		default:
		}
		//trstctl:system-query — only this disposable fixture database's advisory lock wait count is inspected; no tenant data or backend identity is selected (AN-1 exemption).
		if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%lock_certificate_metadata_order%'`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if blocked != 1 {
		t.Fatal("direct producer never waited for the actual metadata order lock")
	}
	if head, err := log.LastSequence(ctx); err != nil || head != before {
		t.Fatalf("direct producer published before metadata order ownership: head=%d before=%d err=%v", head, before, err)
	}
	close(release)
	released = true
	if err := <-ownerDone; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != before+1 {
		t.Fatalf("direct producer did not publish after metadata order ownership: head=%d before=%d err=%v", head, before, err)
	}
}
