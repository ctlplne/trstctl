// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/cmdbexport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestCMDBExportRecoversAnAppendWhoseOutboxTransactionRolledBack(t *testing.T) {
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	ctx := t.Context()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	outbox := orchestrator.NewOutbox(st)
	orch := orchestrator.NewOrchestrator(log, st, outbox)
	command := cmdbexport.Command{ID: "33333333-3333-4333-8333-333333333333", CertificateID: "44444444-4444-4444-8444-444444444444", Fingerprint: strings.Repeat("a", 64), BindingID: "writer", BindingDigest: "sha256:" + strings.Repeat("b", 64)}
	// This trigger belongs only to this disposable package database. It forces
	// the SQL intent to roll back after the independent event log acknowledged.
	_, err = st.SystemPool().Exec(ctx, `CREATE FUNCTION test_cmdb_export_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'CMDB export transaction fault'; END $$;
		CREATE TRIGGER test_cmdb_export_fault BEFORE INSERT ON outbox FOR EACH ROW WHEN (NEW.destination = 'cmdb.certificate_export') EXECUTE FUNCTION test_cmdb_export_fault()`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(ctx, `DROP TRIGGER IF EXISTS test_cmdb_export_fault ON outbox; DROP FUNCTION IF EXISTS test_cmdb_export_fault()`)
	})
	if err := orch.RequestCMDBCertificateExport(ctx, tenantA, command); err == nil {
		t.Fatal("faulted SQL transaction claimed success")
	}
	if _, err := st.GetOutboxAttemptByKey(ctx, tenantA, cmdbexport.Destination, command.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("rolled-back intent: %v", err)
	}
	source, found, err := log.EventByID(ctx, command.ID)
	if err != nil || !found {
		t.Fatalf("source missing: %v", err)
	}
	var retained cmdbexport.Command
	if err := json.Unmarshal(source.Data, &retained); err != nil || retained != command {
		t.Fatalf("retained command changed: %+v %v", retained, err)
	}
	if _, err := st.SystemPool().Exec(ctx, `DROP TRIGGER test_cmdb_export_fault ON outbox; DROP FUNCTION test_cmdb_export_fault()`); err != nil {
		t.Fatal(err)
	}
	if healed, err := orch.ReconcileOutbox(ctx, log); err != nil || healed != 1 {
		t.Fatalf("reconcile healed=%d err=%v", healed, err)
	}
	if _, err := st.GetOutboxAttemptByKey(ctx, tenantA, cmdbexport.Destination, command.ID); err != nil {
		t.Fatal(err)
	}
	if err := orch.RequestCMDBCertificateExport(ctx, tenantA, command); err != nil {
		t.Fatal(err)
	}
	changed := command
	changed.CertificateID = "55555555-5555-4555-8555-555555555555"
	if err := orch.RequestCMDBCertificateExport(ctx, tenantA, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed command accepted: %v", err)
	}
}
