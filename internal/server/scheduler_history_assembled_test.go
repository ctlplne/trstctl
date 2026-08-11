// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	backupartifact "trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/schedulerhistory"
	"trstctl.com/trstctl/internal/store"
)

func TestSchedulerHistorySanitationClosesAssembledSurfacesAcrossRestoreRetentionAndRestart(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID   = "11111111-1111-1111-1111-111111111111"
		scheduleID = "22222222-2222-2222-2222-222222222222"
		runID      = "33333333-3333-3333-3333-333333333333"
		runEventID = "legacy-scheduler-run"
		secretText = "https://operator:provider-credential@example.invalid"
	)
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "AUD-116"}); err != nil {
		t.Fatal(err)
	}
	auditKey, err := jose.GenerateRSASigningKey("aud-116-assembled")
	if err != nil {
		t.Fatal(err)
	}
	sourceCfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}
	source, err := openHistoryAwareEventLog(ctx, sourceCfg, st, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	old := time.Now().UTC().Add(-48 * time.Hour)
	fixtures := []events.Event{
		{
			ID: "tenant-registration", Type: projections.EventTenantRegistered,
			TenantID: tenantID, Time: old, Data: []byte(`{"name":"AUD-116"}`),
		},
		{
			ID: "rotation-schedule", Type: projections.EventSecretRotationScheduleUpserted,
			TenantID: tenantID, Time: old.Add(time.Second),
			Data: []byte(`{"id":"` + scheduleID + `","name":"assembled","provider":"vault","key":"database/password","old_ref":"version:1","interval_seconds":3600,"enabled":true,"next_run_at":"` + old.Add(time.Hour).Format(time.RFC3339Nano) + `"}`),
		},
		{
			ID: runEventID, Type: schedulerhistory.EventType,
			TenantID: tenantID, Time: old.Add(2 * time.Second), SchemaVersion: 1,
			Data: []byte(`{"schedule_id":"` + scheduleID + `","run_id":"` + runID + `","status":"failed","new_ref":"version:2","error":"` + secretText + `"}`),
		},
	}
	for _, fixture := range fixtures {
		if _, err := source.Append(ctx, fixture); err != nil {
			t.Fatalf("append %s: %v", fixture.Type, err)
		}
	}
	if err := ensureLegacySchedulerHistorySanitized(ctx, source, st, auditKey, true); err != nil {
		t.Fatalf("production sanitation: %v", err)
	}
	source.EnforceLegacySchedulerWriteFloor()
	assertSanitizedSchedulerEventByID(t, source, runEventID, secretText)

	auditService := audit.NewService(source, auditKey, audit.WithCheckpoints(st))
	records, err := auditService.Search(ctx, audit.Query{TenantID: tenantID})
	if err != nil {
		t.Fatalf("audit search: %v", err)
	}
	assertAuditRecordsSecretFree(t, records, runEventID, secretText)
	signedExport, err := auditService.Export(ctx, audit.Query{TenantID: tenantID})
	if err != nil {
		t.Fatalf("audit export: %v", err)
	}
	bundle, err := audit.VerifyBundle(signedExport, auditService.VerificationKeys())
	if err != nil {
		t.Fatalf("verify audit export: %v", err)
	}
	assertAuditRecordsSecretFree(t, bundle.Records, runEventID, secretText)

	// Logical retention can prove only archives written after sanitation. Copies
	// already exported to operator-controlled external storage remain outside the
	// repository's deletion authority and are disclosed by the signed receipt.
	time.Sleep(2 * time.Millisecond)
	archiveDir := t.TempDir()
	retention := audit.NewRetentionWorker(
		auditService, source, audit.DirArchiver{Dir: archiveDir}, st, time.Nanosecond,
	)
	summary, err := retention.RunOnce(ctx)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if summary.RecordsArchived < len(fixtures)+1 || summary.RecordsSourceRetained != summary.RecordsArchived || summary.RecordsPruned != 0 {
		t.Fatalf("retention summary = %+v", summary)
	}
	assertAuditArchivesSecretFree(t, archiveDir, auditService, secretText)

	key := []byte("0123456789abcdef0123456789abcdef")
	var artifact bytes.Buffer
	if _, err := backupartifact.WriteLogWithKey(ctx, source, &artifact, key); err != nil {
		t.Fatalf("exact backup: %v", err)
	}
	assertExactBackupSecretFree(t, artifact.Bytes(), secretText)

	targetCfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}
	authorizer, err := crypto.NewBackupRestoreAuthorizer(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Destroy)
	target, err := events.Open(
		ctx, targetCfg,
		events.WithRequiredPrivacyEventPolicies(),
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)),
		events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(auditKey)),
		events.WithBackupRestoreAuthorizer(authorizer),
	)
	if err != nil {
		t.Fatal(err)
	}
	target.EnforceLegacySchedulerWriteFloor()
	if _, err := backupartifact.RestoreLogWithKey(ctx, target, bytes.NewReader(artifact.Bytes()), key); err != nil {
		t.Fatalf("exact restore: %v", err)
	}
	if err := target.RequireNoPendingBackupRestore(ctx); err != nil {
		t.Fatalf("restored target retained artifact binding: %v", err)
	}
	assertSanitizedSchedulerEventByID(t, target, runEventID, secretText)
	if err := projections.New(st).Rebuild(ctx, target); err != nil {
		t.Fatalf("projection rebuild: %v", err)
	}
	schedule, err := st.GetSecretRotationSchedule(ctx, tenantID, scheduleID)
	if err != nil {
		t.Fatalf("read rebuilt schedule: %v", err)
	}
	if schedule.LastError != "scheduled rotation failed" || bytes.Contains([]byte(schedule.LastError), []byte(secretText)) {
		t.Fatalf("rebuilt schedule error = %q", schedule.LastError)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openSanitizedHistoryAwareEventLog(ctx, targetCfg, st, auditKey, true)
	if err != nil {
		t.Fatalf("production restart: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	assertSanitizedSchedulerEventByID(t, restarted, runEventID, secretText)
	restartedAudit := audit.NewService(restarted, auditKey, audit.WithCheckpoints(st))
	if _, err := restartedAudit.Search(ctx, audit.Query{TenantID: tenantID}); err != nil {
		t.Fatalf("audit search after restart: %v", err)
	}
}

func assertSanitizedSchedulerEventByID(t *testing.T, log *events.Log, eventID, secretText string) {
	t.Helper()
	event, found, err := log.EventByID(context.Background(), eventID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("event %q not found", eventID)
	}
	if bytes.Contains(event.Data, []byte(secretText)) {
		t.Fatalf("EventByID retained injected credential: %s", event.Data)
	}
	if err := schedulerhistory.ValidateSanitizedLegacyRun(event.Data); err != nil {
		t.Fatalf("EventByID returned noncanonical scheduler history: %v", err)
	}
}

func assertAuditRecordsSecretFree(t *testing.T, records []audit.Record, eventID, secretText string) {
	t.Helper()
	found := false
	for _, record := range records {
		if bytes.Contains(record.Data, []byte(secretText)) {
			t.Fatalf("audit record retained injected credential: %+v", record)
		}
		if record.ID == eventID {
			found = true
			if err := schedulerhistory.ValidateSanitizedLegacyRun(record.Data); err != nil {
				t.Fatalf("audit record is not canonical: %v", err)
			}
		}
	}
	if !found {
		t.Fatalf("audit records did not contain %q", eventID)
	}
}

func assertAuditArchivesSecretFree(t *testing.T, dir string, service *audit.Service, secretText string) {
	t.Helper()
	files := 0
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		files++
		signed, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		bundle, err := audit.VerifyBundle(string(signed), service.VerificationKeys())
		if err != nil {
			t.Fatalf("verify retention archive %s: %v", path, err)
		}
		for _, record := range bundle.Records {
			if bytes.Contains(record.Data, []byte(secretText)) {
				t.Fatalf("retention archive retained injected credential: %s", record.Data)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("retention wrote no signed archive")
	}
}

func assertExactBackupSecretFree(t *testing.T, artifact []byte, secretText string) {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(artifact))
	for scanner.Scan() {
		var entry struct {
			Stored []byte          `json:"stored"`
			Data   json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(entry.Data, []byte(secretText)) {
			t.Fatalf("exact backup decoded data retained injected credential: %s", entry.Data)
		}
		if len(entry.Stored) != 0 {
			var envelope struct {
				Data []byte `json:"data"`
			}
			if err := json.Unmarshal(entry.Stored, &envelope); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(envelope.Data, []byte(secretText)) {
				t.Fatalf("exact backup stored envelope retained injected credential: %s", envelope.Data)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
