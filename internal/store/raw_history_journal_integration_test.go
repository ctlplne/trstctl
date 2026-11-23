// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// CR-045: an ACKed raw broker record and an unresolved PostgreSQL journal
// start survive the same failure. Exact-artifact resume reads back the prefix
// and settles that start before publishing the next source position.
func TestRawHistoryJournalRecoversRealBrokerACKWithLostSettlementCR045(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const tenant = "49900000-0000-4000-8000-0000000000a2"
	const operation = "49900000-0000-4000-8000-0000000000b2"
	key := []byte("fixture-restore-authority-key-32")
	artifactDigest := strings.Repeat("a", 64)
	records := make([]events.BackupHistoryRecord, 0, 2)
	for sequence, id := range []string{"raw-resume-1", "raw-resume-2"} {
		record, err := events.LegacyBackupHistoryRecord(ctx, uint64(sequence+1), events.Event{
			ID: id, Type: "owner.created", TenantID: tenant,
			Time: time.Date(2026, 11, 21, 0, 0, sequence, 0, time.UTC),
			Data: []byte(`{"owner":"fixture"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	source := func(yield func(events.BackupHistoryRecord) error) error {
		for _, record := range records {
			if err := yield(record); err != nil {
				return err
			}
		}
		return nil
	}
	historyDigest, err := events.BackupHistoryDigest(ctx, 2, source)
	if err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID: operation, ArtifactSHA256: strings.Repeat("b", 64),
		EventHistorySHA256: artifactDigest, EventCut: 2,
		DeploymentID: "raw-journal-broker-resume",
	}
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
	authorizer, err := crypto.NewBackupRestoreAuthorizer(key)
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Destroy()
	grant, err := crypto.BackupRestoreAuthorization(key, crypto.BackupRestoreIntent{
		EventCutSequence: 2, ArtifactSHA256: artifactDigest,
		HistorySHA256: historyDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Destroy()
	lostSettlement := errors.New("broker ACK returned before journal settlement")
	loseOnce := true
	storeDir := t.TempDir()
	openLog := func() (*events.Log, error) {
		return events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir},
			events.WithBackupRestoreAuthorizer(authorizer),
			events.WithRequiredBackupHistoryAdmission(),
			events.WithBackupHistoryAdmission(func(admitted context.Context, _ uint64, _ string,
				run func(context.Context) (int, error),
			) (int, error) {
				return run(admitted)
			}),
			events.WithBackupHistoryJournal(func(admitted context.Context, cut uint64,
				digest, action string, record events.BackupHistoryRecord,
				run func(context.Context) error,
			) error {
				return s.WithRawHistoryRecordJournal(admitted, cut, digest, action, record,
					func(runCtx context.Context) error {
						if err := run(runCtx); err != nil {
							return err
						}
						if action == "live" && record.Sequence == 1 && loseOnce {
							loseOnce = false
							return lostSettlement
						}
						return nil
					})
			}))
	}
	log, err := openLog()
	if err != nil {
		t.Fatal(err)
	}
	var restored int
	err = s.WithFullRestoreOwner(ctx, marker, func(ownerCtx context.Context) error {
		var runErr error
		restored, runErr = log.RestoreAuthorizedBackupHistory(ownerCtx, 2, artifactDigest, grant, source)
		return runErr
	})
	if !errors.Is(err, lostSettlement) || restored != 1 {
		t.Fatalf("ambiguous first restore count=%d err=%v", restored, err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != 1 {
		t.Fatalf("acknowledged prefix head=%d err=%v", head, err)
	}
	var phase string
	if err := s.SystemPool().QueryRow(ctx, `SELECT phase FROM trstctl_recovery.raw_history_journal
		WHERE tenant_id=$1 AND operation_id=$2 AND source_sequence=1 AND action='live'`,
		tenant, operation).Scan(&phase); err != nil || phase != "started" {
		t.Fatalf("ambiguous row phase=%q err=%v", phase, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = openLog()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	err = s.WithFullRestoreOwner(ctx, marker, func(ownerCtx context.Context) error {
		var runErr error
		restored, runErr = log.RestoreAuthorizedBackupHistory(ownerCtx, 2, artifactDigest, grant, source)
		return runErr
	})
	if err != nil || restored != 2 {
		t.Fatalf("same-artifact resume count=%d err=%v", restored, err)
	}
	var verified int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.raw_history_journal
		WHERE tenant_id=$1 AND operation_id=$2 AND action='live' AND phase='verified'`,
		tenant, operation).Scan(&verified); err != nil || verified != 2 {
		t.Fatalf("verified live rows=%d err=%v", verified, err)
	}
}
