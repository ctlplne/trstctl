// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
)

var errBackupRestoreTestCrash = errors.New("events: simulated backup restore crash")

func TestExactBackupRestoreResumesAfterFirstLiveAcknowledgement(t *testing.T) {
	ctx := context.Background()
	log := openBackupHistoryTestLog(t)
	state, err := log.schedulerSafetySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldIndex := eventIDIndexPrefix + eventIDSourceEpoch(state)
	artifactDigest := strings.Repeat("a", 64)
	history := []BackupHistoryRecord{
		backupHistoryEvent(t, 1, "resume-one", "owner.created"),
		{Sequence: 2, GapThrough: 2},
		backupHistoryEvent(t, 3, "resume-three", "owner.updated"),
	}
	_, err = log.RestoreBackupHistory(ctx, 3, artifactDigest, func(yield func(BackupHistoryRecord) error) error {
		if err := yield(history[0]); err != nil {
			return err
		}
		return errBackupRestoreTestCrash
	})
	if !errors.Is(err, errBackupRestoreTestCrash) {
		t.Fatalf("first restore error = %v, want simulated crash", err)
	}
	if _, err := log.js.Stream(ctx, oldIndex); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("pending restore retained old identity projection: %v", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != 1 {
		t.Fatalf("partial restore head = %d, want acknowledged prefix 1", head)
	}

	n, err := log.RestoreBackupHistory(ctx, 3, artifactDigest, backupHistorySource(history))
	if err != nil {
		t.Fatalf("resume exact restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("resumed restore records = %d, want total live count 2", n)
	}
	assertBackupHistory(t, log, 3, history)
	if event, found, err := log.EventByID(ctx, history[2].MessageID); err != nil || !found || event.Sequence != 3 {
		t.Fatalf("restored identity lookup = %+v, %t, %v", event, found, err)
	}
}

// CR-045: a broker ACK can succeed while journal settlement is lost. The
// same-artifact retry must read back the exact prefix instead of publishing a
// second event, then complete the next source position.
func TestBackupHistoryJournalRecoversAcknowledgedPendingRecordCR045(t *testing.T) {
	ctx := t.Context()
	log := openBackupHistoryTestLog(t)
	digest := strings.Repeat("a", 64)
	history := []BackupHistoryRecord{
		backupHistoryEvent(t, 1, "pending-journal-one", "owner.created"),
		backupHistoryEvent(t, 2, "pending-journal-two", "owner.updated"),
	}
	phases := make(map[uint64]string)
	loseFirstSettlement := true
	log.backupHistoryJournal = func(admitted context.Context, _ uint64, _ string,
		action string, record BackupHistoryRecord, run func(context.Context) error,
	) error {
		if action != "live" {
			return run(admitted)
		}
		phases[record.Sequence] = "started"
		if err := run(admitted); err != nil {
			return err
		}
		if record.Sequence == 1 && loseFirstSettlement {
			loseFirstSettlement = false
			return errBackupRestoreTestCrash
		}
		phases[record.Sequence] = "verified"
		return nil
	}
	if _, err := log.RestoreBackupHistory(ctx, 2, digest, backupHistorySource(history)); !errors.Is(err, errBackupRestoreTestCrash) {
		t.Fatalf("lost settlement result=%v", err)
	}
	if phases[1] != "started" {
		t.Fatalf("ambiguous first record phase=%q", phases[1])
	}
	if head, err := log.LastSequence(ctx); err != nil || head != 1 {
		t.Fatalf("acknowledged first record head=%d err=%v", head, err)
	}
	if _, err := log.RestoreBackupHistory(ctx, 2, digest, backupHistorySource(history)); err != nil {
		t.Fatalf("same-artifact journal resume: %v", err)
	}
	if phases[1] != "verified" || phases[2] != "verified" {
		t.Fatalf("resumed journal phases=%v", phases)
	}
	assertBackupHistory(t, log, 2, history)
}

func TestExactBackupRestoreRejectsDifferentBackupAgainstPartialPrefix(t *testing.T) {
	ctx := context.Background()
	log := openBackupHistoryTestLog(t)
	originalDigest := strings.Repeat("b", 64)
	differentDigest := strings.Repeat("c", 64)
	original := backupHistoryEvent(t, 1, "partial-original", "owner.created")
	_, err := log.RestoreBackupHistory(ctx, 2, originalDigest, func(yield func(BackupHistoryRecord) error) error {
		if err := yield(original); err != nil {
			return err
		}
		return errBackupRestoreTestCrash
	})
	if !errors.Is(err, errBackupRestoreTestCrash) {
		t.Fatalf("first restore error = %v, want simulated crash", err)
	}

	_, err = log.RestoreBackupHistory(ctx, 2, differentDigest, backupHistorySource([]BackupHistoryRecord{
		original,
		{Sequence: 2, GapThrough: 2},
	}))
	if !errors.Is(err, ErrBackupHistoryPrefixMismatch) {
		t.Fatalf("different-backup resume error = %v, want prefix mismatch", err)
	}
	head, headErr := log.LastSequence(ctx)
	if headErr != nil {
		t.Fatal(headErr)
	}
	if head != 1 {
		t.Fatalf("different-backup rejection advanced head to %d, want 1", head)
	}
}

func TestExactBackupRestoreReopenRecoversPublishedGapMarker(t *testing.T) {
	ctx := context.Background()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	artifactDigest := strings.Repeat("d", 64)
	log, err := openFixture(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	name, stream, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info, err := log.infoForStream(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	stream, _, err = log.bindBackupRestoreIdentity(
		ctx, name, stream, info, 2, artifactDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	restoreSubject, err := backupRestorePublishSubject(artifactDigest, backupGapSubject)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := log.js.Publish(
		ctx,
		restoreSubject,
		nil,
		jetstream.WithMsgID(backupGapMessageID(1)),
		jetstream.WithExpectLastSequence(0),
	)
	if err != nil {
		t.Fatalf("publish simulated crash marker: %v", err)
	}
	if ack.Sequence != 1 {
		t.Fatalf("gap marker sequence = %d, want 1", ack.Sequence)
	}
	raw, err := stream.GetMsg(ctx, 1)
	if err != nil || !isBackupGapMarker(raw, 1) {
		t.Fatalf("simulated live gap marker = %+v err=%v", raw, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openFixture(ctx, cfg)
	if err != nil {
		t.Fatalf("Open with live restore marker: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	event := backupHistoryEvent(t, 2, "after-leading-gap", "owner.created")
	n, err := reopened.RestoreBackupHistory(ctx, 2, artifactDigest, backupHistorySource([]BackupHistoryRecord{
		{Sequence: 1, GapThrough: 1},
		event,
	}))
	if err != nil {
		t.Fatalf("resume after gap-marker crash: %v", err)
	}
	if n != 1 {
		t.Fatalf("restored records = %d, want 1", n)
	}
	assertBackupHistory(t, reopened, 2, []BackupHistoryRecord{
		{Sequence: 1, GapThrough: 1},
		event,
	})
	var replayed []Event
	if err := reopened.Replay(ctx, 0, func(event Event) error {
		replayed = append(replayed, event)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(replayed) != 1 || replayed[0].Sequence != 2 || replayed[0].ID != event.MessageID {
		t.Fatalf("replayed history = %+v, want only sequence-2 live event", replayed)
	}
}

func TestProductionOpenRefusesUnownedLegacyPendingRouteUpgradeCR045(t *testing.T) {
	ctx := context.Background()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	source, err := openFixture(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	name, stream, err := source.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info, err := source.infoForStream(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("b", 64)
	streamCfg := cloneStreamConfig(info.Config)
	if streamCfg.Metadata == nil {
		streamCfg.Metadata = map[string]string{}
	}
	streamCfg.Metadata[backupRestoreMetadataDigest] = digest
	streamCfg.Metadata[backupRestoreMetadataCut] = "0"
	if _, err := source.js.UpdateStream(ctx, streamCfg); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	missing, err := Open(ctx, cfg, WithRequiredBackupHistoryAdmission())
	if missing != nil {
		defer func() { _ = missing.Close() }()
	}
	if !errors.Is(err, ErrBackupHistoryAdmissionUnavailable) {
		t.Fatalf("pending route with missing production adapter was admitted: %v", err)
	}
	opened, err := Open(ctx, cfg,
		WithRequiredBackupHistoryAdmission(),
		WithBackupHistoryJournal(func(ctx context.Context, _ uint64, _, _ string,
			_ BackupHistoryRecord, run func(context.Context) error,
		) error {
			return run(ctx)
		}),
		WithBackupHistoryAdmission(func(context.Context, uint64, string,
			func(context.Context) (int, error),
		) (int, error) {
			return 0, ErrBackupHistoryAdmissionUnavailable
		}))
	if opened != nil {
		defer func() { _ = opened.Close() }()
	}
	if !errors.Is(err, ErrBackupHistoryAdmissionUnavailable) {
		t.Fatalf("unowned pending-route upgrade was admitted: %v", err)
	}
	srv, nc, err := openEmbedded(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rawClosed := false
	t.Cleanup(func() {
		if !rawClosed {
			shutdown(srv, nc)
		}
	})
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	stream, err = js.Stream(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	info, err = stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.Metadata[backupRestoreMetadataRoute] != "" ||
		info.Config.Metadata[backupRestoreMetadataDigest] != digest {
		t.Fatal("unowned Open changed the pending broker route")
	}
	shutdown(srv, nc)
	rawClosed = true
	owned, err := Open(ctx, cfg, WithRequiredBackupHistoryAdmission(),
		WithBackupHistoryAdmission(func(ctx context.Context, _ uint64, _ string,
			run func(context.Context) (int, error),
		) (int, error) {
			return run(ctx)
		}),
		WithBackupHistoryJournal(func(ctx context.Context, _ uint64, _, _ string,
			_ BackupHistoryRecord, run func(context.Context) error,
		) error {
			return run(ctx)
		}))
	if err != nil {
		t.Fatalf("owner-bound pending route recovery: %v", err)
	}
	defer func() { _ = owned.Close() }()
	_, stream, err = owned.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info, err = owned.infoForStream(ctx, stream)
	if err != nil || !backupRestoreRouteIsFrozen(info.Config, digest) {
		t.Fatalf("owner-bound Open did not freeze pending broker route: %v", err)
	}
}

func TestExactBackupRestoreAllGapBoundsKeepNextSequence(t *testing.T) {
	ctx := context.Background()
	log := openBackupHistoryTestLog(t)
	artifactDigest := strings.Repeat("e", 64)
	history := []BackupHistoryRecord{{Sequence: 1, GapThrough: 3}}
	n, err := log.RestoreBackupHistory(ctx, 3, artifactDigest, backupHistorySource(history))
	if err != nil {
		t.Fatalf("RestoreBackupHistory all-gap: %v", err)
	}
	if n != 0 {
		t.Fatalf("all-gap restore records = %d, want 0", n)
	}
	assertBackupHistory(t, log, 3, history)
	n, err = log.RestoreBackupHistory(ctx, 3, artifactDigest, backupHistorySource(history))
	if err != nil {
		t.Fatalf("markerless completed all-gap retry: %v", err)
	}
	if n != 0 {
		t.Fatalf("markerless all-gap retry records = %d, want 0", n)
	}
	next, err := log.Append(ctx, Event{
		ID: "after-all-gap", Type: "owner.created",
		TenantID: "11111111-1111-1111-1111-111111111111",
	})
	if err != nil {
		t.Fatalf("Append after all-gap restore: %v", err)
	}
	if next.Sequence != 4 {
		t.Fatalf("next sequence = %d, want 4", next.Sequence)
	}
}

// CR-045: the raw restore journal must stage each gap before the marker is
// published or deleted, as well as staging live source records.
func TestBackupHistoryJournalSeesGapBeforeBrokerMutationCR045(t *testing.T) {
	ctx := t.Context()
	log := openBackupHistoryTestLog(t)
	var seen []uint64
	log.backupHistoryJournal = func(admitted context.Context, cut uint64, digest, _ string,
		record BackupHistoryRecord, run func(context.Context) error,
	) error {
		if cut != 2 || digest != strings.Repeat("f", 64) {
			t.Fatal("journal received another artifact identity")
		}
		if len(seen) == 0 {
			head, err := log.LastSequence(admitted)
			if err != nil || head != 0 {
				t.Fatalf("first journal start followed broker mutation: head=%d err=%v", head, err)
			}
		}
		seen = append(seen, record.Sequence)
		return run(admitted)
	}
	history := []BackupHistoryRecord{
		{Sequence: 1, GapThrough: 1},
		backupHistoryEvent(t, 2, "journal-after-gap", "owner.created"),
	}
	if _, err := log.RestoreBackupHistory(ctx, 2, strings.Repeat("f", 64), backupHistorySource(history)); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 || seen[0] != 0 || seen[1] != 0 || seen[2] != 1 ||
		seen[3] != 2 || seen[4] != 0 {
		t.Fatalf("journaled source sequences = %v, want binding, index, gap, live, unbind", seen)
	}
}

// CR-045: stream binding and index deletion are broker mutations before the
// first source record. Both need ordered journal starts of their own.
func TestBackupHistoryJournalStagesBindingAndIndexBeforeRecordsCR045(t *testing.T) {
	ctx := t.Context()
	log := openBackupHistoryTestLog(t)
	var actions []string
	log.backupHistoryJournal = func(admitted context.Context, _ uint64, _, action string,
		record BackupHistoryRecord, run func(context.Context) error,
	) error {
		_ = record
		actions = append(actions, action)
		return run(admitted)
	}
	record := backupHistoryEvent(t, 1, "journal-first-live", "owner.created")
	if _, err := log.RestoreBackupHistory(ctx, 1, strings.Repeat("f", 64),
		backupHistorySource([]BackupHistoryRecord{record})); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 4 || actions[0] != "bind" || actions[1] != "index" ||
		actions[2] != "live" || actions[3] != "unbind" {
		t.Fatalf("journal order=%v, want bind, index, live, unbind", actions)
	}
}

func openBackupHistoryTestLog(t *testing.T) *Log {
	t.Helper()
	log, err := openFixture(context.Background(), config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func backupHistoryEvent(t *testing.T, sequence uint64, id, eventType string) BackupHistoryRecord {
	t.Helper()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	when := time.Unix(int64(sequence), 0).UTC() // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	stored, err := json.Marshal(storedEvent{
		ID: id, Type: eventType, TenantID: tenantID, Time: when,
		SchemaVersion: DefaultSchemaVersion, Data: []byte(fmt.Sprintf(`{"sequence":%d}`, sequence)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return BackupHistoryRecord{
		Sequence: sequence, Subject: "events." + eventType, MessageID: id, Stored: stored,
		Event: Event{
			ID: id, Type: eventType, TenantID: tenantID, Time: when,
			SchemaVersion: DefaultSchemaVersion, Sequence: sequence,
			Data: []byte(fmt.Sprintf(`{"sequence":%d}`, sequence)),
		},
	}
}

func backupHistorySource(history []BackupHistoryRecord) BackupHistorySource {
	return func(yield func(BackupHistoryRecord) error) error {
		for _, record := range history {
			if err := yield(record); err != nil {
				return err
			}
		}
		return nil
	}
}

func assertBackupHistory(
	t *testing.T,
	log *Log,
	cut uint64,
	want []BackupHistoryRecord,
) {
	t.Helper()
	var got []BackupHistoryRecord
	if err := log.ExportBackupHistoryThrough(
		context.Background(),
		cut,
		func(record BackupHistoryRecord) error {
			got = append(got, record)
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("history entries = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Sequence != want[i].Sequence ||
			got[i].GapThrough != want[i].GapThrough ||
			got[i].Subject != want[i].Subject ||
			got[i].MessageID != want[i].MessageID ||
			!bytes.Equal(got[i].Stored, want[i].Stored) {
			t.Fatalf("history[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
