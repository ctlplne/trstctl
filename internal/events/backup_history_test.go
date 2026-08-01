// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
)

var errBackupRestoreTestCrash = errors.New("events: simulated backup restore crash")

func TestExactBackupRestoreResumesAfterFirstLiveAcknowledgement(t *testing.T) {
	ctx := context.Background()
	log := openBackupHistoryTestLog(t)
	history := []BackupHistoryRecord{
		backupHistoryEvent(t, 1, "resume-one", "owner.created"),
		{Sequence: 2, GapThrough: 2},
		backupHistoryEvent(t, 3, "resume-three", "owner.updated"),
	}
	_, err := log.RestoreBackupHistory(ctx, 3, "artifact-resume", func(yield func(BackupHistoryRecord) error) error {
		if err := yield(history[0]); err != nil {
			return err
		}
		return errBackupRestoreTestCrash
	})
	if !errors.Is(err, errBackupRestoreTestCrash) {
		t.Fatalf("first restore error = %v, want simulated crash", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != 1 {
		t.Fatalf("partial restore head = %d, want acknowledged prefix 1", head)
	}

	n, err := log.RestoreBackupHistory(ctx, 3, "artifact-resume", backupHistorySource(history))
	if err != nil {
		t.Fatalf("resume exact restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("resumed restore records = %d, want total live count 2", n)
	}
	assertBackupHistory(t, log, 3, history)
}

func TestExactBackupRestoreRejectsDifferentBackupAgainstPartialPrefix(t *testing.T) {
	ctx := context.Background()
	log := openBackupHistoryTestLog(t)
	original := backupHistoryEvent(t, 1, "partial-original", "owner.created")
	_, err := log.RestoreBackupHistory(ctx, 2, "artifact-original", func(yield func(BackupHistoryRecord) error) error {
		if err := yield(original); err != nil {
			return err
		}
		return errBackupRestoreTestCrash
	})
	if !errors.Is(err, errBackupRestoreTestCrash) {
		t.Fatalf("first restore error = %v, want simulated crash", err)
	}

	_, err = log.RestoreBackupHistory(ctx, 2, "artifact-different", backupHistorySource([]BackupHistoryRecord{
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
	log, err := Open(ctx, cfg)
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
		ctx, name, stream, info, 2, "artifact-gap-reopen",
	)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := log.js.Publish(
		ctx,
		backupGapSubject,
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

	reopened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open with live restore marker: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	event := backupHistoryEvent(t, 2, "after-leading-gap", "owner.created")
	n, err := reopened.RestoreBackupHistory(ctx, 2, "artifact-gap-reopen", backupHistorySource([]BackupHistoryRecord{
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

func TestExactBackupRestoreAllGapBoundsKeepNextSequence(t *testing.T) {
	ctx := context.Background()
	log := openBackupHistoryTestLog(t)
	history := []BackupHistoryRecord{{Sequence: 1, GapThrough: 3}}
	n, err := log.RestoreBackupHistory(ctx, 3, "artifact-all-gap", backupHistorySource(history))
	if err != nil {
		t.Fatalf("RestoreBackupHistory all-gap: %v", err)
	}
	if n != 0 {
		t.Fatalf("all-gap restore records = %d, want 0", n)
	}
	assertBackupHistory(t, log, 3, history)
	n, err = log.RestoreBackupHistory(ctx, 3, "artifact-all-gap", backupHistorySource(history))
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

func openBackupHistoryTestLog(t *testing.T) *Log {
	t.Helper()
	log, err := Open(context.Background(), config.NATS{
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
