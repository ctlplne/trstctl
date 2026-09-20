// SPDX-License-Identifier: BUSL-1.1

package backup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

const drTenant = "11111111-1111-1111-1111-111111111111"

func openLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func appendEvent(t *testing.T, log *events.Log, ctx context.Context, typ string, data string) {
	t.Helper()
	if _, err := log.Append(ctx, events.Event{Type: typ, TenantID: drTenant, Data: []byte(data)}); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func collect(t *testing.T, log *events.Log) []events.Event {
	t.Helper()
	var got []events.Event
	if err := log.Replay(context.Background(), 0, func(e events.Event) error { got = append(got, e); return nil }); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return got
}

// TestBackupRestoreRoundTrip is the R2.4 source-of-truth backup acceptance: the
// event log backs up to a portable stream and restores into a fresh log
// byte-for-byte — type, tenant, data, and the recorded actor (R2.1) all survive.
func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: "alice@example.com", Roles: []string{"admin"}})
	appendEvent(t, src, actorCtx, "owner.created", `{"name":"payments"}`)
	appendEvent(t, src, ctx, "certificate.recorded", `{"serial":"01"}`)
	appendEvent(t, src, actorCtx, "identity.issued", `{}`)

	var buf bytes.Buffer
	n, err := backup.WriteLog(ctx, src, &buf)
	if err != nil {
		t.Fatalf("WriteLog: %v", err)
	}
	if n != 3 {
		t.Fatalf("backed up %d events, want 3", n)
	}

	dst := openLog(t)
	m, err := backup.RestoreLog(ctx, dst, &buf)
	if err != nil {
		t.Fatalf("RestoreLog: %v", err)
	}
	if m != 3 {
		t.Fatalf("restored %d events, want 3", m)
	}

	got := collect(t, dst)
	if len(got) != 3 {
		t.Fatalf("restored log has %d events, want 3", len(got))
	}
	if got[0].Type != "owner.created" || got[0].TenantID != drTenant {
		t.Errorf("event 0 = %+v", got[0])
	}
	if got[0].Actor == nil || got[0].Actor.Subject != "alice@example.com" {
		t.Errorf("actor not preserved on restore: %+v", got[0].Actor)
	}
	if string(got[1].Data) != `{"serial":"01"}` {
		t.Errorf("data not preserved on restore: %s", got[1].Data)
	}
	if got[1].Actor != nil {
		t.Errorf("event 1 should remain unattributed, got %+v", got[1].Actor)
	}
}

func TestWriteLogPreflightsUnsafeLegacySchedulerHistoryBeforeOutput(t *testing.T) {
	ctx := context.Background()
	log := openLog(t)
	secret := "provider-token-must-not-leave-history"
	if _, err := log.Append(ctx, events.Event{
		Type: schedulerhistory.EventType, TenantID: drTenant,
		SchemaVersion: schedulerhistory.LegacySchemaVersion,
		Data:          []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"` + secret + `"}`),
	}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	_, err := backup.WriteLogWithKey(ctx, log, &output, []byte("test-integrity-key"))
	if !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
		t.Fatalf("WriteLogWithKey error = %v, want sanitation-required", err)
	}
	if output.Len() != 0 {
		t.Fatalf("backup emitted %d bytes before failing closed", output.Len())
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("backup error disclosed unsafe scheduler data")
	}
}

// TestRestoreRefusesNonEmptyLog: restoring into a log that already has events is
// rejected, so a misdirected restore can't silently duplicate the stream.
func TestRestoreRefusesNonEmptyLog(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	appendEvent(t, src, ctx, "owner.created", `{}`)
	var buf bytes.Buffer
	if _, err := backup.WriteLog(ctx, src, &buf); err != nil {
		t.Fatal(err)
	}

	dst := openLog(t)
	appendEvent(t, dst, ctx, "owner.created", `{}`)
	if _, err := backup.RestoreLog(ctx, dst, &buf); !errors.Is(err, backup.ErrRestoreTargetNotEmpty) {
		t.Fatal("restore into a non-empty log must error")
	}
}

// TestRestoreRejectsBadHeader: a stream that is not a trstctl backup is rejected.
func TestRestoreRejectsBadHeader(t *testing.T) {
	dst := openLog(t)
	if _, err := backup.RestoreLog(context.Background(), dst, strings.NewReader("garbage\n{}\n")); err == nil {
		t.Fatal("restore must reject a stream with no valid backup header")
	}
}

// makeBackup writes a small backup (optionally keyed) and returns its bytes.
func makeBackup(t *testing.T, key []byte) []byte {
	t.Helper()
	ctx := context.Background()
	src := openLog(t)
	appendEvent(t, src, ctx, "owner.created", `{"name":"payments"}`)
	appendEvent(t, src, ctx, "certificate.recorded", `{"serial":"01"}`)
	appendEvent(t, src, ctx, "identity.issued", `{"id":"abc"}`)
	var buf bytes.Buffer
	if _, err := backup.WriteLogWithKey(ctx, src, &buf, key); err != nil {
		t.Fatalf("WriteLogWithKey: %v", err)
	}
	return buf.Bytes()
}

func TestVerifyEventLogBackupRejectsCheckpointWithMissingTenantPrefix(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	appendEvent(t, src, ctx, "owner.created", `{"name":"one"}`)
	const otherTenant = "22222222-2222-2222-2222-222222222222"
	if _, err := src.Append(ctx, events.Event{
		ID: "checkpoint-other-tenant", Type: "owner.created", TenantID: otherTenant,
		Data: []byte(`{"name":"two"}`),
	}); err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	if _, err := backup.WriteLog(ctx, src, &artifact); err != nil {
		t.Fatal(err)
	}

	_, err := backup.VerifyEventLogBackupWithAuditCheckpoints(
		bytes.NewReader(artifact.Bytes()),
		nil,
		[]backup.AuditCheckpointBoundary{{
			TenantID: drTenant, BoundarySeq: 2, RecordCount: 2,
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "retains 1 of 2") {
		t.Fatalf("checkpoint preflight error = %v, want incomplete tenant-prefix rejection", err)
	}

	summary, err := backup.VerifyEventLogBackupWithAuditCheckpoints(
		bytes.NewReader(artifact.Bytes()),
		nil,
		[]backup.AuditCheckpointBoundary{{
			TenantID: drTenant, BoundarySeq: 2, RecordCount: 1,
		}},
	)
	if err != nil {
		t.Fatalf("complete tenant prefix rejected: %v", err)
	}
	if summary.HasGaps || summary.EventCutSequence != 2 || summary.Records != 2 {
		t.Fatalf("verified summary = %+v, want complete two-event source", summary)
	}
}

// TestRestoreRejectsTamperedBackup is the OPS-006 acceptance: a single flipped
// byte anywhere in a record makes --restore (RestoreLog) fail closed with an
// integrity error, while the untouched backup restores cleanly. It FAILS on the
// pre-fix tree, which validated only format+version and never hashed the bytes.
func TestRestoreRejectsTamperedBackup(t *testing.T) {
	good := makeBackup(t, nil)

	// (1) The pristine backup restores its three events.
	{
		dst := openLog(t)
		n, err := backup.RestoreLog(context.Background(), dst, bytes.NewReader(good))
		if err != nil {
			t.Fatalf("pristine backup must restore: %v", err)
		}
		if n != 3 {
			t.Fatalf("restored %d events, want 3", n)
		}
	}

	// (2) Flip a byte inside the serial of the second record ("01" -> "02"); the
	// SHA-256 over the stream no longer matches the trailer, so restore must reject
	// it WITHOUT appending anything.
	tampered := bytes.Replace(good, []byte(`"serial":"01"`), []byte(`"serial":"02"`), 1)
	if bytes.Equal(tampered, good) {
		t.Fatal("test setup: expected to mutate the serial in the backup bytes")
	}
	dst := openLog(t)
	n, err := backup.RestoreLog(context.Background(), dst, bytes.NewReader(tampered))
	if err == nil {
		t.Fatal("restore must REJECT a bit-flipped backup (OPS-006)")
	}
	if !strings.Contains(err.Error(), "decoded fields do not match its stored envelope") {
		t.Errorf("rejection should identify the first exact-envelope mismatch, got: %v", err)
	}
	if n != 0 {
		t.Errorf("a tampered backup must not append any events, appended %d", n)
	}
	// The target log is untouched: nothing was restored.
	if got := collect(t, dst); len(got) != 0 {
		t.Errorf("target log should be empty after a rejected restore, has %d events", len(got))
	}
}

// TestRestoreRejectsTruncatedBackup: a stream cut short (lost trailer, or a
// dropped record) is rejected fail-closed.
func TestRestoreRejectsTruncatedBackup(t *testing.T) {
	good := makeBackup(t, nil)

	// Drop the final line (the integrity trailer).
	lines := bytes.Split(bytes.TrimRight(good, "\n"), []byte("\n"))
	if len(lines) < 3 {
		t.Fatalf("unexpected backup shape: %d lines", len(lines))
	}
	noTrailer := append(bytes.Join(lines[:len(lines)-1], []byte("\n")), '\n')

	dst := openLog(t)
	if _, err := backup.RestoreLog(context.Background(), dst, bytes.NewReader(noTrailer)); err == nil {
		t.Fatal("restore must reject a backup with no integrity trailer (truncated)")
	}

	// Drop a data record (the trailer's record count no longer matches, AND the
	// hash no longer matches).
	dropped := bytes.Join(append([][]byte{lines[0], lines[2]}, lines[3:]...), []byte("\n"))
	dropped = append(dropped, '\n')
	dst2 := openLog(t)
	if _, err := backup.RestoreLog(context.Background(), dst2, bytes.NewReader(dropped)); err == nil {
		t.Fatal("restore must reject a backup with a removed record (OPS-006)")
	}
}

// TestKeyedBackupRequiresValidMAC: a keyed (HMAC) backup verifies only under the
// right key — restoring under the wrong key, or with no key when the caller
// requires one, fails; the matching key restores.
func TestKeyedBackupRequiresValidMAC(t *testing.T) {
	ctx := context.Background()
	key := []byte("deployment-integrity-key-32-bytes!")
	keyed := makeBackup(t, key)

	// Right key: restores.
	{
		dst := openLog(t)
		n, err := backup.RestoreLogWithKey(ctx, dst, bytes.NewReader(keyed), key)
		if err != nil {
			t.Fatalf("keyed backup must restore under the right key: %v", err)
		}
		if n != 3 {
			t.Fatalf("restored %d events, want 3", n)
		}
	}

	// Wrong key: the SHA-256 still matches (untampered), but the MAC must not
	// verify, so restore is rejected fail-closed.
	{
		dst := openLog(t)
		_, err := backup.RestoreLogWithKey(ctx, dst, bytes.NewReader(keyed), []byte("a-different-wrong-integrity-key!!"))
		if err == nil {
			t.Fatal("keyed backup must be rejected under the wrong integrity key")
		}
		if !strings.Contains(err.Error(), "integrity") {
			t.Errorf("wrong-key rejection should be an integrity error, got: %v", err)
		}
		if pristine, inspectErr := dst.BackupHistoryPristine(ctx); inspectErr != nil || !pristine {
			t.Fatalf(
				"wrong-key restore mutated target: pristine=%t inspect_err=%v",
				pristine, inspectErr,
			)
		}
	}

	// A caller that requires a key but is handed a checksum-only (keyless) backup
	// must reject it (a downgrade attempt).
	{
		keyless := makeBackup(t, nil)
		dst := openLog(t)
		if _, err := backup.RestoreLogWithKey(ctx, dst, bytes.NewReader(keyless), key); err == nil {
			t.Fatal("a key-requiring restore must reject a backup that carries no HMAC")
		}
	}
}

// TestFullRestoreResumesAfterLogRestore pins RESIL-002: when a full restore has
// already loaded the event log but fails later while importing independent
// PostgreSQL state, a retry must prove the existing log is byte-for-byte the same
// backup stream and then continue instead of demanding a freshly empty log.
func TestFullRestoreResumesAfterLogRestore(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	appendEvent(t, src, ctx, "owner.created", `{"name":"payments"}`)
	appendEvent(t, src, ctx, "certificate.recorded", `{"serial":"01"}`)

	var stream bytes.Buffer
	if _, err := backup.WriteLog(ctx, src, &stream); err != nil {
		t.Fatalf("WriteLog: %v", err)
	}

	target := openLog(t)
	if _, err := backup.RestoreLog(ctx, target, bytes.NewReader(stream.Bytes())); err != nil {
		t.Fatalf("initial RestoreLog: %v", err)
	}
	resumed, err := backup.RestoreLog(ctx, target, bytes.NewReader(stream.Bytes()))
	if err != nil {
		t.Fatalf("completed markerless RestoreLog retry: %v", err)
	}
	if resumed != 2 {
		t.Fatalf("completed markerless retry verified %d events, want 2", resumed)
	}
	n, err := backup.VerifyLogMatchesWithKey(ctx, target, bytes.NewReader(stream.Bytes()), nil)
	if err != nil {
		t.Fatalf("resume equivalence check rejected matching log: %v", err)
	}
	if n != 2 {
		t.Fatalf("matched %d events, want 2", n)
	}
}

// TestFullRestoreRejectsDifferentManifestOnResume is the fail-closed half of the
// same resume path. ELI5: if the partially restored event log belongs to backup A,
// retrying with backup B is not a resume; it is a different restore and must stop.
func TestFullRestoreRejectsDifferentManifestOnResume(t *testing.T) {
	ctx := context.Background()
	srcA := openLog(t)
	appendEvent(t, srcA, ctx, "owner.created", `{"name":"payments"}`)
	var streamA bytes.Buffer
	if _, err := backup.WriteLog(ctx, srcA, &streamA); err != nil {
		t.Fatalf("WriteLog A: %v", err)
	}

	srcB := openLog(t)
	appendEvent(t, srcB, ctx, "owner.created", `{"name":"billing"}`)
	var streamB bytes.Buffer
	if _, err := backup.WriteLog(ctx, srcB, &streamB); err != nil {
		t.Fatalf("WriteLog B: %v", err)
	}

	target := openLog(t)
	if _, err := backup.RestoreLog(ctx, target, bytes.NewReader(streamA.Bytes())); err != nil {
		t.Fatalf("initial RestoreLog: %v", err)
	}
	if _, err := backup.VerifyLogMatchesWithKey(ctx, target, bytes.NewReader(streamB.Bytes()), nil); err == nil {
		t.Fatal("resume equivalence check accepted a different backup stream")
	}
}

// TestBackupRestorePreservesRewriteRetentionSequenceGapSubjectAndAuditCheckpointBoundary
// pins the cross-store DR invariant. ELI5: PostgreSQL remembers an audit boundary
// as "stream position 2." A rewrite changes the physical JetStream generation and
// retention can delete position 2, but backup/restore must keep that position as a
// gap. If restore renumbered the surviving receipt from 3 to 2, PostgreSQL would
// point at the wrong historical fact.
func TestBackupRestorePreservesRewriteRetentionSequenceGapSubjectAndAuditCheckpointBoundary(t *testing.T) {
	ctx := context.Background()
	const otherTenant = "22222222-2222-2222-2222-222222222222"
	src, err := events.Open(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithHistoryRewriteContinuityVerifier(func(context.Context, events.TenantDataContinuityEvidence) error {
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("events.Open source: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	rewritten, err := src.Append(ctx, events.Event{
		ID: "backup-rewrite-source", Type: "secret.version.written", TenantID: drTenant,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	})
	if err != nil {
		t.Fatalf("append rewrite source: %v", err)
	}
	retainedBoundary, err := src.Append(ctx, events.Event{
		ID: "backup-retention-boundary", Type: "owner.updated", TenantID: otherTenant,
		Data: []byte(`{"state":"archived"}`),
	})
	if err != nil {
		t.Fatalf("append retention boundary: %v", err)
	}
	if _, err := src.RewriteTenantData(
		ctx,
		drTenant,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			next := bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant"))
			return next, !bytes.Equal(next, data), nil
		},
		events.WithTenantDataPairValidator(func(_ string, _ int, before, after []byte) error {
			if bytes.Equal(before, after) {
				return errors.New("rewrite pair is unchanged")
			}
			return nil
		}),
		events.WithTenantDataCutoverPreparation(func(
			ctx context.Context,
			_ events.TenantDataRewriteReport,
			proceed func(context.Context) error,
		) error {
			return proceed(ctx)
		}),
		events.WithTenantDataAuditContinuity(func(
			context.Context,
			events.TenantDataAuditView,
		) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: "backup-test-genesis"}, nil
		}),
		events.WithTenantDataContinuity(func(
			_ context.Context,
			report events.TenantDataRewriteReport,
		) (events.Event, error) {
			data, err := json.Marshal(report)
			if err != nil {
				return events.Event{}, err
			}
			return events.Event{
				ID: "backup-rewrite-receipt", Type: "tenant.data.rewrite.receipt",
				TenantID: report.TenantID, Time: report.CompletedAt,
				SchemaVersion: events.DefaultSchemaVersion, Data: data,
			}, nil
		}),
	); err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}

	// Simulate a pre-B-3375cb42 audit checkpoint whose legacy retention worker
	// physically removed source messages. Production retention no longer calls
	// this deprecated primitive; exact backup must still preserve old legal gaps.
	auditCheckpointBoundary := retainedBoundary.Sequence
	checkpointSaved := false
	//nolint:staticcheck // The test deliberately constructs legacy physically pruned history.
	if err := src.PruneTenantThroughCheckpoint(
		ctx,
		otherTenant,
		auditCheckpointBoundary,
		func(context.Context) error {
			checkpointSaved = true
			return nil
		},
	); err != nil {
		t.Fatalf("PruneTenantThroughCheckpoint: %v", err)
	}
	if !checkpointSaved {
		t.Fatal("retention removed the boundary before saving its audit checkpoint")
	}

	cut, err := src.LastSequence(ctx)
	if err != nil {
		t.Fatalf("source LastSequence: %v", err)
	}
	if rewritten.Sequence != 1 || auditCheckpointBoundary != 2 || cut != 3 {
		t.Fatalf(
			"test setup sequences source=%d boundary=%d cut=%d, want 1/2/3",
			rewritten.Sequence, auditCheckpointBoundary, cut,
		)
	}
	wantHistory := collectExactHistory(t, src, cut)
	if len(wantHistory) != 3 ||
		!wantHistory[1].IsGap() ||
		wantHistory[1].Sequence != auditCheckpointBoundary ||
		wantHistory[1].GapThrough != auditCheckpointBoundary {
		t.Fatalf("source exact history = %+v, want event/gap/event with boundary gap", wantHistory)
	}

	var stream bytes.Buffer
	if _, err := backup.WriteLogWithKeyThrough(ctx, src, &stream, nil, cut); err != nil {
		t.Fatalf("WriteLogWithKeyThrough: %v", err)
	}
	summary, err := backup.VerifyEventLogBackup(bytes.NewReader(stream.Bytes()))
	if err != nil {
		t.Fatalf("VerifyEventLogBackup: %v", err)
	}
	if summary.EventCutSequence != cut ||
		summary.Records != 2 ||
		summary.HistoryEntries != 3 ||
		!summary.ExactSequenceLayout {
		t.Fatalf("event backup preflight = %+v, want cut=3 records=2 entries=3 exact", summary)
	}
	dst := openLog(t)
	if _, err := backup.RestoreLog(ctx, dst, bytes.NewReader(stream.Bytes())); err != nil {
		t.Fatalf("RestoreLog: %v", err)
	}
	gotHistory := collectExactHistory(t, dst, cut)
	assertExactHistoryEqual(t, gotHistory, wantHistory)

	// The PostgreSQL checkpoint remains coherent: sequence 2 is still the exact
	// archived gap, and the signed rewrite receipt remains sequence 3.
	if !gotHistory[1].IsGap() ||
		gotHistory[1].Sequence != auditCheckpointBoundary ||
		gotHistory[2].Event.Type != "tenant.data.rewrite.receipt" ||
		gotHistory[2].Sequence != cut {
		t.Fatalf(
			"restored checkpoint boundary/cut = gap %+v receipt %+v",
			gotHistory[1], gotHistory[2],
		)
	}
	if _, err := backup.VerifyLogMatchesWithKey(
		ctx, dst, bytes.NewReader(stream.Bytes()), nil,
	); err != nil {
		t.Fatalf("VerifyLogMatchesWithKey exact history: %v", err)
	}
	next, err := dst.Append(ctx, events.Event{
		ID: "backup-after-restore", Type: "owner.updated", TenantID: drTenant,
	})
	if err != nil {
		t.Fatalf("append after exact restore: %v", err)
	}
	if next.Sequence != cut+1 {
		t.Fatalf("post-restore sequence = %d, want %d", next.Sequence, cut+1)
	}
}

func collectExactHistory(t *testing.T, log *events.Log, cut uint64) []events.BackupHistoryRecord {
	t.Helper()
	var history []events.BackupHistoryRecord
	if err := log.ExportBackupHistoryThrough(
		context.Background(),
		cut,
		func(record events.BackupHistoryRecord) error {
			history = append(history, record)
			return nil
		},
	); err != nil {
		t.Fatalf("ExportBackupHistoryThrough: %v", err)
	}
	return history
}

func assertExactHistoryEqual(
	t *testing.T,
	got, want []events.BackupHistoryRecord,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("exact history entries = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Sequence != want[i].Sequence ||
			got[i].GapThrough != want[i].GapThrough ||
			got[i].Subject != want[i].Subject ||
			got[i].MessageID != want[i].MessageID ||
			!bytes.Equal(got[i].Stored, want[i].Stored) {
			t.Fatalf("exact history[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRestoreRejectsMalformedExactSequenceAndGapBeforeMutation(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	first, err := src.Append(ctx, events.Event{
		ID: "malformed-first", Type: "owner.created", TenantID: drTenant, Data: []byte(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	gap, err := src.Append(ctx, events.Event{
		ID: "malformed-gap", Type: "owner.updated", TenantID: drTenant, Data: []byte(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Delete(ctx, gap.Sequence); err != nil {
		t.Fatal(err)
	}
	last, err := src.Append(ctx, events.Event{
		ID: "malformed-last", Type: "owner.updated", TenantID: drTenant, Data: []byte(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var good bytes.Buffer
	if _, err := backup.WriteLogWithKeyThrough(ctx, src, &good, nil, last.Sequence); err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || gap.Sequence != 2 || last.Sequence != 3 {
		t.Fatalf("test setup sequences = %d/%d/%d", first.Sequence, gap.Sequence, last.Sequence)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "out of order gap",
			mutate: func(entry map[string]any) {
				if entry["kind"] == "gap" {
					entry["sequence"] = float64(3)
				}
			},
			want: "ordering",
		},
		{
			name: "gap beyond cut",
			mutate: func(entry map[string]any) {
				if entry["kind"] == "gap" {
					entry["gap_through"] = float64(4)
				}
			},
			want: "gap",
		},
		{
			name: "message id differs from stored envelope",
			mutate: func(entry map[string]any) {
				if entry["kind"] == "event" && entry["sequence"] == float64(1) {
					entry["message_id"] = "different-message-id"
				}
			},
			want: "message_id",
		},
		{
			name: "subject suffix differs from stored event type",
			mutate: func(entry map[string]any) {
				if entry["kind"] == "event" && entry["sequence"] == float64(1) {
					entry["subject"] = "events.owner.deleted"
				}
			},
			want: "subject",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			malformed := rewriteExactBackupAndChecksum(t, good.Bytes(), test.mutate)
			dst := openLog(t)
			n, err := backup.RestoreLog(ctx, dst, bytes.NewReader(malformed))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("RestoreLog error = %v, want %q rejection", err, test.want)
			}
			if n != 0 {
				t.Fatalf("malformed restore appended %d events, want 0", n)
			}
			head, headErr := dst.LastSequence(ctx)
			if headErr != nil {
				t.Fatal(headErr)
			}
			if head != 0 {
				t.Fatalf("malformed restore consumed history through %d before rejection", head)
			}
		})
	}

	t.Run("redundant JSON whitespace differs from stored bytes", func(t *testing.T) {
		malformed := bytes.Replace(
			good.Bytes(),
			[]byte(`"data":{}`),
			[]byte(`"data":{ }`),
			1,
		)
		if bytes.Equal(malformed, good.Bytes()) {
			t.Fatal("test setup did not alter redundant event data bytes")
		}
		malformed = resignExactBackup(t, malformed)
		dst := openLog(t)
		n, err := backup.RestoreLog(ctx, dst, bytes.NewReader(malformed))
		if err == nil || !strings.Contains(err.Error(), "decoded fields") {
			t.Fatalf("RestoreLog error = %v, want byte-different redundancy rejection", err)
		}
		if n != 0 {
			t.Fatalf("malformed restore appended %d events, want 0", n)
		}
		head, headErr := dst.LastSequence(ctx)
		if headErr != nil {
			t.Fatal(headErr)
		}
		if head != 0 {
			t.Fatalf("malformed restore consumed history through %d before rejection", head)
		}
	})
}

func TestExactRestoreRejectsDifferentArtifactWithSamePartialPrefixThenResumesOriginal(t *testing.T) {
	ctx := context.Background()
	first := events.Event{
		ID: "shared-prefix", Type: "owner.created", TenantID: drTenant,
		Time: time.Unix(100, 0).UTC(), SchemaVersion: events.DefaultSchemaVersion,
		Data: []byte(`{"same":true}`),
	}
	makeArtifact := func(t *testing.T, second events.Event) (*events.Log, []byte) {
		t.Helper()
		log := openLog(t)
		if _, err := log.Import(ctx, first); err != nil {
			t.Fatal(err)
		}
		if _, err := log.Import(ctx, second); err != nil {
			t.Fatal(err)
		}
		var stream bytes.Buffer
		if _, err := backup.WriteLog(ctx, log, &stream); err != nil {
			t.Fatal(err)
		}
		return log, stream.Bytes()
	}
	sourceA, artifactA := makeArtifact(t, events.Event{
		ID: "suffix-a", Type: "owner.updated", TenantID: drTenant,
		Time: time.Unix(101, 0).UTC(), SchemaVersion: events.DefaultSchemaVersion,
		Data: []byte(`{"suffix":"a"}`),
	})
	_, artifactB := makeArtifact(t, events.Event{
		ID: "suffix-b", Type: "owner.updated", TenantID: drTenant,
		Time: time.Unix(102, 0).UTC(), SchemaVersion: events.DefaultSchemaVersion,
		Data: []byte(`{"suffix":"b"}`),
	})
	historyA := collectExactHistory(t, sourceA, 2)
	digestA := exactBackupTrailerSHA(t, artifactA)

	target := openLog(t)
	_, err := target.RestoreBackupHistory(
		ctx,
		2,
		digestA,
		func(yield func(events.BackupHistoryRecord) error) error {
			if err := yield(historyA[0]); err != nil {
				return err
			}
			return errors.New("simulated process exit after first live ACK")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "simulated process exit") {
		t.Fatalf("partial exact restore error = %v", err)
	}

	if _, err := backup.RestoreLog(ctx, target, bytes.NewReader(artifactB)); !errors.Is(err, events.ErrBackupHistoryPrefixMismatch) {
		t.Fatalf("different artifact resume error = %v, want durable artifact-binding mismatch", err)
	}
	head, err := target.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != 1 {
		t.Fatalf("different artifact advanced partial target head to %d, want 1", head)
	}
	n, err := backup.RestoreLog(ctx, target, bytes.NewReader(artifactA))
	if err != nil {
		t.Fatalf("same artifact resume: %v", err)
	}
	if n != 2 {
		t.Fatalf("same artifact resume records = %d, want total 2", n)
	}
	assertExactHistoryEqual(t, collectExactHistory(t, target, 2), historyA)
}

func exactBackupTrailerSHA(t *testing.T, stream []byte) string {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(stream, []byte{'\n'}), []byte{'\n'})
	if len(lines) < 2 {
		t.Fatalf("backup lines = %d", len(lines))
	}
	var trailer struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(lines[len(lines)-1], &trailer); err != nil {
		t.Fatal(err)
	}
	if trailer.SHA256 == "" {
		t.Fatal("backup trailer has no sha256")
	}
	return trailer.SHA256
}

func TestLegacyV1RestorePolicyAcceptsOnlyCutBearingContiguousHistory(t *testing.T) {
	ctx := context.Background()
	cut := uint64(1)
	contiguous := legacyV1Backup(t, &cut, "")
	dst := openLog(t)
	n, err := backup.RestoreLog(ctx, dst, bytes.NewReader(contiguous))
	if err != nil {
		t.Fatalf("cut-bearing contiguous legacy v1 restore: %v", err)
	}
	if n != 1 {
		t.Fatalf("legacy v1 restored %d events, want 1", n)
	}
	got := collect(t, dst)
	if len(got) != 1 || got[0].Sequence != 1 || got[0].ID != "legacy-v1" {
		t.Fatalf("legacy v1 history = %+v", got)
	}

	for _, test := range []struct {
		name   string
		stream []byte
		want   string
	}{
		{
			name:   "pre-cut artifact",
			stream: legacyV1Backup(t, nil, ""),
			want:   "lacks exact sequences/gaps",
		},
		{
			name:   "unknown history layout",
			stream: legacyV1Backup(t, &cut, "future-layout"),
			want:   "unsupported history layout",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := openLog(t)
			n, err := backup.RestoreLog(ctx, target, bytes.NewReader(test.stream))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("RestoreLog error = %v, want %q", err, test.want)
			}
			if n != 0 {
				t.Fatalf("unsafe legacy restore appended %d events", n)
			}
			head, headErr := target.LastSequence(ctx)
			if headErr != nil {
				t.Fatal(headErr)
			}
			if head != 0 {
				t.Fatalf("unsafe legacy restore consumed sequence %d", head)
			}
		})
	}
}

func legacyV1Backup(t *testing.T, cut *uint64, layout string) []byte {
	t.Helper()
	header := map[string]any{
		"format":     "trstctl-event-log-backup",
		"version":    float64(1),
		"created_at": "2026-01-01T00:00:00Z",
	}
	trailer := map[string]any{
		"format":  "trstctl-event-log-backup-trailer",
		"records": float64(1),
	}
	if cut != nil {
		header["event_cut_sequence"] = float64(*cut)
		trailer["event_cut_sequence"] = float64(*cut)
	}
	if layout != "" {
		header["history_layout"] = layout
		trailer["history_layout"] = layout
	}
	event := map[string]any{
		"id": "legacy-v1", "type": "owner.created", "tenant_id": drTenant,
		"v": float64(1), "time": "2026-01-01T00:00:01Z",
		"data": map[string]any{"legacy": true},
	}
	headerLine, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	eventLine, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	body := append(append(append([]byte(nil), headerLine...), '\n'), eventLine...)
	body = append(body, '\n')
	trailer["sha256"] = trstcrypto.SHA256Hex(body)
	trailerLine, err := json.Marshal(trailer)
	if err != nil {
		t.Fatal(err)
	}
	stream := append([]byte(nil), body...)
	stream = append(stream, trailerLine...)
	stream = append(stream, '\n')
	return stream
}

func rewriteExactBackupAndChecksum(
	t *testing.T,
	stream []byte,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(stream, []byte{'\n'}), []byte{'\n'})
	if len(lines) < 3 {
		t.Fatalf("backup has %d lines, want header/entries/trailer", len(lines))
	}
	for i := 1; i < len(lines)-1; i++ {
		var entry map[string]any
		if err := json.Unmarshal(lines[i], &entry); err != nil {
			t.Fatal(err)
		}
		before, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		mutate(entry)
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, encoded) {
			lines[i] = encoded
		}
	}
	return resignExactBackup(t, append(bytes.Join(lines, []byte{'\n'}), '\n'))
}

func resignExactBackup(t *testing.T, stream []byte) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(stream, []byte{'\n'}), []byte{'\n'})
	if len(lines) < 3 {
		t.Fatalf("backup has %d lines, want header/entries/trailer", len(lines))
	}
	body := append(bytes.Join(lines[:len(lines)-1], []byte{'\n'}), '\n')
	var tr map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &tr); err != nil {
		t.Fatal(err)
	}
	tr["sha256"] = trstcrypto.SHA256Hex(body)
	encodedTrailer, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte(nil), body...)
	out = append(out, encodedTrailer...)
	out = append(out, '\n')
	return out
}
