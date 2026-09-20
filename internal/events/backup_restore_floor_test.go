// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

type pendingRestoreTailProbe struct {
	*localHistoryRewriteCoordinator
	firstReadDone chan struct{}
	once          sync.Once
}

func (p *pendingRestoreTailProbe) WithRead(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	err := p.localHistoryRewriteCoordinator.WithRead(ctx, fn)
	p.once.Do(func() { close(p.firstReadDone) })
	return err
}

func TestAuthorizedExactRestoreResumesUnsafeBoundPrefixAfterFloor(t *testing.T) {
	ctx := context.Background()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}
	history := []BackupHistoryRecord{
		legacySchedulerBackupRecord(t, 1, "legacy-run-1", "provider-credential"),
		backupHistoryEvent(t, 2, "after-legacy-run", "owner.updated"),
	}
	artifactDigest := strings.Repeat("a", 64)
	wrongArtifactDigest := strings.Repeat("b", 64)

	historyCoordinator := &pendingRestoreTailProbe{
		localHistoryRewriteCoordinator: newLocalHistoryRewriteCoordinator(),
		firstReadDone:                  make(chan struct{}),
	}
	partial, err := Open(ctx, cfg, WithHistoryRewriteCoordinator(historyCoordinator))
	if err != nil {
		t.Fatal(err)
	}

	// Start the durable projector before the restore begins. A partial restore
	// changes metadata on the same stream, so a tailer that checks only when it
	// first creates its consumer would otherwise reuse that consumer and apply the
	// artifact-bound prefix after the restore releases the cutover lock.
	tailCtx, cancelTail := context.WithCancel(ctx)
	t.Cleanup(cancelTail)
	tailApplied := make(chan struct{}, 1)
	errTailApplied := errors.New("tail applied an incomplete restore prefix")
	tailDone := make(chan error, 1)
	go func() {
		tailDone <- partial.TailFrom(
			tailCtx,
			func(context.Context) (uint64, error) { return 0, nil },
			func(Event) error {
				tailApplied <- struct{}{}
				return errTailApplied
			},
		)
	}()
	select {
	case <-historyCoordinator.firstReadDone:
	case <-time.After(5 * time.Second):
		t.Fatal("already-open tailer did not create its durable consumer")
	}

	// Model a process stop immediately after JetStream ACKed the first restored
	// envelope. The binding and prefix are installed under the same exclusive
	// cutover used by the real restore path, so the tailer can observe only the
	// complete before-view or the durable pending after-view.
	err = historyCoordinator.WithCutover(ctx, func(cutoverCtx context.Context) error {
		name, stream, err := partial.resolveActiveStream(cutoverCtx)
		if err != nil {
			return err
		}
		info, err := partial.infoForStream(cutoverCtx, stream)
		if err != nil {
			return err
		}
		_, _, err = partial.bindBackupRestoreIdentity(
			cutoverCtx, name, stream, info, 2, artifactDigest,
		)
		if err != nil {
			return err
		}
		restoreSubject, err := backupRestorePublishSubject(artifactDigest, history[0].Subject)
		if err != nil {
			return err
		}
		ack, err := partial.js.PublishMsg(cutoverCtx, &nats.Msg{
			Subject: restoreSubject,
			Data:    append([]byte(nil), history[0].Stored...),
		}, jetstream.WithMsgID(history[0].MessageID), jetstream.WithExpectStream(name), jetstream.WithExpectLastSequence(0))
		if err != nil {
			return err
		}
		if ack.Sequence != 1 {
			return errors.New("crash prefix was not acknowledged at sequence one")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("install crash-after-ACK prefix: %v", err)
	}

	select {
	case err := <-tailDone:
		if !errors.Is(err, ErrBackupRestoreIncomplete) {
			t.Fatalf("already-open tailer error = %v, want incomplete restore", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("already-open tailer did not fail closed on pending restore")
	}
	select {
	case <-tailApplied:
		t.Fatal("already-open tailer applied the artifact-bound prefix")
	default:
	}
	_, activeStream, err := partial.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve pending restore stream: %v", err)
	}
	consumer, err := activeStream.Consumer(ctx, tailConsumerName)
	if err != nil {
		t.Fatalf("open already-created tail consumer: %v", err)
	}
	consumerInfo, err := consumer.Info(ctx)
	if err != nil {
		t.Fatalf("inspect already-created tail consumer: %v", err)
	}
	if consumerInfo.AckFloor.Stream != 0 {
		t.Fatalf("pending restore tail ack floor = %d, want 0", consumerInfo.AckFloor.Stream)
	}

	// This Log was opened before the restore binding existed. Ordinary serving
	// must still refuse its next mutation instead of extending a prefix that only
	// the matching authenticated artifact may complete.
	if _, err := partial.Append(ctx, Event{
		ID: "ordinary-writer", Type: "owner.updated",
		TenantID: "11111111-1111-1111-1111-111111111111",
		Data:     []byte(`{"name":"must-not-append"}`),
	}); !errors.Is(err, ErrBackupRestoreIncomplete) {
		t.Fatalf("already-open append error = %v, want incomplete restore", err)
	}
	if head, err := partial.LastSequence(ctx); err != nil || head != 1 {
		t.Fatalf("pending restore head after refused append = %d, err %v, want 1", head, err)
	}
	if err := partial.Close(); err != nil {
		t.Fatal(err)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	authorizer, err := crypto.NewBackupRestoreAuthorizer(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Destroy)
	reopened, err := Open(ctx, cfg, WithBackupRestoreAuthorizer(authorizer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.RequireNoPendingBackupRestore(ctx); !errors.Is(err, ErrBackupRestoreIncomplete) {
		t.Fatalf("pending restore check = %v, want incomplete restore", err)
	}
	replayCalled := false
	if err := reopened.Replay(ctx, 0, func(Event) error {
		replayCalled = true
		return nil
	}); !errors.Is(err, ErrBackupRestoreIncomplete) || replayCalled {
		t.Fatalf("pending restore replay = (%v, called=%t), want fail before callback", err, replayCalled)
	}
	exportCalled := false
	if err := reopened.ExportBackupHistoryThrough(ctx, 1, func(BackupHistoryRecord) error {
		exportCalled = true
		return nil
	}); !errors.Is(err, ErrBackupRestoreIncomplete) || exportCalled {
		t.Fatalf("pending restore export = (%v, called=%t), want fail before callback", err, exportCalled)
	}
	if event, found, err := reopened.EventByID(ctx, history[0].MessageID); !errors.Is(err, ErrBackupRestoreIncomplete) || found || event.ID != "" {
		t.Fatalf("pending restore EventByID = (%+v, %t, %v), want zero fail-closed result", event, found, err)
	}
	if tenants, err := reopened.UnsafeLegacySchedulerHistoryTenants(ctx); !errors.Is(err, ErrBackupRestoreIncomplete) || len(tenants) != 0 {
		t.Fatalf(
			"pending restore sanitation discovery = (%v, %v), want zero fail-closed result",
			tenants, err,
		)
	}
	reopened.EnforceLegacySchedulerWriteFloor()
	historyDigest, err := BackupHistoryDigest(ctx, 2, backupHistorySource(history))
	if err != nil {
		t.Fatal(err)
	}
	wrongGrant, err := crypto.BackupRestoreAuthorization(key, crypto.BackupRestoreIntent{
		EventCutSequence: 2, ArtifactSHA256: wrongArtifactDigest, HistorySHA256: historyDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reopened.RestoreAuthorizedBackupHistory(
		ctx, 2, wrongArtifactDigest, wrongGrant, backupHistorySource(history),
	)
	wrongGrant.Destroy()
	if !errors.Is(err, ErrBackupHistoryPrefixMismatch) {
		t.Fatalf("wrong-artifact resume = %v, want prefix mismatch", err)
	}
	head, err := reopened.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != 1 {
		t.Fatalf("wrong artifact advanced crash prefix to %d", head)
	}

	grant, err := crypto.BackupRestoreAuthorization(key, crypto.BackupRestoreIntent{
		EventCutSequence: 2, ArtifactSHA256: artifactDigest, HistorySHA256: historyDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := reopened.RestoreAuthorizedBackupHistory(
		ctx, 2, artifactDigest, grant, backupHistorySource(history),
	)
	grant.Destroy()
	if err != nil {
		t.Fatalf("same-artifact resume: %v", err)
	}
	if n != 2 {
		t.Fatalf("same-artifact live count = %d, want 2", n)
	}
	if err := reopened.RequireNoPendingBackupRestore(ctx); err != nil {
		t.Fatalf("completed restore retained binding: %v", err)
	}
	if err := reopened.Replay(ctx, 0, func(Event) error { return nil }); !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
		t.Fatalf("restored unsafe prefix replay = %v, want sanitation requirement", err)
	}
}

func TestBackupRestoreBrokerFenceRejectsCrossReplicaPublishAfterMetadataCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	history := newLocalHistoryRewriteCoordinator()
	primary, err := Open(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true},
		WithHistoryRewriteCoordinator(history),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = primary.Close() })
	replica := openSecondReplicaLog(t, primary, history)

	checked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	replica.publishAfterRestoreCheckTestHook = func() {
		once.Do(func() {
			close(checked)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
	}
	appendDone := make(chan struct {
		event Event
		err   error
	}, 1)
	go func() {
		event, appendErr := replica.Append(ctx, Event{
			ID:       "ordinary-writer-racing-restore",
			Type:     "owner.updated",
			TenantID: "11111111-1111-1111-1111-111111111111",
			Data:     []byte(`{"name":"must-not-append"}`),
		})
		appendDone <- struct {
			event Event
			err   error
		}{event: event, err: appendErr}
	}()

	select {
	case <-checked:
	case <-ctx.Done():
		t.Fatalf("ordinary replica did not reach the pre-publish restore check: %v", ctx.Err())
	}
	artifactDigest := strings.Repeat("c", 64)
	err = history.WithCutover(ctx, func(cutoverCtx context.Context) error {
		name, stream, err := primary.resolveActiveStream(cutoverCtx)
		if err != nil {
			return err
		}
		info, err := primary.infoForStream(cutoverCtx, stream)
		if err != nil {
			return err
		}
		_, _, err = primary.bindBackupRestoreIdentity(
			cutoverCtx, name, stream, info, 1, artifactDigest,
		)
		return err
	})
	if err != nil {
		close(release)
		t.Fatalf("bind cross-replica restore: %v", err)
	}
	close(release)

	var result struct {
		event Event
		err   error
	}
	select {
	case result = <-appendDone:
	case <-ctx.Done():
		t.Fatalf("racing ordinary append did not finish: %v", ctx.Err())
	}
	if !errors.Is(result.err, ErrBackupRestoreIncomplete) {
		t.Fatalf("racing ordinary append error = %v, want incomplete restore", result.err)
	}
	if result.event.ID != "" || result.event.Sequence != 0 {
		t.Fatalf("racing ordinary append returned an event: %+v", result.event)
	}
	_, pending, found, err := primary.pendingBackupRestoreStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("broker fence lost the pending restore generation")
	}
	info, err := primary.infoForStream(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.LastSeq != 0 || info.State.Msgs != 0 {
		t.Fatalf(
			"broker fence admitted racing append: head=%d messages=%d",
			info.State.LastSeq, info.State.Msgs,
		)
	}
}

func TestOpenFreezesLegacyPendingRestoreBeforeReturningUsableLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}
	artifactDigest := strings.Repeat("d", 64)
	history := []BackupHistoryRecord{
		backupHistoryEvent(t, 1, "legacy-bound-prefix", "owner.created"),
		backupHistoryEvent(t, 2, "legacy-bound-suffix", "owner.updated"),
	}

	legacy, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	name, stream, err := legacy.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info, err := legacy.infoForStream(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	legacyCfg := cloneStreamConfig(info.Config)
	legacyCfg.Metadata[backupRestoreMetadataDigest] = artifactDigest
	legacyCfg.Metadata[backupRestoreMetadataCut] = "2"
	if _, err := legacy.js.UpdateStream(ctx, legacyCfg); err != nil {
		t.Fatal(err)
	}
	ack, err := legacy.js.PublishMsg(
		ctx,
		&nats.Msg{
			Subject: history[0].Subject,
			Data:    append([]byte(nil), history[0].Stored...),
		},
		jetstream.WithMsgID(history[0].MessageID),
		jetstream.WithExpectStream(name),
		jetstream.WithExpectLastSequence(0),
	)
	if err != nil || ack.Sequence != 1 {
		t.Fatalf("install legacy pending prefix: ack=%+v err=%v", ack, err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open legacy pending restore: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	_, pending, found, err := reopened.pendingBackupRestoreStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("Open lost the legacy pending restore")
	}
	pendingInfo, err := reopened.infoForStream(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	if !backupRestoreRouteIsFrozen(pendingInfo.Config, artifactDigest) {
		t.Fatalf("Open returned before freezing legacy route: %+v", pendingInfo.Config)
	}

	if _, err := reopened.js.PublishMsg(
		ctx,
		&nats.Msg{
			Subject: history[1].Subject,
			Data:    append([]byte(nil), history[1].Stored...),
		},
		jetstream.WithMsgID(history[1].MessageID),
		jetstream.WithExpectStream(name),
		jetstream.WithExpectLastSequence(1),
	); err == nil {
		t.Fatal("ordinary broker route extended a legacy artifact-bound prefix after Open")
	}
	if head, err := reopened.LastSequence(ctx); err != nil || head != 1 {
		t.Fatalf("legacy pending head after refused broker publish = %d, err=%v, want 1", head, err)
	}

	n, err := reopened.RestoreBackupHistory(
		ctx, 2, artifactDigest, backupHistorySource(history),
	)
	if err != nil {
		t.Fatalf("resume startup-frozen legacy restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("resumed legacy restore live count = %d, want 2", n)
	}
	if err := reopened.RequireNoPendingBackupRestore(ctx); err != nil {
		t.Fatalf("resumed legacy restore retained binding: %v", err)
	}
}

func TestPendingRestoreRejectsUnrelatedHistoryMutationsAndReadiness(t *testing.T) {
	ctx := context.Background()
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	history := []BackupHistoryRecord{
		backupHistoryEvent(t, 1, "bound-before-rewrite", "owner.created"),
		backupHistoryEvent(t, 2, "bound-after-rewrite", "owner.updated"),
	}
	errCrash := errors.New("simulated restore process stop")
	_, err = log.RestoreBackupHistory(
		ctx, 2, strings.Repeat("e", 64),
		func(yield func(BackupHistoryRecord) error) error {
			if err := yield(history[0]); err != nil {
				return err
			}
			return errCrash
		},
	)
	if !errors.Is(err, errCrash) {
		t.Fatalf("install pending rewrite prefix: %v", err)
	}
	if err := log.Ping(ctx); !errors.Is(err, ErrBackupRestoreIncomplete) {
		t.Fatalf("pending restore readiness = %v, want incomplete restore", err)
	}
	readCalled := false
	if err := log.WithHistoryRead(ctx, func(context.Context) error {
		readCalled = true
		return nil
	}); !errors.Is(err, ErrBackupRestoreIncomplete) || readCalled {
		t.Fatalf(
			"pending generic history read = (err=%v, called=%t), want incomplete/false",
			err, readCalled,
		)
	}
	operationCalled := false
	if err := log.WithHistoryOperation(ctx, func(context.Context) error {
		operationCalled = true
		return nil
	}); !errors.Is(err, ErrBackupRestoreIncomplete) || operationCalled {
		t.Fatalf(
			"pending generic history operation = (err=%v, called=%t), want incomplete/false",
			err, operationCalled,
		)
	}
	if err := log.Delete(ctx, 1); !errors.Is(err, ErrBackupRestoreIncomplete) {
		t.Fatalf("pending restore delete = %v, want incomplete restore", err)
	}
	if err := log.PruneTenantThroughCheckpoint(
		ctx, history[0].Event.TenantID, 1, nil,
	); !errors.Is(err, ErrBackupRestoreIncomplete) {
		t.Fatalf("pending restore prune = %v, want incomplete restore", err)
	}
	if err := log.PseudonymizeSubject(
		ctx,
		history[0].Event.TenantID,
		"unrelated-subject",
		rewriteProofOptions(t)...,
	); !errors.Is(err, ErrBackupRestoreIncomplete) {
		t.Fatalf("pending restore pseudonymization = %v, want incomplete restore", err)
	}

	changed, err := log.RewriteTenantData(
		ctx,
		history[0].Event.TenantID,
		func(_ string, _ int, _ []byte) ([]byte, bool, error) {
			return []byte(`{"sequence":9}`), true, nil
		},
		rewriteProofOptions(t)...,
	)
	if !errors.Is(err, ErrBackupRestoreIncomplete) || changed != 0 {
		t.Fatalf(
			"unrelated generation rewrite = (changed=%d, err=%v), want zero/incomplete restore",
			changed, err,
		)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != 1 {
		t.Fatalf("pending head after refused rewrite = %d, err=%v, want 1", head, err)
	}
	_, pending, found, err := log.pendingBackupRestoreStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("unrelated history operations cleared the pending binding")
	}
	raw, err := pending.GetMsg(ctx, 1)
	if err != nil {
		t.Fatalf("unrelated history operations deleted the bound prefix: %v", err)
	}
	if err := matchBackupLiveRecord(raw, history[0]); err != nil {
		t.Fatalf("unrelated history operations changed the bound prefix: %v", err)
	}
}

func TestOpenRequiringSanitizedSchedulerHistoryRejectsUnsafeHistoryAndInstallsFloor(t *testing.T) {
	ctx := context.Background()
	unsafeCfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}
	unsafeLog, err := Open(ctx, unsafeCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unsafeLog.Append(ctx, Event{
		ID: "unsafe-run", Type: schedulerhistory.EventType,
		TenantID: "11111111-1111-1111-1111-111111111111", SchemaVersion: 1,
		Data: []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"provider-credential"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := unsafeLog.Close(); err != nil {
		t.Fatal(err)
	}
	if log, err := OpenRequiringSanitizedSchedulerHistory(ctx, unsafeCfg); !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
		if log != nil {
			_ = log.Close()
		}
		t.Fatalf("unsafe safe-open = %v, want sanitation requirement", err)
	}

	safeCfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}
	safeLog, err := OpenRequiringSanitizedSchedulerHistory(ctx, safeCfg)
	if err != nil {
		t.Fatalf("safe history open: %v", err)
	}
	t.Cleanup(func() { _ = safeLog.Close() })
	if _, err := safeLog.Append(ctx, Event{
		ID: "late-unsafe-run", Type: schedulerhistory.EventType,
		TenantID: "11111111-1111-1111-1111-111111111111", SchemaVersion: 1,
		Data: []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"provider-credential"}`),
	}); !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
		t.Fatalf("post-open legacy append = %v, want sanitation requirement", err)
	}
}

func legacySchedulerBackupRecord(t *testing.T, sequence uint64, id, detail string) BackupHistoryRecord {
	t.Helper()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	when := time.Unix(int64(sequence), 0).UTC() // #nosec G115 -- tiny fixed test sequence
	data := []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"` + detail + `"}`)
	stored, err := json.Marshal(storedEvent{
		ID: id, Type: schedulerhistory.EventType, TenantID: tenantID, Time: when,
		SchemaVersion: schedulerhistory.LegacySchemaVersion, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return BackupHistoryRecord{
		Sequence: sequence, Subject: "events." + schedulerhistory.EventType,
		MessageID: id, Stored: stored,
		Event: Event{
			Sequence: sequence, ID: id, Type: schedulerhistory.EventType,
			TenantID: tenantID, Time: when, SchemaVersion: schedulerhistory.LegacySchemaVersion,
			Data: data,
		},
	}
}
