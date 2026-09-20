// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func rewriteProofOptions(t *testing.T) []TenantDataRewriteOption {
	t.Helper()
	return []TenantDataRewriteOption{
		WithTenantDataPairValidator(func(_ string, _ int, before, after []byte) error {
			if bytes.Equal(before, after) {
				return errors.New("rewritten pair is byte-identical")
			}
			if bytes.Contains(after, []byte("deployment-ciphertext")) {
				return errors.New("rewritten pair retains the deployment ciphertext marker")
			}
			return nil
		}),
		WithTenantDataCutoverPreparation(func(
			ctx context.Context,
			_ TenantDataRewriteReport,
			proceed func(context.Context) error,
		) error {
			return proceed(ctx)
		}),
		WithTenantDataAuditContinuity(func(
			context.Context,
			TenantDataAuditView,
		) (TenantDataAuditCheckpoint, error) {
			return TenantDataAuditCheckpoint{
				IdentityDigest: crypto.SHA256Hex([]byte("test-genesis")),
			}, nil
		}),
		WithTenantDataContinuity(func(_ context.Context, report TenantDataRewriteReport) (Event, error) {
			data, err := json.Marshal(report)
			if err != nil {
				return Event{}, err
			}
			return Event{
				ID:            "rewrite-receipt-" + report.OperationID,
				Type:          "tenant.data.rewrite.receipt",
				TenantID:      report.TenantID,
				Time:          report.CompletedAt,
				SchemaVersion: DefaultSchemaVersion,
				Data:          data,
			}, nil
		}),
	}
}

func TestOnlyPrivacyExternalPreparationDefersCutoverSnapshotInvalidation(t *testing.T) {
	ctx := context.Background()
	if TenantDataCutoverDefersSnapshotInvalidation(ctx) {
		t.Fatal("plain context unexpectedly deferred snapshot invalidation")
	}
	generic := tenantDataCutoverPreparationContext(ctx, tenantDataRewriteOptions{})
	if TenantDataCutoverDefersSnapshotInvalidation(generic) {
		t.Fatal("generic rewrite unexpectedly deferred snapshot invalidation")
	}
	privacyCtx := tenantDataCutoverPreparationContext(ctx, tenantDataRewriteOptions{
		externalPreparation: func(context.Context, TenantDataRewriteReport) error { return nil },
		externalKind:        rewriteExternalPreparationPrivacySubjectErasure,
	})
	if !TenantDataCutoverDefersSnapshotInvalidation(privacyCtx) {
		t.Fatal("privacy external preparation did not own target snapshot invalidation")
	}
	wrongKind := tenantDataCutoverPreparationContext(ctx, tenantDataRewriteOptions{
		externalPreparation: func(context.Context, TenantDataRewriteReport) error { return nil },
		externalKind:        "future_external_preparation",
	})
	if TenantDataCutoverDefersSnapshotInvalidation(wrongKind) {
		t.Fatal("unknown external preparation weakened generic snapshot invalidation")
	}
}

func rewriteTestContinuityVerifier(_ context.Context, evidence TenantDataContinuityEvidence) error {
	if evidence.OperationID == "" || evidence.TenantID == "" ||
		evidence.ReceiptSequence == 0 || evidence.Receipt.ID == "" ||
		len(evidence.Receipt.Data) == 0 {
		return errors.New("incomplete rewrite continuity evidence")
	}
	if evidence.Report.OperationID != evidence.OperationID ||
		evidence.Report.TenantID != evidence.TenantID ||
		evidence.Report.SourceStream != evidence.SourceStream ||
		evidence.Report.TargetStream != evidence.TargetStream ||
		evidence.Report.ReceiptSequence != evidence.ReceiptSequence ||
		evidence.Report.TargetContentDigest == "" ||
		evidence.Report.SourceConfigDigest == "" ||
		evidence.Report.TargetConfigDigest == "" ||
		evidence.Report.ArchiveExposure != TenantDataArchiveExposureExternalCopiesMayRetainSourceBytes {
		return errors.New("rewrite report is not bound to continuity evidence")
	}
	reportPayload, err := json.Marshal(evidence.Report)
	if err != nil {
		return err
	}
	if !bytes.Equal(reportPayload, evidence.Receipt.Data) {
		return errors.New("receipt does not bind the exact rewrite report")
	}
	return nil
}

func openRewriteLog(t *testing.T, cfg config.NATS) (*Log, error) {
	t.Helper()
	return Open(context.Background(), cfg,
		WithHistoryRewriteContinuityVerifier(rewriteTestContinuityVerifier))
}

func openSecondReplicaLog(t *testing.T, primary *Log, history HistoryRewriteCoordinator) *Log {
	t.Helper()
	nc, err := nats.Connect("", nats.InProcessServer(primary.srv))
	if err != nil {
		t.Fatalf("connect second replica: %v", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		t.Fatalf("second replica JetStream: %v", err)
	}
	replica := &Log{
		nc: nc, js: js, mode: config.NATSExternal, desiredReplicas: 1,
		history: history, continuityVerifier: rewriteTestContinuityVerifier,
	}
	name, stream, err := replica.resolveActiveStream(context.Background())
	if err != nil {
		nc.Close()
		t.Fatalf("resolve second replica active stream: %v", err)
	}
	replica.setActiveStreamNamed(name, stream)
	t.Cleanup(func() { _ = replica.Close() })
	return replica
}

func TestTenantKeyDomainRewriteGenerationPreservesSequencesGapsSubjectsAndEnvelopes(t *testing.T) {
	ctx := context.Background()
	const (
		targetTenant = "11111111-1111-1111-1111-111111111111"
		otherTenant  = "22222222-2222-2222-2222-222222222222"
	)
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	target, err := log.Append(ctx, Event{
		ID: "target-event", Type: "secret.version.written", TenantID: targetTenant,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	})
	if err != nil {
		t.Fatalf("Append target: %v", err)
	}
	other, err := log.Append(ctx, Event{
		ID: "other-event", Type: "secret.version.written", TenantID: otherTenant,
		Data: []byte(`{"sealed":"other-tenant-ciphertext"}`),
	})
	if err != nil {
		t.Fatalf("Append other: %v", err)
	}
	deleted, err := log.Append(ctx, Event{
		ID: "deleted-event", Type: "owner.created", TenantID: otherTenant,
		Data: []byte(`{"deleted":true}`),
	})
	if err != nil {
		t.Fatalf("Append deleted: %v", err)
	}
	if err := log.Delete(ctx, deleted.Sequence); err != nil {
		t.Fatalf("create source gap: %v", err)
	}

	changed, err := log.RewriteTenantData(ctx, targetTenant, func(eventType string, schemaVersion int, data []byte) ([]byte, bool, error) {
		if eventType != "secret.version.written" {
			return nil, false, errors.New("unexpected event type")
		}
		if schemaVersion != DefaultSchemaVersion {
			return nil, false, errors.New("unexpected schema version")
		}
		return bytes.ReplaceAll(data, []byte("deployment-ciphertext"), []byte("tenant-domain-ciphertext")), true, nil
	}, rewriteProofOptions(t)...)
	if err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	if changed != 1 {
		t.Fatalf("RewriteTenantData changed %d events, want 1", changed)
	}
	raw := rawStreamBytes(t, log)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"sealed":"deployment-ciphertext"}`)))) {
		t.Fatalf("raw hot log retains target deployment ciphertext: %s", raw)
	}
	if !bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"sealed":"tenant-domain-ciphertext"}`)))) ||
		!bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"sealed":"other-tenant-ciphertext"}`)))) {
		t.Fatalf("raw hot log lost replacement or other tenant bytes: %s", raw)
	}

	var replayed []Event
	if err := log.Replay(ctx, 0, func(ev Event) error {
		replayed = append(replayed, ev)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(replayed) != 3 {
		t.Fatalf("Replay returned %d events, want two source events plus receipt", len(replayed))
	}
	if replayed[0].ID != target.ID || replayed[0].Time != target.Time ||
		replayed[0].Type != target.Type || replayed[0].TenantID != target.TenantID ||
		replayed[0].Sequence != target.Sequence {
		t.Fatalf("target event envelope changed: got %+v want %+v", replayed[0], target)
	}
	if replayed[1].ID != other.ID || replayed[1].Sequence != other.Sequence ||
		!bytes.Equal(replayed[1].Data, other.Data) {
		t.Fatalf("other tenant event changed: got %+v want %+v", replayed[1], other)
	}
	if replayed[2].Sequence != deleted.Sequence+1 ||
		replayed[2].Type != "tenant.data.rewrite.receipt" {
		t.Fatalf("receipt = %+v, want sequence %d after preserved gap", replayed[2], deleted.Sequence+1)
	}

	next, err := log.Append(ctx, Event{ID: "post-rewrite", Type: "owner.updated", TenantID: otherTenant})
	if err != nil {
		t.Fatalf("Append after rewrite: %v", err)
	}
	if next.Sequence != deleted.Sequence+2 {
		t.Fatalf("post-rewrite sequence = %d, want %d", next.Sequence, deleted.Sequence+2)
	}
	if _, err := log.js.Stream(ctx, streamName); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("source generation still exists after scrub: %v", err)
	}
}

func TestTenantKeyDomainRewriteFailureLeavesHotLogUntouched(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	if _, err := log.Append(ctx, Event{
		Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"first-deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"second-deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	before := rawStreamBytes(t, log)
	calls := 0
	changed, err := log.RewriteTenantData(ctx, tenantID, func(_ string, _ int, data []byte) ([]byte, bool, error) {
		calls++
		if calls == 2 {
			return nil, false, errors.New("synthetic rewrap failure")
		}
		return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
	}, rewriteProofOptions(t)...)
	if err == nil {
		t.Fatal("RewriteTenantData succeeded despite transform failure")
	}
	if changed != 0 {
		t.Fatalf("RewriteTenantData changed count = %d after abort, want 0", changed)
	}
	after := rawStreamBytes(t, log)
	if !bytes.Equal(after, before) {
		t.Fatalf("hot log changed after preflight failure:\nbefore=%s\nafter=%s", before, after)
	}
	name, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve active source: %v", err)
	}
	if name != streamName {
		t.Fatalf("active stream = %q after transform failure, want source %q", name, streamName)
	}
}

func TestTenantKeyDomainRewriteContinuityFailureRollsBackFrozenSource(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, Event{
		ID: "event", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := rawStreamBytes(t, log)
	options := rewriteProofOptions(t)
	options = append(options, WithTenantDataContinuity(func(context.Context, TenantDataRewriteReport) (Event, error) {
		return Event{}, errors.New("signer unavailable")
	}))
	_, err = log.RewriteTenantData(ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		options...,
	)
	if err == nil {
		t.Fatal("RewriteTenantData succeeded without continuity evidence")
	}
	if got := rawStreamBytes(t, log); !bytes.Equal(got, before) {
		t.Fatalf("source changed after continuity failure:\nbefore=%s\nafter=%s", before, got)
	}
	name, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve source after rollback: %v", err)
	}
	if name != streamName {
		t.Fatalf("active stream after rollback = %q, want %q", name, streamName)
	}
}

func TestTenantKeyDomainRewriteCallsRandomizedTransformOncePerChangedEvent(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := 0; i < 3; i++ {
		if _, err := log.Append(ctx, Event{
			ID: fmt.Sprintf("event-%d", i), Type: "secret.version.written", TenantID: tenantID,
			Data: []byte(fmt.Sprintf(`{"sealed":"deployment-ciphertext-%d"}`, i)),
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	var calls atomic.Int64
	opts := rewriteProofOptions(t)
	changed, err := log.RewriteTenantData(ctx, tenantID, func(_ string, _ int, data []byte) ([]byte, bool, error) {
		n := calls.Add(1)
		next := bytes.ReplaceAll(data, []byte("deployment-ciphertext"), []byte("tenant-domain-ciphertext"))
		next = bytes.Replace(next, []byte("}"), []byte(fmt.Sprintf(`,"nonce":%d}`, n)), 1)
		return next, true, nil
	}, opts...)
	if err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	if changed != 3 || calls.Load() != 3 {
		t.Fatalf("changed/calls = %d/%d, want 3/3; transform was re-run during reconcile", changed, calls.Load())
	}
}

func TestTenantKeyDomainRewriteRandomizedTransformCrashResumeDoesNotReinvoke(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := log.Append(ctx, Event{
			ID: fmt.Sprintf("event-%d", i), Type: "secret.version.written", TenantID: tenantID,
			Data: []byte(fmt.Sprintf(`{"sealed":"deployment-ciphertext-%d"}`, i)),
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	var calls atomic.Int64
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseActivated {
			return errRewriteTestCrash
		}
		return nil
	}
	_, err = log.RewriteTenantData(ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			calls.Add(1)
			next := bytes.ReplaceAll(data, []byte("deployment-ciphertext"), []byte("tenant-domain-ciphertext"))
			next = bytes.Replace(next, []byte("}"), []byte(`,"rewrap_nonce":"`+NewID()+`"}`), 1)
			return next, true, nil
		},
		rewriteProofOptions(t)...,
	)
	if !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("RewriteTenantData error = %v, want activated crash", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("randomized transform calls before restart = %d, want 2", calls.Load())
	}
	stagedBytes := rawStreamBytes(t, log)
	_ = log.Close()

	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after randomized transform crash: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if calls.Load() != 2 {
		t.Fatalf("recovery re-invoked randomized transform: calls=%d", calls.Load())
	}
	if recovered := rawStreamBytes(t, reopened); !bytes.Equal(recovered, stagedBytes) {
		t.Fatalf("recovery changed staged randomized bytes:\nbefore=%s\nafter=%s", stagedBytes, recovered)
	}
}

func TestTenantKeyDomainRewriteCapturesConcurrentAppendAtItsOriginalSequence(t *testing.T) {
	ctx := context.Background()
	const (
		targetTenant = "11111111-1111-1111-1111-111111111111"
		otherTenant  = "22222222-2222-2222-2222-222222222222"
	)
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, Event{
		ID: "target", Type: "secret.version.written", TenantID: targetTenant,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append target: %v", err)
	}

	transformEntered := make(chan struct{})
	releaseTransform := make(chan struct{})
	rewriteDone := make(chan error, 1)
	go func() {
		_, rewriteErr := log.RewriteTenantData(ctx, targetTenant, func(_ string, _ int, data []byte) ([]byte, bool, error) {
			close(transformEntered)
			<-releaseTransform
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		}, rewriteProofOptions(t)...)
		rewriteDone <- rewriteErr
	}()
	<-transformEntered
	concurrent, err := log.Append(ctx, Event{
		ID: "concurrent", Type: "owner.created", TenantID: otherTenant,
		Data: []byte(`{"during":"stage"}`),
	})
	if err != nil {
		t.Fatalf("concurrent Append: %v", err)
	}
	close(releaseTransform)
	if err := <-rewriteDone; err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}

	var got []Event
	if err := log.Replay(ctx, 0, func(e Event) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("replayed %d events, want target, concurrent append, receipt", len(got))
	}
	if got[1].ID != concurrent.ID || got[1].Sequence != concurrent.Sequence {
		t.Fatalf("concurrent append moved across cutover: got %+v want %+v", got[1], concurrent)
	}
	if got[2].Sequence != concurrent.Sequence+1 {
		t.Fatalf("receipt sequence = %d, want %d", got[2].Sequence, concurrent.Sequence+1)
	}
}

func TestTenantKeyDomainRewriteCrashAfterFreezeRecoversUnchangedSource(t *testing.T) {
	ctx := context.Background()
	storeDir := t.TempDir()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "target", Type: "secret.version.written",
		TenantID: "11111111-1111-1111-1111-111111111111",
		Data:     []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := rawStreamBytes(t, log)
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseFrozen {
			return errRewriteTestCrash
		}
		return nil
	}
	_, err = log.RewriteTenantData(ctx, "11111111-1111-1111-1111-111111111111",
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	)
	if !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("RewriteTenantData error = %v, want simulated crash", err)
	}
	_ = log.Close()

	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after frozen crash: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if got := rawStreamBytes(t, reopened); !bytes.Equal(got, before) {
		t.Fatalf("recovered source changed:\nbefore=%s\nafter=%s", before, got)
	}
	name, _, err := reopened.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve recovered source: %v", err)
	}
	if name != streamName {
		t.Fatalf("active stream after frozen recovery = %q, want %q", name, streamName)
	}
}

func TestTenantKeyDomainRewriteCrashBeforeFreezeRecoversUnchangedSource(t *testing.T) {
	ctx := context.Background()
	storeDir := t.TempDir()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "target", Type: "secret.version.written",
		TenantID: "11111111-1111-1111-1111-111111111111",
		Data:     []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := rawStreamBytes(t, log)
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseStaging {
			return errRewriteTestCrash
		}
		return nil
	}
	_, err = log.RewriteTenantData(ctx, "11111111-1111-1111-1111-111111111111",
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	)
	if !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("RewriteTenantData error = %v, want simulated crash", err)
	}
	_ = log.Close()

	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after staging crash: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if got := rawStreamBytes(t, reopened); !bytes.Equal(got, before) {
		t.Fatalf("recovered source changed:\nbefore=%s\nafter=%s", before, got)
	}
	name, _, err := reopened.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve recovered source: %v", err)
	}
	if name != streamName {
		t.Fatalf("active stream after staging recovery = %q, want %q", name, streamName)
	}
}

func TestTenantKeyDomainRewriteCrashAfterActivationKeepsTargetAndFinishesScrub(t *testing.T) {
	ctx := context.Background()
	storeDir := t.TempDir()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "target", Type: "secret.version.written",
		TenantID: "11111111-1111-1111-1111-111111111111",
		Data:     []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseActivated {
			return errRewriteTestCrash
		}
		return nil
	}
	_, err = log.RewriteTenantData(ctx, "11111111-1111-1111-1111-111111111111",
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	)
	if !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("RewriteTenantData error = %v, want simulated crash", err)
	}
	_ = log.Close()

	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after activation crash: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	raw := rawStreamBytes(t, reopened)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"sealed":"deployment-ciphertext"}`)))) {
		t.Fatalf("recovered target retains deployment ciphertext: %s", raw)
	}
	if _, err := reopened.js.Stream(ctx, streamName); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("frozen source survived activation recovery: %v", err)
	}
}

func TestTenantKeyDomainRewriteCrashMidScrubKeepsTargetAndFinishesScrub(t *testing.T) {
	ctx := context.Background()
	storeDir := t.TempDir()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := log.Append(ctx, Event{
			ID: fmt.Sprintf("target-%d", i), Type: "secret.version.written",
			TenantID: "11111111-1111-1111-1111-111111111111",
			Data:     []byte(fmt.Sprintf(`{"sealed":"deployment-ciphertext-%d"}`, i)),
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	var scrubCalls atomic.Int64
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseScrubbing && scrubCalls.Add(1) == 1 {
			return errRewriteTestCrash
		}
		return nil
	}
	_, err = log.RewriteTenantData(ctx, "11111111-1111-1111-1111-111111111111",
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	)
	if !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("RewriteTenantData error = %v, want mid-scrub crash", err)
	}
	if scrubCalls.Load() != 1 {
		t.Fatalf("scrub hook calls = %d, want 1 before crash", scrubCalls.Load())
	}
	_ = log.Close()

	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after mid-scrub crash: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	raw := rawStreamBytes(t, reopened)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte("deployment")))) ||
		bytes.Contains(raw, []byte("deployment-ciphertext")) {
		t.Fatalf("recovered target retains source-domain bytes: %s", raw)
	}
	if _, err := reopened.js.Stream(ctx, streamName); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("partially scrubbed source survived recovery: %v", err)
	}
}

func TestTenantKeyDomainRewriteRecoveryRejectsMetadataAndConfigTampering(t *testing.T) {
	for _, test := range []struct {
		name   string
		tamper func(*jetstream.StreamConfig)
	}{
		{
			name: "missing operation id",
			tamper: func(cfg *jetstream.StreamConfig) {
				delete(cfg.Metadata, rewriteMetadataOperation)
			},
		},
		{
			name: "unrelated metadata",
			tamper: func(cfg *jetstream.StreamConfig) {
				cfg.Metadata["operator.retention_class"] = "tampered"
			},
		},
		{
			name: "material stream field",
			tamper: func(cfg *jetstream.StreamConfig) {
				cfg.MaxMsgs = 99
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
			log, err := openRewriteLog(t, cfg)
			if err != nil {
				t.Fatalf("Open embedded: %v", err)
			}
			if _, err := log.Append(ctx, Event{
				ID: "target", Type: "secret.version.written",
				TenantID: "11111111-1111-1111-1111-111111111111",
				Data:     []byte(`{"sealed":"deployment-ciphertext"}`),
			}); err != nil {
				t.Fatalf("Append: %v", err)
			}
			log.rewriteTestHook = func(phase rewritePhase) error {
				if phase == rewritePhaseActivated {
					return errRewriteTestCrash
				}
				return nil
			}
			_, err = log.RewriteTenantData(ctx, "11111111-1111-1111-1111-111111111111",
				func(_ string, _ int, data []byte) ([]byte, bool, error) {
					return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
				},
				rewriteProofOptions(t)...,
			)
			if !errors.Is(err, errRewriteTestCrash) {
				t.Fatalf("RewriteTenantData error = %v, want activated crash", err)
			}
			_, target, err := log.resolveActiveStream(ctx)
			if err != nil {
				t.Fatalf("resolve activated target: %v", err)
			}
			info, err := log.infoForStream(ctx, target)
			if err != nil {
				t.Fatalf("target info: %v", err)
			}
			tampered := cloneStreamConfig(info.Config)
			test.tamper(&tampered)
			if _, err := log.js.UpdateStream(ctx, tampered); err != nil {
				t.Fatalf("apply tamper: %v", err)
			}
			_ = log.Close()

			reopened, err := openRewriteLog(t, cfg)
			if err == nil {
				_ = reopened.Close()
				t.Fatal("Open accepted tampered unfinished rewrite")
			}
		})
	}
}

func TestTenantKeyDomainRewriteActivePendingGenerationRejectsTamperingOnOpen(t *testing.T) {
	for _, test := range []struct {
		name   string
		tamper func(context.Context, *Log, jetstream.Stream, *jetstream.StreamInfo) error
	}{
		{
			name: "receipt message",
			tamper: func(ctx context.Context, _ *Log, target jetstream.Stream, info *jetstream.StreamInfo) error {
				sequence, err := strconv.ParseUint(info.Config.Metadata[rewriteMetadataReceiptSeq], 10, 64)
				if err != nil {
					return err
				}
				return target.SecureDeleteMsg(ctx, sequence)
			},
		},
		{
			name: "report metadata",
			tamper: func(ctx context.Context, log *Log, _ jetstream.Stream, info *jetstream.StreamInfo) error {
				cfg := cloneStreamConfig(info.Config)
				cfg.Metadata[rewriteMetadataReport] += "A"
				_, err := log.js.UpdateStream(ctx, cfg)
				return err
			},
		},
		{
			name: "config",
			tamper: func(ctx context.Context, log *Log, _ jetstream.Stream, info *jetstream.StreamInfo) error {
				cfg := cloneStreamConfig(info.Config)
				cfg.MaxMsgs = 42
				_, err := log.js.UpdateStream(ctx, cfg)
				return err
			},
		},
		{
			name: "target content",
			tamper: func(ctx context.Context, _ *Log, target jetstream.Stream, _ *jetstream.StreamInfo) error {
				return target.SecureDeleteMsg(ctx, 1)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
			log, err := openRewriteLog(t, cfg)
			if err != nil {
				t.Fatalf("Open embedded: %v", err)
			}
			if _, err := log.Append(ctx, Event{
				ID: "target", Type: "secret.version.written",
				TenantID: "11111111-1111-1111-1111-111111111111",
				Data:     []byte(`{"sealed":"deployment-ciphertext"}`),
			}); err != nil {
				t.Fatalf("Append: %v", err)
			}
			log.rewriteTestHook = func(phase rewritePhase) error {
				if phase == rewritePhaseActivated {
					return errRewriteTestCrash
				}
				return nil
			}
			if _, err := log.RewriteTenantData(ctx, "11111111-1111-1111-1111-111111111111",
				func(_ string, _ int, data []byte) ([]byte, bool, error) {
					return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
				},
				rewriteProofOptions(t)...,
			); !errors.Is(err, errRewriteTestCrash) {
				t.Fatalf("RewriteTenantData error = %v, want active-pending crash", err)
			}
			_, target, err := log.resolveActiveStream(ctx)
			if err != nil {
				t.Fatalf("resolve completed target: %v", err)
			}
			info, err := log.infoForStream(ctx, target)
			if err != nil {
				t.Fatalf("completed target info: %v", err)
			}
			if err := test.tamper(ctx, log, target, info); err != nil {
				t.Fatalf("apply tamper: %v", err)
			}
			_ = log.Close()

			reopened, err := openRewriteLog(t, cfg)
			if err == nil {
				_ = reopened.Close()
				t.Fatal("Open accepted tampered active-pending generation")
			}
		})
	}
}

func TestTenantKeyDomainRewriteRejectsMissingScopeOrTransform(t *testing.T) {
	log := &Log{}
	if _, err := log.RewriteTenantData(context.Background(), "", func(string, int, []byte) ([]byte, bool, error) {
		return nil, false, nil
	}); err == nil {
		t.Fatal("RewriteTenantData accepted empty tenant")
	}
	if _, err := log.RewriteTenantData(context.Background(), "tenant", nil); err == nil {
		t.Fatal("RewriteTenantData accepted nil transform")
	}
}

func TestTenantKeyDomainRewriteRequiresValidatorContinuityAndExternalCoordinator(t *testing.T) {
	ctx := context.Background()
	log := &Log{mode: config.NATSExternal, continuityVerifier: rewriteTestContinuityVerifier}
	transform := func(string, int, []byte) ([]byte, bool, error) {
		return []byte(`{"sealed":"tenant-ciphertext"}`), true, nil
	}
	if _, err := log.RewriteTenantData(ctx, "tenant", transform); err == nil {
		t.Fatal("RewriteTenantData accepted missing validator, continuity callback, and distributed coordinator")
	}
	if _, err := log.RewriteTenantData(ctx, "tenant", transform, rewriteProofOptions(t)...); err == nil {
		t.Fatal("external RewriteTenantData accepted missing distributed coordinator")
	}
}

func TestTenantKeyDomainRewriteTwoReplicasPreserveConcurrentAcknowledgedAppends(t *testing.T) {
	ctx := context.Background()
	const (
		targetTenant = "11111111-1111-1111-1111-111111111111"
		otherTenant  = "22222222-2222-2222-2222-222222222222"
	)
	primary, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open primary: %v", err)
	}
	t.Cleanup(func() { _ = primary.Close() })
	history := newLocalHistoryRewriteCoordinator()
	primary.history = history
	replica := openSecondReplicaLog(t, primary, history)

	first, err := primary.Append(ctx, Event{
		ID: "before-rewrite", Type: "secret.version.written", TenantID: targetTenant,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	})
	if err != nil {
		t.Fatalf("Append initial: %v", err)
	}
	stageEntered := make(chan struct{})
	releaseStage := make(chan struct{})
	frozen := make(chan struct{})
	publishEntered := make(chan struct{})
	var publishOnce sync.Once
	primary.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseFrozen {
			replica.publishAttemptTestHook = func() {
				publishOnce.Do(func() { close(publishEntered) })
			}
			close(frozen)
			<-publishEntered
		}
		return nil
	}
	rewriteDone := make(chan error, 1)
	go func() {
		_, rewriteErr := primary.RewriteTenantData(ctx, targetTenant,
			func(_ string, _ int, data []byte) ([]byte, bool, error) {
				close(stageEntered)
				<-releaseStage
				return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
			},
			rewriteProofOptions(t)...,
		)
		rewriteDone <- rewriteErr
	}()
	<-stageEntered
	duringStage, err := replica.Append(ctx, Event{
		ID: "during-stage", Type: "owner.created", TenantID: otherTenant,
	})
	if err != nil {
		t.Fatalf("second replica append during stage: %v", err)
	}
	close(releaseStage)
	<-frozen
	cutoverAppend := make(chan struct {
		event Event
		err   error
	}, 1)
	go func() {
		event, appendErr := replica.Append(ctx, Event{
			ID: "during-cutover", Type: "owner.updated", TenantID: otherTenant,
		})
		cutoverAppend <- struct {
			event Event
			err   error
		}{event: event, err: appendErr}
	}()
	if err := <-rewriteDone; err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	cutoverResult := <-cutoverAppend
	if cutoverResult.err != nil {
		t.Fatalf("second replica append across cutover: %v", cutoverResult.err)
	}

	var replayed []Event
	if err := replica.Replay(ctx, 0, func(event Event) error {
		replayed = append(replayed, event)
		return nil
	}); err != nil {
		t.Fatalf("second replica replay: %v", err)
	}
	if len(replayed) != 4 {
		t.Fatalf("replayed %d events, want initial, staged append, receipt, cutover append", len(replayed))
	}
	if replayed[0].ID != first.ID || replayed[0].Sequence != first.Sequence ||
		replayed[1].ID != duringStage.ID || replayed[1].Sequence != duringStage.Sequence ||
		replayed[2].Type != "tenant.data.rewrite.receipt" ||
		replayed[3].ID != cutoverResult.event.ID ||
		replayed[3].Sequence != cutoverResult.event.Sequence {
		t.Fatalf("acknowledged events did not survive exactly once in order: %+v", replayed)
	}
	for index, event := range replayed {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("replayed sequence[%d] = %d, want %d", index, event.Sequence, index+1)
		}
	}
}

func TestTailFromTwoReplicasShareOneDurableCursorPerGeneration(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	primary, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open primary: %v", err)
	}
	t.Cleanup(func() { _ = primary.Close() })
	history := newLocalHistoryRewriteCoordinator()
	primary.history = history
	replica := openSecondReplicaLog(t, primary, history)
	if _, err := primary.Append(ctx, Event{
		ID: "rewrite-me", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append source: %v", err)
	}
	if _, err := primary.RewriteTenantData(ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	head, err := primary.LastSequence(ctx)
	if err != nil {
		t.Fatalf("replacement head: %v", err)
	}
	var checkpoint atomic.Uint64
	checkpoint.Store(head)
	checkpointSource := func(context.Context) (uint64, error) {
		return checkpoint.Load(), nil
	}
	tailCtx, cancelTail := context.WithCancel(ctx)
	defer cancelTail()
	const appendedCount = 12
	var (
		mu        sync.Mutex
		seen      = make([]Event, 0, appendedCount)
		applyErr  error
		allSeen   = make(chan struct{})
		closeOnce sync.Once
	)
	apply := func(event Event) error {
		mu.Lock()
		defer mu.Unlock()
		if event.Sequence != checkpoint.Load()+1 {
			applyErr = fmt.Errorf(
				"global tail order broke: got seq %d after checkpoint %d",
				event.Sequence, checkpoint.Load(),
			)
			return applyErr
		}
		checkpoint.Store(event.Sequence)
		seen = append(seen, event)
		if len(seen) == appendedCount {
			closeOnce.Do(func() { close(allSeen) })
		}
		return nil
	}
	tailDone := make(chan error, 2)
	go func() { tailDone <- primary.TailFrom(tailCtx, checkpointSource, apply) }()
	go func() { tailDone <- replica.TailFrom(tailCtx, checkpointSource, apply) }()

	wantIDs := make([]string, 0, appendedCount)
	for i := 0; i < appendedCount; i++ {
		id := fmt.Sprintf("shared-tail-%02d", i)
		wantIDs = append(wantIDs, id)
		writer := primary
		if i%2 == 1 {
			writer = replica
		}
		if _, err := writer.Append(ctx, Event{
			ID: id, Type: "owner.updated", TenantID: tenantID,
		}); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}
	select {
	case <-allSeen:
	case <-time.After(10 * time.Second):
		t.Fatal("two replica tails did not drain the shared durable")
	}
	cancelTail()
	for i := 0; i < 2; i++ {
		select {
		case err := <-tailDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("TailFrom replica error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("TailFrom replica did not stop")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	if len(seen) != appendedCount {
		t.Fatalf("globally applied %d events, want %d", len(seen), appendedCount)
	}
	for i, event := range seen {
		if event.ID != wantIDs[i] {
			t.Fatalf("globally applied id[%d] = %q, want %q", i, event.ID, wantIDs[i])
		}
	}
}

func TestTailFromAcceptsLegacyDeliverAllDurableAndIdleFetch(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	_, stream, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve legacy stream: %v", err)
	}
	if _, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       tailConsumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		FilterSubject: subjectFilter,
		MaxAckPending: 1,
	}); err != nil {
		t.Fatalf("create legacy durable: %v", err)
	}
	var checkpoint atomic.Uint64
	tailCtx, cancelTail := context.WithCancel(ctx)
	defer cancelTail()
	seen := make(chan Event, 1)
	tailDone := make(chan error, 1)
	go func() {
		tailDone <- log.TailFrom(
			tailCtx,
			func(context.Context) (uint64, error) { return checkpoint.Load(), nil },
			func(event Event) error {
				checkpoint.Store(event.Sequence)
				seen <- event
				return nil
			},
		)
	}()
	// More than two FetchMaxWait windows: an empty pull timeout is normal idle,
	// not a terminal tail error.
	select {
	case err := <-tailDone:
		t.Fatalf("idle TailFrom returned early: %v", err)
	case <-time.After(650 * time.Millisecond):
	}
	appended, err := log.Append(ctx, Event{
		ID: "after-idle", Type: "owner.updated", TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("Append after idle: %v", err)
	}
	select {
	case event := <-seen:
		if event.ID != appended.ID || event.Sequence != appended.Sequence {
			t.Fatalf("legacy durable delivered %+v, want %+v", event, appended)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("legacy durable did not deliver append")
	}
	cancelTail()
	select {
	case err := <-tailDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("TailFrom stop error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TailFrom did not stop")
	}
}

func TestTailFromFollowsGenerationAndRestartsAtProjectionCheckpoint(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := log.Append(ctx, Event{
			ID: fmt.Sprintf("source-%d", i), Type: "secret.version.written", TenantID: tenantID,
			Data: []byte(`{"sealed":"deployment-ciphertext"}`),
		}); err != nil {
			t.Fatalf("Append source %d: %v", i, err)
		}
	}

	var checkpoint atomic.Uint64
	tailCtx, cancelTail := context.WithCancel(ctx)
	tailDone := make(chan error, 1)
	seen := make(chan Event, 8)
	go func() {
		tailDone <- log.TailFrom(
			tailCtx,
			func(context.Context) (uint64, error) { return checkpoint.Load(), nil },
			func(event Event) error {
				checkpoint.Store(event.Sequence)
				seen <- event
				return nil
			},
		)
	}()
	for want := uint64(1); want <= 2; want++ {
		select {
		case event := <-seen:
			if event.Sequence != want {
				t.Fatalf("initial tail sequence = %d, want %d", event.Sequence, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for initial tail sequence %d", want)
		}
	}

	if _, err := log.RewriteTenantData(ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	select {
	case event := <-seen:
		if event.Sequence != 3 || event.Type != "tenant.data.rewrite.receipt" {
			t.Fatalf("post-cutover tail event = %+v, want receipt at seq 3", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tail did not follow the activated generation")
	}
	cancelTail()
	select {
	case err := <-tailDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("TailFrom error = %v, want context cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tail did not stop")
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close before restart: %v", err)
	}

	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open replacement generation: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	restartCtx, cancelRestart := context.WithCancel(ctx)
	defer cancelRestart()
	restartSeen := make(chan Event, 2)
	restartDone := make(chan error, 1)
	restartReady := make(chan struct{})
	var restartReadyOnce sync.Once
	go func() {
		restartDone <- reopened.TailFrom(
			restartCtx,
			func(context.Context) (uint64, error) {
				restartReadyOnce.Do(func() { close(restartReady) })
				return checkpoint.Load(), nil
			},
			func(event Event) error {
				checkpoint.Store(event.Sequence)
				restartSeen <- event
				return nil
			},
		)
	}()
	select {
	case <-restartReady:
	case err := <-restartDone:
		t.Fatalf("restart tail exited before reading its durable checkpoint: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("restart tail did not read its durable checkpoint")
	}
	select {
	case event := <-restartSeen:
		t.Fatalf("restart replayed checkpointed event %+v", event)
	case err := <-restartDone:
		t.Fatalf("restart tail exited before the post-checkpoint append: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	appended, err := reopened.Append(ctx, Event{
		ID: "after-restart", Type: "owner.updated", TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("Append after restart: %v", err)
	}
	select {
	case event := <-restartSeen:
		if event.ID != appended.ID || event.Sequence != 4 {
			t.Fatalf("restart tail event = %+v, want appended seq 4", event)
		}
	case err := <-restartDone:
		t.Fatalf("restart tail exited before delivering the post-checkpoint append: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("restart tail did not receive post-checkpoint append")
	}
	cancelRestart()
	select {
	case err := <-restartDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("restart TailFrom error = %v, want context cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("restart tail did not stop")
	}
}

func TestTenantDataRewritePreservesOldEventDeduplicationIdentity(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		eventID  = "old-dedup-identity"
	)
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()

	original, err := log.Import(ctx, Event{
		ID: eventID, Type: "secret.version.written", TenantID: tenantID,
		Time: time.Now().UTC().Add(-2 * eventDedupWindow),
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	})
	if err != nil {
		t.Fatalf("Import old event: %v", err)
	}
	if _, err := log.RewriteTenantData(
		ctx,
		tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}

	_, active, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve replacement generation: %v", err)
	}
	raw, err := active.GetMsg(ctx, original.Sequence)
	if err != nil {
		t.Fatalf("read replacement event: %v", err)
	}
	if got := raw.Header.Values(jetstream.MsgIDHeader); len(got) != 1 || got[0] != eventID {
		t.Fatalf("replacement %s = %q, want exactly %q", jetstream.MsgIDHeader, got, eventID)
	}
	headBeforeRetry, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("replacement head: %v", err)
	}
	canonical, err := log.Append(ctx, Event{
		ID: eventID, Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"must-not-append"}`),
	})
	if err != nil {
		t.Fatalf("retry old event id: %v", err)
	}
	if canonical.Sequence != original.Sequence ||
		!bytes.Equal(canonical.Data, []byte(`{"sealed":"tenant-ciphertext"}`)) {
		t.Fatalf("retry returned %+v, want canonical rewritten sequence %d", canonical, original.Sequence)
	}
	headAfterRetry, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("head after retry: %v", err)
	}
	if headAfterRetry != headBeforeRetry {
		t.Fatalf("retry appended sequence %d after replacement head %d", headAfterRetry, headBeforeRetry)
	}
}

func TestLocalHistoryReadIsReentrantWhenCutoverWriterIsQueued(t *testing.T) {
	ctx := context.Background()
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: "nested-read", Type: "owner.created",
		TenantID: "11111111-1111-1111-1111-111111111111",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	history, ok := log.history.(*localHistoryRewriteCoordinator)
	if !ok {
		t.Fatalf("embedded history coordinator = %T", log.history)
	}
	writerStarted := make(chan struct{})
	writerAcquired := make(chan struct{})
	writerDone := make(chan error, 1)
	err = log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		go func() {
			close(writerStarted)
			writerDone <- history.WithCutover(ctx, func(context.Context) error {
				close(writerAcquired)
				return nil
			})
		}()
		<-writerStarted
		// Give the writer time to queue behind this outer read. A non-reentrant
		// nested RLock would now wait behind it forever.
		time.Sleep(25 * time.Millisecond)
		nestedDone := make(chan error, 1)
		go func() {
			nestedDone <- log.Replay(readCtx, 0, func(Event) error { return nil })
		}()
		select {
		case nestedErr := <-nestedDone:
			return nestedErr
		case <-writerAcquired:
			return errors.New("cutover writer acquired while outer history read was held")
		case <-time.After(2 * time.Second):
			return errors.New("nested history read deadlocked behind queued cutover writer")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatalf("queued cutover: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued cutover did not acquire after outer read released")
	}
}

func TestLocalHistoryCutoverMayEnterNestedRead(t *testing.T) {
	history := newLocalHistoryRewriteCoordinator()
	done := make(chan error, 1)
	go func() {
		done <- history.WithCutover(context.Background(), func(cutoverCtx context.Context) error {
			return history.WithRead(cutoverCtx, func(context.Context) error { return nil })
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cutover with nested read: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nested history read deadlocked while its cutover held the exclusive barrier")
	}
}

func TestEscapedLocalHistoryCutoverContextCannotBypassLaterCutover(t *testing.T) {
	ctx := context.Background()
	history := newLocalHistoryRewriteCoordinator()
	var escapedCutover context.Context
	if err := history.WithCutover(ctx, func(cutoverCtx context.Context) error {
		escapedCutover = cutoverCtx
		return nil
	}); err != nil {
		t.Fatalf("capture cutover context: %v", err)
	}

	cutoverEntered := make(chan struct{})
	releaseCutover := make(chan struct{})
	cutoverDone := make(chan error, 1)
	go func() {
		cutoverDone <- history.WithCutover(ctx, func(context.Context) error {
			close(cutoverEntered)
			<-releaseCutover
			return nil
		})
	}()
	<-cutoverEntered

	readEntered := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		readDone <- history.WithRead(escapedCutover, func(context.Context) error {
			close(readEntered)
			return nil
		})
	}()
	select {
	case <-readEntered:
		t.Fatal("escaped cutover context bypassed a later exclusive cutover")
	case <-time.After(75 * time.Millisecond):
	}
	close(releaseCutover)
	if err := <-cutoverDone; err != nil {
		t.Fatalf("later cutover: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("revoked cutover context read: %v", err)
	}
}

type opaqueHistoryCutoverGrantContextKey struct{}

type opaqueHistoryCutoverGrant struct {
	coordinator *opaqueHistoryRewriteCoordinator
	active      *atomic.Bool
}

type opaqueHistoryRewriteCoordinator struct {
	operation sync.Mutex
	barrier   sync.RWMutex
	bypassed  atomic.Int32
}

func (c *opaqueHistoryRewriteCoordinator) WithRewriteOperation(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	c.operation.Lock()
	defer c.operation.Unlock()
	return fn(ctx)
}

func (c *opaqueHistoryRewriteCoordinator) WithCutover(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	c.barrier.Lock()
	defer c.barrier.Unlock()
	active := &atomic.Bool{}
	active.Store(true)
	defer active.Store(false)
	return fn(context.WithValue(ctx, opaqueHistoryCutoverGrantContextKey{}, opaqueHistoryCutoverGrant{
		coordinator: c,
		active:      active,
	}))
}

func (c *opaqueHistoryRewriteCoordinator) WithRead(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	grant, _ := ctx.Value(opaqueHistoryCutoverGrantContextKey{}).(opaqueHistoryCutoverGrant)
	if grant.coordinator == c && grant.active != nil && grant.active.Load() {
		c.bypassed.Add(1)
		return fn(ctx)
	}
	c.barrier.RLock()
	defer c.barrier.RUnlock()
	return fn(ctx)
}

func TestExpiredGenerationViewDropsOpaqueCoordinatorCutoverGrant(t *testing.T) {
	coordinator := &opaqueHistoryRewriteCoordinator{}
	log := &Log{history: coordinator}
	readEntered := make(chan struct{}, 1)
	readResult := make(chan error, 1)

	err := coordinator.WithCutover(context.Background(), func(cutoverCtx context.Context) error {
		var escaped context.Context
		if err := log.withFrozenGenerationReadView(
			cutoverCtx, "frozen-source", nil,
			func(preparationCtx context.Context) error {
				escaped = preparationCtx
				return nil
			},
		); err != nil {
			return err
		}
		go func() {
			readResult <- log.withHistoryRead(escaped, func(context.Context) error {
				readEntered <- struct{}{}
				return nil
			})
		}()
		select {
		case <-readEntered:
			return errors.New("expired generation view reused an opaque coordinator cutover grant")
		case <-time.After(75 * time.Millisecond):
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readResult:
		if err != nil {
			t.Fatalf("ordinary read after cutover: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expired generation context did not reacquire after cutover")
	}
	if got := coordinator.bypassed.Load(); got != 0 {
		t.Fatalf("opaque coordinator grant bypasses = %d, want 0", got)
	}
}

func TestCompletedRewriteReceiptMayBeCheckpointPrunedAndReopened(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "retained-source", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := log.RewriteTenantData(
		ctx,
		tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("replacement head: %v", err)
	}
	_, active, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve replacement: %v", err)
	}
	info, err := log.infoForStream(ctx, active)
	if err != nil {
		t.Fatalf("replacement info: %v", err)
	}
	if info.Config.Metadata[rewriteMetadataGeneration] == "" {
		t.Fatal("completed replacement lost its generation marker")
	}
	for key := range info.Config.Metadata {
		if strings.HasPrefix(key, "trstctl.rewrite.") {
			t.Fatalf("completed replacement retained recovery-only metadata %q", key)
		}
	}
	checkpointSaved := false
	if err := log.PruneTenantThroughCheckpoint(
		ctx, tenantID, head, func(context.Context) error {
			checkpointSaved = true
			return nil
		},
	); err != nil {
		t.Fatalf("PruneTenantThroughCheckpoint: %v", err)
	}
	if !checkpointSaved {
		t.Fatal("retention deleted before saving its checkpoint")
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after legitimate receipt retention: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if err := reopened.Ping(ctx); err != nil {
		t.Fatalf("Ping pruned replacement: %v", err)
	}
}

func TestCheckpointedPruneRecoversBeforeFirstAndMidDelete(t *testing.T) {
	for _, test := range []struct {
		name   string
		failAt int
	}{
		{name: "before first delete", failAt: 1},
		{name: "mid delete", failAt: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			const tenantID = "11111111-1111-1111-1111-111111111111"
			cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
			log, err := openRewriteLog(t, cfg)
			if err != nil {
				t.Fatalf("Open embedded: %v", err)
			}
			var boundary uint64
			for i := 1; i <= 3; i++ {
				event, err := log.Append(ctx, Event{
					ID:   fmt.Sprintf("checkpoint-crash-%d", i),
					Type: "owner.updated", TenantID: tenantID,
				})
				if err != nil {
					t.Fatalf("Append %d: %v", i, err)
				}
				boundary = event.Sequence
			}
			checkpointSaved := false
			calls := 0
			log.pruneTestHook = func(uint64) error {
				calls++
				if calls == test.failAt {
					return errRewriteTestCrash
				}
				return nil
			}
			err = log.PruneTenantThroughCheckpoint(
				ctx, tenantID, boundary, func(context.Context) error {
					checkpointSaved = true
					return nil
				},
			)
			if !errors.Is(err, errRewriteTestCrash) || !checkpointSaved {
				t.Fatalf("checkpointed crash = %v, saved=%v", err, checkpointSaved)
			}
			if err := log.Close(); err != nil {
				t.Fatalf("Close crashed pruner: %v", err)
			}

			reopened, err := openRewriteLog(t, cfg)
			if err != nil {
				t.Fatalf("Open checkpointed partial prune: %v", err)
			}
			reopened.pruneTestHook = nil
			if err := reopened.PruneTenantThroughCheckpoint(
				ctx, tenantID, boundary, nil,
			); err != nil {
				_ = reopened.Close()
				t.Fatalf("recover checkpointed prune: %v", err)
			}
			var live int
			if err := reopened.Replay(ctx, 0, func(event Event) error {
				if event.TenantID == tenantID && event.Sequence <= boundary {
					live++
				}
				return nil
			}); err != nil {
				_ = reopened.Close()
				t.Fatalf("Replay recovered prune: %v", err)
			}
			if live != 0 {
				_ = reopened.Close()
				t.Fatalf("recovered prune retained %d authorized records", live)
			}
			_ = reopened.Close()
		})
	}
}

func TestRetentionPruneWaitsForPinnedHistoryRead(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()
	event, err := log.Append(ctx, Event{
		ID: "backup-pinned", Type: "owner.updated", TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	pruneStarted := make(chan struct{})
	checkpointCalled := make(chan struct{})
	pruneDone := make(chan error, 1)
	err = log.WithHistoryRead(ctx, func(context.Context) error {
		go func() {
			close(pruneStarted)
			pruneDone <- log.PruneTenantThroughCheckpoint(
				ctx, tenantID, event.Sequence, func(context.Context) error {
					close(checkpointCalled)
					return nil
				},
			)
		}()
		<-pruneStarted
		select {
		case <-checkpointCalled:
			return errors.New("retention checkpoint interleaved with pinned history read")
		case <-time.After(100 * time.Millisecond):
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-pruneDone:
		if err != nil {
			t.Fatalf("PruneTenantThroughCheckpoint: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retention prune did not continue after history read released")
	}
}

func TestDeleteWaitsForPinnedHistoryRead(t *testing.T) {
	ctx := context.Background()
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()
	event, err := log.Append(ctx, Event{
		ID: "delete-backup-pinned", Type: "owner.updated",
		TenantID: "11111111-1111-1111-1111-111111111111",
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	deleteStarted := make(chan struct{})
	deleteDone := make(chan error, 1)
	err = log.WithHistoryRead(ctx, func(context.Context) error {
		go func() {
			close(deleteStarted)
			deleteDone <- log.Delete(ctx, event.Sequence)
		}()
		<-deleteStarted
		select {
		case err := <-deleteDone:
			return fmt.Errorf("Delete completed inside pinned history read: %v", err)
		case <-time.After(75 * time.Millisecond):
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-deleteDone:
		if err != nil {
			t.Fatalf("Delete after read release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Delete did not continue after pinned history read released")
	}
}

func TestRetentionRecoversActivePendingRewriteBeforePruningReceipt(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: "pending-retention", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseActivated {
			return errRewriteTestCrash
		}
		return nil
	}
	if _, err := log.RewriteTenantData(
		ctx,
		tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("RewriteTenantData error = %v, want active-pending crash", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("pending target head: %v", err)
	}
	log.rewriteTestHook = nil
	if err := log.PruneTenantThroughCheckpoint(
		ctx, tenantID, head, func(context.Context) error { return nil },
	); err != nil {
		t.Fatalf("retention did not recover active-pending rewrite first: %v", err)
	}
	if _, err := log.js.Stream(ctx, streamName); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("retention left frozen source after recovery: %v", err)
	}
}

func TestRewriteNoOpRestoresPriorCompletedGenerationExactlyAndReopens(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "first-generation", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := log.RewriteTenantData(
		ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); err != nil {
		t.Fatalf("first RewriteTenantData: %v", err)
	}
	beforeName, beforeStream, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve completed generation: %v", err)
	}
	beforeInfo, err := log.infoForStream(ctx, beforeStream)
	if err != nil {
		t.Fatalf("completed generation info: %v", err)
	}
	beforeConfig := cloneStreamConfig(beforeInfo.Config)
	beforeBytes := rawStreamBytes(t, log)

	changed, err := log.RewriteTenantData(
		ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return append([]byte(nil), data...), false, nil
		},
		rewriteProofOptions(t)...,
	)
	if err != nil || changed != 0 {
		t.Fatalf("no-op rewrite = changed %d, err %v", changed, err)
	}
	afterName, afterStream, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve after no-op: %v", err)
	}
	afterInfo, err := log.infoForStream(ctx, afterStream)
	if err != nil {
		t.Fatalf("info after no-op: %v", err)
	}
	if afterName != beforeName {
		t.Fatalf("no-op changed generation %q -> %q", beforeName, afterName)
	}
	beforeConfigJSON, _ := json.Marshal(beforeConfig)
	afterConfigJSON, _ := json.Marshal(afterInfo.Config)
	if !bytes.Equal(beforeConfigJSON, afterConfigJSON) {
		t.Fatalf("no-op changed source config:\nbefore=%s\nafter=%s", beforeConfigJSON, afterConfigJSON)
	}
	if got := rawStreamBytes(t, log); !bytes.Equal(got, beforeBytes) {
		t.Fatalf("no-op changed source bytes:\nbefore=%s\nafter=%s", beforeBytes, got)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after no-op restore: %v", err)
	}
	_ = reopened.Close()
}

func TestLaterStagingCrashRestoresPriorCompletedGenerationOnOpen(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "staging-after-success", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := log.RewriteTenantData(
		ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); err != nil {
		t.Fatalf("first rewrite: %v", err)
	}
	beforeName, beforeStream, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve first generation: %v", err)
	}
	beforeInfo, err := log.infoForStream(ctx, beforeStream)
	if err != nil {
		t.Fatalf("first generation info: %v", err)
	}
	beforeConfig, _ := json.Marshal(beforeInfo.Config)
	beforeBytes := rawStreamBytes(t, log)
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseStaging {
			return errRewriteTestCrash
		}
		return nil
	}
	if _, err := log.RewriteTenantData(
		ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("tenant"), []byte("tenant-v2")), true, nil
		},
		rewriteProofOptions(t)...,
	); !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("second rewrite error = %v, want staging crash", err)
	}
	_ = log.Close()
	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after later staging crash: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	afterName, afterStream, err := reopened.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve recovered generation: %v", err)
	}
	afterInfo, err := reopened.infoForStream(ctx, afterStream)
	if err != nil {
		t.Fatalf("recovered generation info: %v", err)
	}
	afterConfig, _ := json.Marshal(afterInfo.Config)
	if afterName != beforeName || !bytes.Equal(afterConfig, beforeConfig) {
		t.Fatalf("staging recovery did not restore exact prior generation/config")
	}
	if got := rawStreamBytes(t, reopened); !bytes.Equal(got, beforeBytes) {
		t.Fatalf("staging recovery changed prior bytes:\nbefore=%s\nafter=%s", beforeBytes, got)
	}
}

func TestRewritePreservesCustomTargetMetadataAcrossRestart(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	_, source, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve source: %v", err)
	}
	info, err := log.infoForStream(ctx, source)
	if err != nil {
		t.Fatalf("source info: %v", err)
	}
	custom := cloneStreamConfig(info.Config)
	custom.Metadata["operator.retention_class"] = "regulated"
	custom.Metadata["operator.owner"] = "platform-security"
	if _, err := log.js.UpdateStream(ctx, custom); err != nil {
		t.Fatalf("set custom metadata: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "custom-metadata", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := log.RewriteTenantData(
		ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	_ = log.Close()
	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open replacement: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	_, target, err := reopened.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}
	targetInfo, err := reopened.infoForStream(ctx, target)
	if err != nil {
		t.Fatalf("target info: %v", err)
	}
	if got := targetInfo.Config.Metadata["operator.retention_class"]; got != "regulated" {
		t.Fatalf("target retention metadata = %q", got)
	}
	if got := targetInfo.Config.Metadata["operator.owner"]; got != "platform-security" {
		t.Fatalf("target owner metadata = %q", got)
	}
}

func TestTargetCreateFailureRestoresExactSourceConfigBytesAndReopens(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "create-failure", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	_, source, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve source: %v", err)
	}
	info, err := log.infoForStream(ctx, source)
	if err != nil {
		t.Fatalf("source info: %v", err)
	}
	beforeConfig, _ := json.Marshal(info.Config)
	beforeBytes := rawStreamBytes(t, log)
	log.createRewriteTargetTestHook = func() error {
		return errors.New("forced CreateStream failure")
	}
	if _, err := log.RewriteTenantData(
		ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); err == nil || !strings.Contains(err.Error(), "forced CreateStream failure") {
		t.Fatalf("RewriteTenantData create error = %v", err)
	}
	log.createRewriteTargetTestHook = nil
	_, restored, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve restored source: %v", err)
	}
	restoredInfo, err := log.infoForStream(ctx, restored)
	if err != nil {
		t.Fatalf("restored source info: %v", err)
	}
	afterConfig, _ := json.Marshal(restoredInfo.Config)
	if !bytes.Equal(afterConfig, beforeConfig) {
		t.Fatalf("target-create rollback changed config:\nbefore=%s\nafter=%s", beforeConfig, afterConfig)
	}
	if got := rawStreamBytes(t, log); !bytes.Equal(got, beforeBytes) {
		t.Fatalf("target-create rollback changed bytes:\nbefore=%s\nafter=%s", beforeBytes, got)
	}
	_ = log.Close()
	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open after target-create rollback: %v", err)
	}
	_ = reopened.Close()
}

func TestRewriteRecoveryRejectsSourceOnlyRestoreMetadataTamper(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "restore-tamper", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseStaging {
			return errRewriteTestCrash
		}
		return nil
	}
	if _, err := log.RewriteTenantData(
		ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("RewriteTenantData error = %v, want staging crash", err)
	}
	source, err := log.js.Stream(ctx, streamName)
	if err != nil {
		t.Fatalf("open marked source: %v", err)
	}
	sourceInfo, err := log.infoForStream(ctx, source)
	if err != nil {
		t.Fatalf("marked source info: %v", err)
	}
	tampered := cloneStreamConfig(sourceInfo.Config)
	tampered.Metadata[rewriteMetadataRestore] += "A"
	if _, err := log.js.UpdateStream(ctx, tampered); err != nil {
		t.Fatalf("tamper source restore point: %v", err)
	}
	_ = log.Close()
	reopened, err := openRewriteLog(t, cfg)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("Open accepted source-only restore metadata tamper")
	}
	if !strings.Contains(err.Error(), "restore digest mismatch") {
		t.Fatalf("Open tamper error = %v", err)
	}
}

func TestRewriteRetrySameProcessRecoversActivatedAndMidScrubAttempts(t *testing.T) {
	for _, test := range []struct {
		name  string
		phase rewritePhase
	}{
		{name: "activated", phase: rewritePhaseActivated},
		{name: "mid scrub", phase: rewritePhaseScrubbing},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			const tenantID = "11111111-1111-1111-1111-111111111111"
			log, err := openRewriteLog(t, config.NATS{
				Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
			})
			if err != nil {
				t.Fatalf("Open embedded: %v", err)
			}
			defer func() { _ = log.Close() }()
			for i := 0; i < 2; i++ {
				if _, err := log.Append(ctx, Event{
					ID:   fmt.Sprintf("same-process-%d", i),
					Type: "secret.version.written", TenantID: tenantID,
					Data: []byte(fmt.Sprintf(`{"sealed":"deployment-ciphertext-%d"}`, i)),
				}); err != nil {
					t.Fatalf("Append %d: %v", i, err)
				}
			}
			var crashed atomic.Bool
			log.rewriteTestHook = func(phase rewritePhase) error {
				if phase == test.phase && crashed.CompareAndSwap(false, true) {
					return errRewriteTestCrash
				}
				return nil
			}
			transform := func(_ string, _ int, data []byte) ([]byte, bool, error) {
				next := bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant"))
				return next, !bytes.Equal(next, data), nil
			}
			if _, err := log.RewriteTenantData(
				ctx, tenantID, transform, rewriteProofOptions(t)...,
			); !errors.Is(err, errRewriteTestCrash) {
				t.Fatalf("first rewrite error = %v, want crash at %s", err, test.phase)
			}
			log.rewriteTestHook = nil
			changed, err := log.RewriteTenantData(
				ctx, tenantID, transform, rewriteProofOptions(t)...,
			)
			if err != nil {
				t.Fatalf("same-process retry: %v", err)
			}
			if changed != 0 {
				t.Fatalf("same-process retry reported %d changes after recovering activated target", changed)
			}
			if state, err := log.findRewriteStreams(ctx); err != nil || state != nil {
				t.Fatalf("unfinished rewrite after same-process retry: state=%+v err=%v", state, err)
			}
			if _, err := log.js.Stream(ctx, streamName); !errors.Is(err, jetstream.ErrStreamNotFound) {
				t.Fatalf("same-process retry retained source generation: %v", err)
			}
		})
	}
}

func TestPingResolvesActiveStreamWhileCacheIsRefreshed(t *testing.T) {
	ctx := context.Background()
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()
	_, active, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve active: %v", err)
	}
	const attempts = 250
	errs := make(chan error, 2)
	go func() {
		for i := 0; i < attempts; i++ {
			log.setActiveStreamNamed("", nil)
			log.setActiveStream(active)
		}
		errs <- nil
	}()
	go func() {
		for i := 0; i < attempts; i++ {
			if err := log.Ping(ctx); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Ping/cache refresh: %v", err)
		}
	}
}

func TestEscapedLocalHistoryContextsCannotBypassLocksAfterCallback(t *testing.T) {
	ctx := context.Background()
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()

	var escapedRead context.Context
	if err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		escapedRead = readCtx
		return nil
	}); err != nil {
		t.Fatalf("capture read context: %v", err)
	}
	history := log.history.(*localHistoryRewriteCoordinator)
	writerEntered := make(chan struct{})
	releaseWriter := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- history.WithCutover(ctx, func(context.Context) error {
			close(writerEntered)
			<-releaseWriter
			return nil
		})
	}()
	<-writerEntered
	readEntered := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		readDone <- log.WithHistoryRead(escapedRead, func(context.Context) error {
			close(readEntered)
			return nil
		})
	}()
	select {
	case <-readEntered:
		t.Fatal("escaped read context bypassed a later exclusive cutover")
	case <-time.After(75 * time.Millisecond):
	}
	close(releaseWriter)
	if err := <-writerDone; err != nil {
		t.Fatalf("cutover writer: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("revoked read context reacquire: %v", err)
	}

	var escapedOperation context.Context
	if err := log.WithHistoryOperation(ctx, func(operationCtx context.Context) error {
		escapedOperation = operationCtx
		return nil
	}); err != nil {
		t.Fatalf("capture operation context: %v", err)
	}
	holderEntered := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- log.WithHistoryOperation(ctx, func(context.Context) error {
			close(holderEntered)
			<-releaseHolder
			return nil
		})
	}()
	<-holderEntered
	escapedEntered := make(chan struct{})
	escapedDone := make(chan error, 1)
	go func() {
		escapedDone <- log.WithHistoryOperation(escapedOperation, func(context.Context) error {
			close(escapedEntered)
			return nil
		})
	}()
	select {
	case <-escapedEntered:
		t.Fatal("escaped operation context bypassed a later operation holder")
	case <-time.After(75 * time.Millisecond):
	}
	close(releaseHolder)
	if err := <-holderDone; err != nil {
		t.Fatalf("operation holder: %v", err)
	}
	if err := <-escapedDone; err != nil {
		t.Fatalf("revoked operation context reacquire: %v", err)
	}
}

func TestRecoveryAuthenticatesReportBeforeWalkingSourceCutSequence(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "signed-before-walk", Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	log.rewriteTestHook = func(phase rewritePhase) error {
		if phase == rewritePhaseActivated {
			return errRewriteTestCrash
		}
		return nil
	}
	if _, err := log.RewriteTenantData(
		ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		},
		rewriteProofOptions(t)...,
	); !errors.Is(err, errRewriteTestCrash) {
		t.Fatalf("RewriteTenantData error = %v, want active-pending crash", err)
	}
	_, target, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}
	info, err := log.infoForStream(ctx, target)
	if err != nil {
		t.Fatalf("target info: %v", err)
	}
	report, err := rewriteReportFromMetadata(info.Config.Metadata)
	if err != nil {
		t.Fatalf("decode report: %v", err)
	}
	report.SourceCutSequence = 1 << 62
	reportPayload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode tampered report: %v", err)
	}
	tampered := cloneStreamConfig(info.Config)
	tampered.Metadata[rewriteMetadataReport] = base64.RawStdEncoding.EncodeToString(reportPayload)
	tampered.Metadata[rewriteMetadataReportSum] = crypto.SHA256Hex(reportPayload)
	if _, err := log.js.UpdateStream(ctx, tampered); err != nil {
		t.Fatalf("store tampered report: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	type openResult struct {
		log *Log
		err error
	}
	result := make(chan openResult, 1)
	go func() {
		reopened, err := Open(context.Background(), cfg,
			WithHistoryRewriteContinuityVerifier(rewriteTestContinuityVerifier))
		result <- openResult{log: reopened, err: err}
	}()
	select {
	case got := <-result:
		if got.log != nil {
			_ = got.log.Close()
		}
		if got.err == nil {
			t.Fatal("Open accepted unsigned SourceCutSequence tamper")
		}
		if !strings.Contains(got.err.Error(), "verify signed rewrite continuity") {
			t.Fatalf("Open rejected tamper after wrong validation stage: %v", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Open traversed attacker-controlled SourceCutSequence before signature verification")
	}
}
