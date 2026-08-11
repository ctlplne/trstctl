// SPDX-License-Identifier: MPL-2.0

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

type schedulerResumeFixture struct {
	log      *events.Log
	artifact []byte
	key      []byte
	report   events.TenantDataRewriteReport
}

func TestVerifyLogMatchesSanitizedSchedulerHistoryDoesNotLoosenExactResume(t *testing.T) {
	ctx := context.Background()
	fixture := newSchedulerResumeFixture(t, "provider-credential-in-old-history")

	if _, err := VerifyLogMatchesWithKey(
		ctx, fixture.log, bytes.NewReader(fixture.artifact), fixture.key,
	); err == nil {
		t.Fatal("generic exact verifier accepted the rewritten descendant")
	}
	if _, err := VerifyLogMatchesSanitizedSchedulerHistoryWithKey(
		ctx, fixture.log, bytes.NewReader(fixture.artifact), fixture.key, openTestRewriteReceipt,
	); err != nil {
		t.Fatalf("sanitation descendant did not verify: %v", err)
	}
}

func TestVerifyLogMatchesSanitizedSchedulerHistoryRejectsTransplantedReceipt(t *testing.T) {
	ctx := context.Background()
	fixture := newSchedulerResumeFixture(t, "first-provider-credential")
	other := newSchedulerResumeFixture(t, "different-provider-credential")

	if fixture.report.TenantID != other.report.TenantID ||
		fixture.report.ChangedEvents != other.report.ChangedEvents ||
		fixture.report.SourceCutSequence != other.report.SourceCutSequence {
		t.Fatal("test receipts do not share the tenant/count/cut transplant preconditions")
	}
	transplanted := func(
		_ context.Context,
		_ events.Event,
	) (events.TenantDataRewriteReport, error) {
		return other.report, nil
	}
	if _, err := VerifyLogMatchesSanitizedSchedulerHistoryWithKey(
		ctx, fixture.log, bytes.NewReader(fixture.artifact), fixture.key, transplanted,
	); err == nil {
		t.Fatal("sanitation descendant accepted a signed report from another generation/content lineage")
	}

	wrongRoots := fixture.report
	wrongRoots.EnvelopeDigest = other.report.EnvelopeDigest
	wrongRoots.MappingDigest = other.report.MappingDigest
	wrongRoots.TargetContentDigest = other.report.TargetContentDigest
	if wrongRoots.MappingDigest == fixture.report.MappingDigest &&
		wrongRoots.TargetContentDigest == fixture.report.TargetContentDigest {
		t.Fatal("test fixture did not produce distinct signed content roots")
	}
	transplantedRoots := func(
		_ context.Context,
		_ events.Event,
	) (events.TenantDataRewriteReport, error) {
		return wrongRoots, nil
	}
	if _, err := VerifyLogMatchesSanitizedSchedulerHistoryWithKey(
		ctx, fixture.log, bytes.NewReader(fixture.artifact), fixture.key, transplantedRoots,
	); err == nil {
		t.Fatal("sanitation descendant accepted transplanted envelope/mapping/target-content roots")
	}
}

func newSchedulerResumeFixture(t *testing.T, secretDetail string) schedulerResumeFixture {
	t.Helper()
	ctx := context.Background()
	var signedReport events.TenantDataRewriteReport
	verifier := func(_ context.Context, evidence events.TenantDataContinuityEvidence) error {
		var report events.TenantDataRewriteReport
		if err := json.Unmarshal(evidence.Receipt.Data, &report); err != nil {
			return err
		}
		if report != evidence.Report {
			return errors.New("receipt report mismatch")
		}
		return nil
	}
	log, err := events.Open(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithHistoryRewriteContinuityVerifier(verifier),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	tenantID := "11111111-1111-1111-1111-111111111111"
	if _, err := log.Append(ctx, events.Event{
		Type: schedulerhistory.EventType, TenantID: tenantID, SchemaVersion: 1,
		Data: []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"` + secretDetail + `"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: "unrelated.event", TenantID: tenantID, Data: []byte(`{"exact":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	cut, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("scheduler-history-resume-integrity-key")
	var artifact bytes.Buffer
	if _, err := writeSanitizedLogWithKeyThrough(ctx, log, &artifact, key, cut); err != nil {
		t.Fatal(err)
	}
	proof := []events.TenantDataRewriteOption{
		events.WithTenantDataPairValidator(func(eventType string, version int, before, after []byte) error {
			if eventType != schedulerhistory.EventType || version != 1 {
				return errors.New("wrong rewrite target")
			}
			return schedulerhistory.ValidateLegacyRunPair(before, after)
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
			return events.TenantDataAuditCheckpoint{
				IdentityDigest: crypto.SHA256Hex([]byte("genesis")),
			}, nil
		}),
		events.WithTenantDataRewriteProfile(schedulerhistory.RewriteProfile),
		events.WithTenantDataContinuity(func(
			_ context.Context,
			report events.TenantDataRewriteReport,
		) (events.Event, error) {
			signedReport = report
			data, err := json.Marshal(report)
			return events.Event{
				ID: events.NewID(), Type: "history.tenant_data_rewrite.continuity",
				TenantID: report.TenantID, Time: report.CompletedAt, Data: data,
			}, err
		}),
	}
	if _, err := log.RewriteTenantData(
		ctx,
		tenantID,
		func(eventType string, version int, data []byte) ([]byte, bool, error) {
			if eventType != schedulerhistory.EventType || version != 1 {
				return data, false, nil
			}
			return schedulerhistory.RewriteLegacyRun(data)
		},
		proof...,
	); err != nil {
		t.Fatal(err)
	}
	return schedulerResumeFixture{
		log: log, artifact: append([]byte(nil), artifact.Bytes()...),
		key: append([]byte(nil), key...), report: signedReport,
	}
}

func openTestRewriteReceipt(
	_ context.Context,
	event events.Event,
) (events.TenantDataRewriteReport, error) {
	var report events.TenantDataRewriteReport
	err := json.Unmarshal(event.Data, &report)
	return report, err
}
