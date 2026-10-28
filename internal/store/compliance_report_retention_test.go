// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// A206: a run's legal hold, queued removal and confirmed removal project per
// run. A hold cancels a queued removal and refuses a run that is not completed
// or has expired; each removal request queues one outbox row keyed by its
// event, so a run released after a hold is queued again; replays change
// nothing; the retention listing skips held, queued and expired runs, the full
// backup's listing skips expired ones, and neither crosses tenants.
func TestComplianceReportRetentionProjectsHoldsAndRemovals(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	// IDs and dates no other test in this package uses: the database is shared.
	const scheduleID = "a2060000-0000-4000-8000-0000000005c1"
	const runA, runB, runQ = "a2060000-0000-4000-8000-0000000005a1", "a2060000-0000-4000-8000-0000000005a2", "a2060000-0000-4000-8000-0000000005a3"
	due := time.Date(2019, 3, 1, 0, 0, 0, 0, time.UTC)
	apply := func(fn func(tx pgx.Tx) error) error { return s.WithTenant(ctx, tenantA, fn) }
	if err := apply(func(tx pgx.Tx) error {
		return s.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, store.ComplianceReportSchedule{
			ID: scheduleID, TenantID: tenantA, Framework: "soc2", Name: "a206 retention pack",
			ReportType: "framework_evidence_pack", IntervalSeconds: 3600, Enabled: true, Delivery: "audit_export",
			NextRunAt: due, CreatedAt: due.Add(-time.Hour), UpdatedAt: due.Add(-time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{runA, runB, runQ} {
		edge := due.Add(time.Duration(i) * time.Hour)
		queued := store.ComplianceReportRun{
			ID: id, TenantID: tenantA, ScheduleID: scheduleID, DueAt: edge, Framework: "soc2",
			ReportType: "framework_evidence_pack", Status: "queued", EventSequence: 1, CreatedAt: edge, UpdatedAt: edge,
		}
		steps := []store.ComplianceReportRun{queued}
		if id != runQ {
			completed := queued
			completed.Status, completed.Attempt, completed.EventSequence = "completed", 1, 2
			completed.CompletedAt, completed.UpdatedAt = edge.Add(time.Minute), edge.Add(time.Minute)
			completed.ArtifactDigest = crypto.SHA256Hex([]byte(`{"run":"` + id + `"}`))
			completed.ArtifactRef = reportArtifactRef(completed)
			steps = append(steps, completed)
		}
		for _, step := range steps {
			if err := apply(func(tx pgx.Tx) error { return s.ApplyComplianceReportRunTx(ctx, tx, step) }); err != nil {
				t.Fatalf("seed run %s: %v", id, err)
			}
		}
	}
	cutoff := due.Add(30 * 24 * time.Hour)
	pastRetention := func() []string {
		t.Helper()
		runs, err := s.ComplianceReportRunsPastRetention(ctx, tenantA, cutoff, cutoff, 100)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, run := range runs {
			if run.ScheduleID == scheduleID {
				ids = append(ids, run.ID)
			}
		}
		return ids
	}
	retention := func(id string) store.ComplianceReportRetention {
		t.Helper()
		run, err := s.GetComplianceReportRun(ctx, tenantA, id)
		if err != nil {
			t.Fatal(err)
		}
		return run.Retention
	}
	hold := func(id string, held bool, sequence uint64) error {
		return apply(func(tx pgx.Tx) error {
			return s.ApplyComplianceReportLegalHoldTx(ctx, tx, tenantA, id, held, "litigation hold 2019-7", "auditor@example.test", due.Add(40*24*time.Hour), sequence)
		})
	}
	request := func(id string, sequence uint64) error {
		return apply(func(tx pgx.Tx) error {
			return s.ApplyComplianceReportArtifactExpiryRequestedTx(ctx, tx, tenantA, id, due.Add(41*24*time.Hour), sequence, []byte(`{"run_id":"`+id+`"}`))
		})
	}
	expired := func(id string, sequence uint64) error {
		return apply(func(tx pgx.Tx) error {
			return s.ApplyComplianceReportArtifactExpiredTx(ctx, tx, tenantA, id, due.Add(42*24*time.Hour), sequence)
		})
	}
	queuedRows := func(id string) int {
		t.Helper()
		var n int
		if err := apply(func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key LIKE $3`,
				tenantA, store.ComplianceReportArtifactExpiryDestination, "report-expiry:"+id+":%").Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if got := pastRetention(); len(got) != 2 || got[0] != runA || got[1] != runB {
		t.Fatalf("past retention = %v, want the two completed runs oldest first", got)
	}
	if err := hold(runA, true, 100); err != nil {
		t.Fatal(err)
	}
	if r := retention(runA); !r.Held() || r.LegalHoldReason != "litigation hold 2019-7" || r.LegalHoldBy != "auditor@example.test" || r.EventSequence != 100 {
		t.Fatalf("held run reads %+v", r)
	}
	if err := hold(runA, true, 100); err != nil {
		t.Fatalf("a replayed hold = %v", err)
	}
	if err := hold(runA, true, 101); !errors.Is(err, store.ErrComplianceReportRetentionState) {
		t.Fatalf("a second hold = %v", err)
	}
	if err := hold(runQ, true, 102); !errors.Is(err, store.ErrComplianceReportRetentionState) {
		t.Fatalf("a hold on an unfinished run = %v", err)
	}
	if err := hold(runB, false, 102); !errors.Is(err, store.ErrComplianceReportRetentionState) {
		t.Fatalf("a release of an unheld run = %v", err)
	}
	if got := pastRetention(); len(got) != 1 || got[0] != runB {
		t.Fatalf("past retention with A held = %v", got)
	}

	// A request marks the run and queues one row; a replay queues nothing.
	for i := 0; i < 2; i++ {
		if err := request(runB, 103); err != nil {
			t.Fatal(err)
		}
	}
	if r := retention(runB); r.ExpiryRequestedAt == nil || queuedRows(runB) != 1 {
		t.Fatalf("queued removal reads %+v with %d rows", r, queuedRows(runB))
	}
	if got := pastRetention(); len(got) != 0 {
		t.Fatalf("past retention with B queued = %v", got)
	}
	// A hold cancels the queued removal; a release returns the run to the
	// retention, and its next request queues a row of its own.
	if err := hold(runB, true, 104); err != nil {
		t.Fatal(err)
	}
	if r := retention(runB); r.ExpiryRequestedAt != nil {
		t.Fatalf("a hold kept the queued removal: %+v", r)
	}
	if err := request(runB, 105); err != nil || queuedRows(runB) != 1 {
		t.Fatalf("a request for a held run = %v with %d rows", err, queuedRows(runB))
	}
	if err := hold(runB, false, 106); err != nil {
		t.Fatal(err)
	}
	if got := pastRetention(); len(got) != 1 || got[0] != runB {
		t.Fatalf("past retention after the release = %v", got)
	}
	if err := request(runB, 107); err != nil || queuedRows(runB) != 2 {
		t.Fatalf("the request after the release = %v with %d rows", err, queuedRows(runB))
	}

	// The confirmed removal: the run reads expired, cannot be held, and leaves
	// the retention and backup listings; a replay is a no-op.
	if err := expired(runB, 108); err != nil {
		t.Fatal(err)
	}
	if err := expired(runB, 108); err != nil {
		t.Fatalf("a replayed removal = %v", err)
	}
	if r := retention(runB); r.ArtifactExpiredAt == nil || r.EventSequence != 108 {
		t.Fatalf("expired run reads %+v", r)
	}
	if err := hold(runB, true, 109); !errors.Is(err, store.ErrComplianceReportRetentionState) {
		t.Fatalf("a hold on an expired run = %v", err)
	}
	artifacts, err := s.ListCompletedComplianceReportArtifacts(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range artifacts {
		if a.RunID == runB {
			t.Fatal("the backup listing still carries the expired run")
		}
	}
	// A removal of a held run is refused.
	if err := expired(runA, 110); !errors.Is(err, store.ErrComplianceReportRetentionState) {
		t.Fatalf("a removal of a held run = %v", err)
	}
	if err := hold(runA, false, 111); err != nil {
		t.Fatal(err)
	}
	if r := retention(runA); r.Held() || r.LegalHoldReason != "" || r.LegalHoldBy != "" {
		t.Fatalf("released run reads %+v", r)
	}

	// Tenant B sees none of it.
	if runs, err := s.ComplianceReportRunsPastRetention(ctx, tenantB, cutoff, cutoff, 100); err != nil || len(runs) != 0 {
		t.Fatalf("tenant B's retention listing = %+v %v", runs, err)
	}
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return s.ApplyComplianceReportLegalHoldTx(ctx, tx, tenantB, runA, true, "cross-tenant", "x", cutoff, 200)
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a cross-tenant hold = %v", err)
	}
	if _, err := s.ComplianceReportRunsPastRetention(ctx, tenantA, cutoff, cutoff, 0); err == nil {
		t.Fatal("a zero listing limit was accepted")
	}
}

// A208: a removal the archive's Object Lock refused leaves the run waiting:
// its queued removal is cleared and the retention listing skips it until the
// lock's end, then lists it again.
func TestComplianceReportStorageLockDefersTheRetention(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	const scheduleID, runID = "a2080000-0000-4000-8000-0000000005c1", "a2080000-0000-4000-8000-0000000005a1"
	due := time.Date(2019, 5, 1, 0, 0, 0, 0, time.UTC)
	apply := func(fn func(tx pgx.Tx) error) error { return s.WithTenant(ctx, tenantA, fn) }
	if err := apply(func(tx pgx.Tx) error {
		return s.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, store.ComplianceReportSchedule{
			ID: scheduleID, TenantID: tenantA, Framework: "soc2", Name: "a208 lock pack",
			ReportType: "framework_evidence_pack", IntervalSeconds: 3600, Enabled: true, Delivery: "audit_export",
			NextRunAt: due, CreatedAt: due.Add(-time.Hour), UpdatedAt: due.Add(-time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}
	queued := store.ComplianceReportRun{ID: runID, TenantID: tenantA, ScheduleID: scheduleID, DueAt: due, Framework: "soc2",
		ReportType: "framework_evidence_pack", Status: "queued", EventSequence: 1, CreatedAt: due, UpdatedAt: due}
	completed := queued
	completed.Status, completed.Attempt, completed.EventSequence = "completed", 1, 2
	completed.CompletedAt, completed.UpdatedAt = due.Add(time.Minute), due.Add(time.Minute)
	completed.ArtifactDigest = crypto.SHA256Hex([]byte(`{"run":"a208"}`))
	completed.ArtifactRef = reportArtifactRef(completed)
	for _, step := range []store.ComplianceReportRun{queued, completed} {
		if err := apply(func(tx pgx.Tx) error { return s.ApplyComplianceReportRunTx(ctx, tx, step) }); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := due.Add(30 * 24 * time.Hour)
	listed := func(now time.Time) bool {
		t.Helper()
		runs, err := s.ComplianceReportRunsPastRetention(ctx, tenantA, cutoff, now, 100)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(runs, func(r store.ComplianceReportRun) bool { return r.ID == runID })
	}
	if err := apply(func(tx pgx.Tx) error {
		return s.ApplyComplianceReportArtifactExpiryRequestedTx(ctx, tx, tenantA, runID, cutoff, 208001, []byte(`{"run_id":"`+runID+`"}`))
	}); err != nil {
		t.Fatal(err)
	}
	lockedUntil := cutoff.Add(48 * time.Hour)
	for i := 0; i < 2; i++ { // the second is a replay
		if err := apply(func(tx pgx.Tx) error {
			return s.ApplyComplianceReportArtifactExpiryDeferredTx(ctx, tx, tenantA, runID, lockedUntil, 208002)
		}); err != nil {
			t.Fatal(err)
		}
	}
	run, err := s.GetComplianceReportRun(ctx, tenantA, runID)
	if err != nil || run.Retention.ExpiryRequestedAt != nil || run.Retention.StorageLockedUntil == nil ||
		!run.Retention.StorageLockedUntil.Equal(lockedUntil) || run.Retention.ArtifactExpiredAt != nil {
		t.Fatalf("deferred run reads %+v %v", run.Retention, err)
	}
	if listed(cutoff) || listed(lockedUntil.Add(-time.Second)) {
		t.Fatal("the retention listed a run its storage lock still protects")
	}
	if !listed(lockedUntil) {
		t.Fatal("the retention did not list the run once its storage lock ended")
	}
}
