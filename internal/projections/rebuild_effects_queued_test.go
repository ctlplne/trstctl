// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestRebuildPastOutboxRetentionQueuesNoEffectAgainA237L4L1: a decoy's
// trigger alert, a secret decoy's first-read alert, a decoy's watch-gap
// warning and a report's removal are queued once, when their events are first
// projected. The rows are delivered and, a day later, reclaimed by the outbox
// sweep. A full rebuild then re-derives the decoys and the run from the log
// and queues none of them again, while a trigger the deployment had not yet
// projected still alerts when the rebuild reaches it. A second rebuild with
// the rows still queued adds no duplicate, and a live projection after the
// rebuilds alerts as before.
func TestRebuildPastOutboxRetentionQueuesNoEffectAgainA237L4L1(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	at := time.Now().UTC().Truncate(time.Second)
	appendJSON := func(typ string, v any) {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{Type: typ, TenantID: tenantA, Time: at, Data: data})
	}
	const (
		apiDecoy   = "a2374101-0000-4000-8000-000000000001"
		readDecoy  = "a2374101-0000-4000-8000-000000000002"
		gapDecoy   = "a2374101-0000-4000-8000-000000000003"
		lateDecoy  = "a2374101-0000-4000-8000-000000000004"
		liveDecoy  = "a2374101-0000-4000-8000-000000000005"
		scheduleID = "a2374101-0000-4000-8000-0000000000a1"
		runID      = "a2374101-0000-4000-8000-0000000000b1"
	)
	decoy := func(id, secret string) {
		t.Helper()
		appendJSON(projections.EventHoneyTokenCreated, projections.HoneyTokenCreated{
			ID: id, Name: "a237l4l1 decoy " + id[len(id)-1:], Placement: "a237l4l1 placement",
			TokenHash: crypto.SHA256Hex([]byte("a237l4l1 bearer " + id)), SecretName: secret,
		})
	}
	trigger := func(id, reader string) {
		t.Helper()
		appendJSON(projections.EventHoneyTokenTriggered, projections.HoneyTokenTriggered{
			ID: id, Method: "GET", Path: "/api/v1/a237l4l1", Reader: reader,
		})
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("A237L4L1")})
	decoy(apiDecoy, "")
	trigger(apiDecoy, "")
	decoy(readDecoy, "a237l4l1/payments/db-password")
	trigger(readDecoy, "a237l4l1-reader")
	decoy(gapDecoy, "")
	appendJSON(projections.EventHoneyTokenWatchGapOpened, projections.HoneyTokenWatchGapOpened{
		ID: gapDecoy, Reason: "a237l4l1: the watcher cannot read the decoy login", Since: at.Add(-time.Minute),
	})
	appendJSON(projections.EventComplianceReportScheduleUpserted, projections.ComplianceReportScheduleUpserted{
		ID: scheduleID, Framework: "soc2", Name: "a237l4l1 pack", ReportType: "framework_evidence_pack",
		IntervalSeconds: 3600, Enabled: true, Delivery: "audit_export",
	})
	digest := crypto.SHA256Hex([]byte(`{"signed_export":{"signature":"a237l4l1"}}`))
	appendJSON(projections.EventComplianceReportRunRecorded, projections.ComplianceReportRunRecorded{
		ID: runID, ScheduleID: scheduleID, DueAt: at.Add(-48 * time.Hour), Framework: "soc2",
		ReportType: "framework_evidence_pack", Status: "completed", Attempt: 1,
		ArtifactRef:    "reports/" + tenantA + "/" + runID + "/" + digest + ".json",
		ArtifactDigest: digest, CompletedAt: at.Add(-47 * time.Hour), CreatedAt: at.Add(-48 * time.Hour),
	})
	appendJSON(projections.EventComplianceReportArtifactExpiryRequested, projections.ComplianceReportArtifactExpiry{
		RunID: runID, Digest: digest, RetentionSeconds: 86400,
	})

	effects := []string{"notification.honeytoken", store.ComplianceReportArtifactExpiryDestination}
	queued := func() []string {
		t.Helper()
		rows, err := s.SystemPool().Query(ctx,
			`SELECT destination || ' ' || idempotency_key FROM outbox
			  WHERE tenant_id = $1 AND destination = ANY($2) ORDER BY id`, tenantA, effects)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var row string
			if err := rows.Scan(&row); err != nil {
				t.Fatal(err)
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(out)
		return out
	}
	hasPrefixes := func(got []string, prefixes ...string) bool {
		if len(got) != len(prefixes) {
			return false
		}
		for _, prefix := range prefixes {
			found := false
			for _, row := range got {
				found = found || strings.HasPrefix(row, prefix)
			}
			if !found {
				return false
			}
		}
		return true
	}
	firstEffects := []string{
		"notification.honeytoken honeytoken.triggered:" + apiDecoy,
		"notification.honeytoken honeytoken.secret_read:" + readDecoy + ":",
		"notification.honeytoken honeytoken.watch_gap:" + gapDecoy + ":",
		store.ComplianceReportArtifactExpiryDestination + " report-expiry:" + runID + ":",
	}

	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if got := queued(); !hasPrefixes(got, firstEffects...) {
		t.Fatalf("first projection queued %q, want one row each of %q", got, firstEffects)
	}

	// Delivered, then reclaimed by the sweep a day later.
	tag, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET status = 'delivered', delivered_at = now() - interval '25 hours'
		  WHERE tenant_id = $1 AND destination = ANY($2)`, tenantA, effects)
	if err != nil || tag.RowsAffected() != int64(len(firstEffects)) {
		t.Fatalf("mark delivered: %v (%d rows)", err, tag.RowsAffected())
	}
	if reclaimed, err := outboxgc.New(s, outboxgc.DefaultRetention).Sweep(ctx); err != nil || reclaimed < int64(len(firstEffects)) {
		t.Fatalf("sweep reclaimed %d rows: %v", reclaimed, err)
	}
	if got := queued(); len(got) != 0 {
		t.Fatalf("after the sweep the outbox still holds %q", got)
	}

	// A trigger appended but not yet projected when the rebuild starts.
	decoy(lateDecoy, "")
	trigger(lateDecoy, "")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	lateAlert := "notification.honeytoken honeytoken.triggered:" + lateDecoy
	if got := queued(); len(got) != 1 || got[0] != lateAlert {
		t.Fatalf("the rebuild queued %q, want only the unprojected trigger's alert %q", got, lateAlert)
	}
	// The rebuild still re-derives what the events say.
	var triggered, gapOpen int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE state = 'triggered'), count(*) FILTER (WHERE watch_gap_since IS NOT NULL)
		   FROM honey_tokens WHERE tenant_id = $1 AND id = ANY($2)`,
		tenantA, []string{apiDecoy, readDecoy, gapDecoy, lateDecoy}).Scan(&triggered, &gapOpen); err != nil {
		t.Fatal(err)
	}
	var readers int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM honey_token_readers WHERE tenant_id = $1 AND honey_token_id = $2`,
		tenantA, readDecoy).Scan(&readers); err != nil {
		t.Fatal(err)
	}
	var removalRequested bool
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT artifact_expiry_requested_at IS NOT NULL FROM compliance_report_runs WHERE tenant_id = $1 AND id = $2`,
		tenantA, runID).Scan(&removalRequested); err != nil {
		t.Fatal(err)
	}
	if triggered != 3 || gapOpen != 1 || readers != 1 || !removalRequested {
		t.Fatalf("rebuilt read model: triggered=%d gap=%d readers=%d removal requested=%v, want 3, 1, 1, true",
			triggered, gapOpen, readers, removalRequested)
	}

	// A second rebuild, with the late alert still queued, adds no duplicate;
	// a live trigger after it alerts once.
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("second rebuild: %v", err)
	}
	if got := queued(); len(got) != 1 || got[0] != lateAlert {
		t.Fatalf("a second rebuild changed the queue to %q", got)
	}
	decoy(liveDecoy, "")
	trigger(liveDecoy, "")
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	liveAlert := "notification.honeytoken honeytoken.triggered:" + liveDecoy
	if got := queued(); len(got) != 2 || got[0] != lateAlert || got[1] != liveAlert {
		t.Fatalf("after a live trigger the queue = %q, want %q and %q", got, lateAlert, liveAlert)
	}
	t.Logf("A237L4L1_OK reclaimed=%d late=%s live=%s", len(firstEffects), lateDecoy, liveDecoy)
}
