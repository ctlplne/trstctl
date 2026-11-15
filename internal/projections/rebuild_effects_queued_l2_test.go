// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/projections"
)

// TestRebuildPastOutboxRetentionQueuesNoDiscoveryRiskAlertAgainA237L4L2: an
// urgent discovery finding queues one notification.risk alert when first
// projected. The row is delivered and, a day later, reclaimed by the sweep;
// a full rebuild re-derives the finding and queues no second alert (the
// finding's own read-model row, which kept a live replay from alerting
// twice, is rebuilt by the same replay). A finding appended but not yet
// projected when the rebuild starts still alerts once.
func TestRebuildPastOutboxRetentionQueuesNoDiscoveryRiskAlertAgainA237L4L2(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	appendAUD96DiscoveryBase(t, log)
	const (
		first = "a2374102-0000-4000-8000-000000000001"
		late  = "a2374102-0000-4000-8000-000000000002"
	)
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	finding := func(id, ref string, when time.Time) {
		t.Helper()
		mustAppend(t, log, events.Event{
			Type: projections.EventDiscoveryFindingRecorded, TenantID: tenantA, Time: when,
			Data: mustJSONAUD96(t, projections.DiscoveryFindingRecorded{
				ID: id, RunID: aud96RunID, SourceID: aud96SourceID,
				Kind: "x509_certificate", Ref: ref, Provenance: "manual:shadow-inventory",
				Fingerprint: "a237l4l2-" + id, RiskScore: 82, Metadata: json.RawMessage(`{"display_name":"` + ref + `"}`),
			}),
		})
	}
	finding(first, "shadow-ingress.a237l4l2.test:443", at)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	alerts := func() []string {
		t.Helper()
		rows, err := s.SystemPool().Query(ctx,
			`SELECT idempotency_key FROM outbox WHERE tenant_id = $1 AND destination = 'notification.risk' ORDER BY idempotency_key`, tenantA)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				t.Fatal(err)
			}
			out = append(out, key)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := alerts(); len(got) != 1 || got[0] != "urgent-risk:"+first {
		t.Fatalf("first projection queued %q, want the finding's one alert", got)
	}
	if tag, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET status = 'delivered', delivered_at = now() - interval '25 hours'
		  WHERE tenant_id = $1 AND destination = 'notification.risk'`, tenantA); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("mark delivered: %v (%d rows)", err, tag.RowsAffected())
	}
	if _, err := outboxgc.New(s, outboxgc.DefaultRetention).Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := alerts(); len(got) != 0 {
		t.Fatalf("after the sweep the outbox still holds %q", got)
	}
	finding(late, "shadow-egress.a237l4l2.test:443", at.Add(time.Minute))
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got := alerts(); len(got) != 1 || got[0] != "urgent-risk:"+late {
		t.Fatalf("the rebuild queued %q, want only the unprojected finding's alert", got)
	}
	if _, err := s.GetDiscoveryFinding(ctx, tenantA, first); err != nil {
		t.Fatalf("the rebuild lost the first finding: %v", err)
	}
	t.Logf("A237L4L2_OK late=%s", late)
}
