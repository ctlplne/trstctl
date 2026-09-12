// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestOutboxExplicitRetryGrantSurvivesWorkerCrashWithoutAnotherClaim(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	box := orchestrator.NewOutbox(s, orchestrator.WithMaxAttempts(10), orchestrator.WithWorkerID("replacement-worker"))
	for _, tc := range []struct {
		name, initial, final   string
		expired                bool
		limit, calls, attempts int
	}{
		{"expired consumed grant", "processing", "failed", true, 2, 0, 2},
		{"pending consumed grant", "pending", "failed", true, 2, 0, 2},
		{"unused grant", "processing", "delivered", true, 3, 1, 3},
		{"live lease", "processing", "processing", false, 2, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := enqueue(t, s, box, orchestrator.Entry{TenantID: tenantA, Destination: "ca.issue", IdempotencyKey: tc.name, Payload: []byte(`{}`)})
			// Exact test row models a claimed worker dying before finalization.
			_, err := s.SystemPool().Exec(ctx, `UPDATE outbox SET status=$3,attempts=2,retry_attempt_limit=$4,
				worker_id='lost-worker',lease_until=now()+CASE WHEN $5 THEN interval '-1 second' ELSE interval '1 hour' END
				WHERE tenant_id=$1 AND id=$2`, tenantA, id, tc.initial, tc.limit, tc.expired)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			_, err = box.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { calls++; return nil }), orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
			if err != nil {
				t.Fatal(err)
			}
			record, err := box.Get(ctx, tenantA, id)
			if err != nil || calls != tc.calls || record.Status != tc.final || record.Attempts != tc.attempts {
				t.Fatalf("calls=%d record=%+v err=%v, want %d calls %s/%d", calls, record, err, tc.calls, tc.final, tc.attempts)
			}
		})
	}
}
