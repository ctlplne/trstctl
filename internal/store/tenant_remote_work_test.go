// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/store"
)

func TestTenantRemoteWorkSurvivesLeaseExpiryAndRetention(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	seedJobs(t, ctx, s, tenantA, 1, jobDeploy)
	const agentID = "daab3ddd-5a10-4440-8cfe-299c0d81b665"
	now := time.Now().UTC()
	claim := func(at time.Time) store.AgentJob {
		t.Helper()
		jobs, err := s.ClaimAgentJobs(ctx, tenantA, agentID, []string{jobDeploy}, nil, 1, time.Minute, at)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("claim=%d err=%v", len(jobs), err)
		}
		return jobs[0]
	}
	assertBusy := func() {
		t.Helper()
		if err := s.RequireTenantAgentWorkQuiescent(ctx, tenantA); !errors.Is(err, store.ErrTenantServiceBusy) {
			t.Fatalf("unresolved claim admitted: %v", err)
		}
		if err := s.RequireTenantAgentWorkQuiescent(ctx, tenantB); err != nil {
			t.Fatalf("another tenant blocked: %v", err)
		}
	}
	first := claim(now)
	assertBusy()
	later := now.Add(2 * time.Minute)
	if n, err := s.ReclaimExpiredAgentJobs(ctx, later); err != nil || n != 1 {
		t.Fatalf("reclaim=%d err=%v", n, err)
	}
	assertBusy()
	second := claim(later)
	if second.ID != first.ID || second.ClaimAttempts != 2 {
		t.Fatal("test did not create a second generation")
	}
	// Synthetic receiver rows isolate retention/admission semantics here; the
	// served test separately verifies signatures and ownership over real mTLS.
	receipt := func(attempt int, state, outcome string) {
		t.Helper()
		if err := s.RecordAgentJobReceipt(ctx, tenantA, store.AgentJobReceipt{JobID: first.ID, Attempt: attempt, State: state, Outcome: outcome,
			Statement: "fixture statement", Signature: "fixture signature", SignerFingerprint: "fixture fingerprint"}); err != nil {
			t.Fatal(err)
		}
	}
	receipt(2, store.AgentJobReceiptVerified, "executed")
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='delivered',delivered_at=$3,claim_completed_at=$3 WHERE tenant_id=$1 AND id=$2`, tenantA, first.ID, now.Add(-72*time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	assertBusy()
	sweep := outboxgc.New(s, 24*time.Hour)
	assertRetained := func() {
		t.Helper()
		if n, err := sweep.Sweep(ctx); err != nil || n != 0 {
			t.Fatalf("unresolved history purged: %d %v", n, err)
		}
		assertBusy()
	}
	assertRetained()
	receipt(1, store.AgentJobReceiptRejected, "executed")
	assertRetained()
	receipt(1, store.AgentJobReceiptVerified, "extend")
	assertRetained()
	receipt(3, store.AgentJobReceiptVerified, "executed")
	assertRetained()
	receipt(1, store.AgentJobReceiptVerified, "failed")
	if err := s.RequireTenantAgentWorkQuiescent(ctx, tenantA); err != nil {
		t.Fatalf("all generations ended: %v", err)
	}
	if n, err := sweep.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("terminal history not reclaimed: %d %v", n, err)
	}
}
