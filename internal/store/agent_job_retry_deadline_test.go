// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestAgentJobClaimHonorsRetryDeadline(t *testing.T) {
	ctx := t.Context()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	seedJobs(t, ctx, st, tenantID, 1, jobDeploy)
	now := time.Now().UTC()
	due := now.Add(time.Minute)
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET agent_next_attempt_at=$2 WHERE tenant_id=$1 AND destination=$3`, tenantID, due, jobDeploy)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	const agentID = "55555555-5555-5555-5555-555555555555"
	before, err := st.ClaimAgentJobs(ctx, tenantID, agentID, []string{jobDeploy}, nil, 1, time.Minute, now)
	if err != nil || len(before) != 0 {
		t.Fatalf("job was claimed before its retry deadline: jobs=%d err=%v", len(before), err)
	}
	after, err := st.ClaimAgentJobs(ctx, tenantID, agentID, []string{jobDeploy}, nil, 1, time.Minute, due.Add(time.Millisecond))
	if err != nil || len(after) != 1 {
		t.Fatalf("due job was not claimable: jobs=%d err=%v", len(after), err)
	}
}

func TestAgentFailureBackoffIsIndependentAndBounded(t *testing.T) {
	ctx := t.Context()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	seedJobs(t, ctx, st, tenantID, 1, jobDeploy)
	const agentID = "55555555-5555-5555-5555-555555555555"
	now := time.Now().UTC()
	// The dispatcher's independent deferral must not prevent first host work.
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET next_attempt_at=$2 WHERE tenant_id=$1`, tenantID, now.Add(time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var previous store.AgentJob
	for attempt := 1; attempt <= 8; attempt++ {
		jobs, err := st.ClaimAgentJobs(ctx, tenantID, agentID, []string{jobDeploy}, nil, 1, time.Minute, now)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("claim %d: jobs=%d err=%v", attempt, len(jobs), err)
		}
		job := jobs[0]
		if previous.ID != 0 {
			if ok, err := st.ReleaseAgentJob(ctx, tenantID, agentID, previous.ID, previous.ClaimAttempts, "late failure", now); err != nil || ok {
				t.Fatalf("late report released newer generation: accepted=%v err=%v", ok, err)
			}
		}
		if ok, err := st.ReleaseAgentJob(ctx, tenantID, agentID, job.ID, job.ClaimAttempts, "failed", now); err != nil || !ok {
			t.Fatalf("release %d: accepted=%v err=%v", attempt, ok, err)
		}
		var deadline time.Time
		if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT agent_next_attempt_at FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantID, job.ID).Scan(&deadline)
		}); err != nil {
			t.Fatal(err)
		}
		ceiling := min(60*time.Second, 5*time.Second<<(attempt-1))
		if delay := deadline.Sub(now); delay < ceiling/2 || delay > ceiling {
			t.Fatalf("attempt %d delay=%s outside %s..%s", attempt, delay, ceiling/2, ceiling)
		}
		if early, err := st.ClaimAgentJobs(ctx, tenantID, agentID, []string{jobDeploy}, nil, 1, time.Minute, deadline.Add(-time.Millisecond)); err != nil || len(early) != 0 {
			t.Fatalf("claimed before deadline: jobs=%d err=%v", len(early), err)
		}
		previous, now = job, deadline.Add(time.Millisecond)
	}
}
