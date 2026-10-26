// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A122: an appliance's reference for a job's key request (ISE's CSR ID) is
// recorded only by the agent holding the job at that attempt, read back for
// any later attempt, and replaced when a later attempt had to make a new
// request.
func TestAgentJobApplianceReferenceFollowsTheHeldClaim(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	const holder = "71220000-0000-4000-8000-000000000001"
	const other = "71220000-0000-4000-8000-000000000002"
	seedJobs(t, ctx, st, tenantID, 1, jobDeploy)
	now := time.Now().UTC()
	claimed, err := st.ClaimAgentJobs(ctx, tenantID, holder, []string{jobDeploy}, nil, 1, time.Minute, now)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim = %d, %v", len(claimed), err)
	}
	job := claimed[0]
	if ref, err := st.AgentJobApplianceReference(ctx, tenantID, job.ID); err != nil || ref != "" {
		t.Fatalf("a job's reference before any = %q, %v", ref, err)
	}
	if ok, err := st.RecordAgentJobApplianceReference(ctx, tenantID, other, job.ID, job.ClaimAttempts, "csr-other", now); err != nil || ok {
		t.Fatalf("an agent not holding the job recorded = %v, %v", ok, err)
	}
	if ok, err := st.RecordAgentJobApplianceReference(ctx, tenantID, holder, job.ID, job.ClaimAttempts+1, "csr-future", now); err != nil || ok {
		t.Fatalf("a future attempt recorded = %v, %v", ok, err)
	}
	if ok, err := st.RecordAgentJobApplianceReference(ctx, tenantID, holder, job.ID, job.ClaimAttempts, "csr-1", now); err != nil || !ok {
		t.Fatalf("the holder's record = %v, %v", ok, err)
	}
	if ref, err := st.AgentJobApplianceReference(ctx, tenantID, job.ID); err != nil || ref != "csr-1" {
		t.Fatalf("the recorded reference = %q, %v", ref, err)
	}
	if ok, err := st.RecordAgentJobApplianceReference(ctx, tenantID, holder, job.ID, job.ClaimAttempts, "csr-2", now); err != nil || !ok {
		t.Fatalf("a replacement = %v, %v", ok, err)
	}
	if ref, _ := st.AgentJobApplianceReference(ctx, tenantID, job.ID); ref != "csr-2" {
		t.Fatalf("the replaced reference = %q", ref)
	}
	if ref, err := st.AgentJobApplianceReference(ctx, tenantB, job.ID); err != nil || ref != "" {
		t.Fatalf("another tenant reads %q, %v", ref, err)
	}
	if _, err := st.RecordAgentJobApplianceReference(ctx, tenantID, holder, job.ID, job.ClaimAttempts, strings.Repeat("x", 257), now); err == nil {
		t.Fatal("an oversized reference was accepted")
	}
	if ok, err := st.RecordAgentJobApplianceReference(ctx, tenantID, holder, job.ID, job.ClaimAttempts, "csr-late", now.Add(2*time.Minute)); err != nil || ok {
		t.Fatalf("a record after the lease lapsed = %v, %v", ok, err)
	}
}
