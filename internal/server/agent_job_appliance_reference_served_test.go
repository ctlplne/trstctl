// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
)

// A122 (owner decision 2026-10-26): an agent records an appliance's own
// reference for the key request its attempt made (Cisco ISE's CSR ID) over the
// agent channel, and every later claim of the job carries it back, so a retry
// reuses the request instead of leaving an orphan. A stale attempt cannot
// record, and an empty reference is refused.
func TestServedAgentJobCarriesItsApplianceReferenceAcrossClaims(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:appliance-reference")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1, LeaseSeconds: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim = %d (err %v)", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	if job.ApplianceReference != "" {
		t.Fatalf("a first claim carries reference %q", job.ApplianceReference)
	}
	recorded, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: job.JobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeRecordReference, ApplianceReference: "ise-csr-7f3a",
	})
	if err != nil || !recorded.Accepted {
		t.Fatalf("record reference = %+v, %v", recorded, err)
	}
	if _, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: job.JobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeRecordReference,
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an empty reference = %v, want InvalidArgument", err)
	}

	if freed, err := h.store.ReclaimExpiredAgentJobs(ctx, time.Now().UTC().Add(time.Minute)); err != nil || freed != 1 {
		t.Fatalf("reclaim = %d, %v", freed, err)
	}
	again, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(again.Jobs) != 1 {
		t.Fatalf("reclaim claim = %d (err %v)", len(again.Jobs), err)
	}
	if again.Jobs[0].ApplianceReference != "ise-csr-7f3a" || again.Jobs[0].Attempt <= job.Attempt {
		t.Fatalf("the reclaimed job = %+v, want the recorded reference on a later attempt", again.Jobs[0])
	}
	stale, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: job.JobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeRecordReference, ApplianceReference: "ise-csr-stale",
	})
	if err != nil || stale.Accepted {
		t.Fatalf("a stale attempt's record = %+v, %v; want refused", stale, err)
	}
}
