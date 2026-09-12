// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestOutboxDispatcherPreservesLiveAgentClaims(t *testing.T) {
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	ob := orchestrator.NewOutbox(s)
	enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "endpoint.renew", IdempotencyKey: "held-host-issuance", Payload: []byte(`{}`), RequiredAgentRole: "host"})
	ctx := t.Context()
	const agentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	jobs, err := s.ClaimAgentJobs(ctx, tenantA, agentID, []string{"endpoint.renew"}, []string{"host"}, 1, time.Minute, time.Now().UTC())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("host claim: jobs=%d err=%v", len(jobs), err)
	}
	processed, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return orchestrator.DeferDelivery(errors.New("host agent owns this job"))
	}))
	if err != nil || processed != 0 {
		t.Fatalf("dispatcher took host-held job: processed=%d err=%v", processed, err)
	}
	if _, held, err := s.GetAgentJobForRedemption(ctx, tenantA, agentID, jobs[0].ID, time.Now().UTC()); err != nil || !held {
		t.Fatalf("dispatcher invalidated the live host claim: held=%v err=%v", held, err)
	}
}
