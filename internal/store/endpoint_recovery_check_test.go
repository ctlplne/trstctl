// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A210: a target's recovery check projects per tenant. A newer request
// replaces the row and clears the old answer; an answer lands only on the
// request it answers; a replayed event changes nothing; tenant B sees none of
// it.
func TestEndpointRecoveryChecksProjectPerTenant(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	const target = "21021021-0210-4210-8210-2100000000a1"
	const agent = "21021021-0210-4210-8210-2100000000b1"
	const first, second = "21021021-0210-4210-8210-2100000000c1", "21021021-0210-4210-8210-2100000000c2"
	at := time.Date(2026, 10, 28, 3, 0, 0, 0, time.UTC)
	apply := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, fn); err != nil {
			t.Fatal(err)
		}
	}
	request := func(checkID string, sequence uint64, offset time.Duration) {
		apply(func(tx pgx.Tx) error {
			return s.ApplyEndpointRecoveryCheckRequestedTx(ctx, tx, store.EndpointRecoveryCheck{
				TenantID: tenantA, TargetID: target, CheckID: checkID, TargetRevision: "revision-1", AgentID: agent,
				RequestedBy: "operator@example.test", RequestedAt: at.Add(offset), EventSequence: sequence,
			})
		})
	}
	answer := func(checkID, recovery string, sequence uint64, jobID int64) {
		checked := at.Add(time.Duration(jobID) * time.Second)
		apply(func(tx pgx.Tx) error {
			return s.ApplyEndpointRecoveryCheckAnsweredTx(ctx, tx, store.EndpointRecoveryCheck{
				TenantID: tenantA, TargetID: target, CheckID: checkID, Status: store.EndpointRecoveryCheckChecked,
				Recovery: recovery, RecoveryAction: "nginx", ExecutableSHA256: "ab", ArgvSHA256: "cd",
				Listener: "stopped", JobID: &jobID, EvidenceDigest: "digest", CheckedAt: &checked, EventSequence: sequence,
			})
		})
	}
	read := func() store.EndpointRecoveryCheck {
		t.Helper()
		c, found, err := s.GetEndpointRecoveryCheck(ctx, tenantA, target)
		if err != nil || !found {
			t.Fatalf("read check: found=%v err=%v", found, err)
		}
		return c
	}

	request(first, 1001, time.Second)
	if c := read(); c.Status != store.EndpointRecoveryCheckQueued || c.CheckID != first || c.RequestSequence != 1001 || c.CheckedAt != nil {
		t.Fatalf("queued check = %+v", c)
	}
	answer(first, "pinned", 1002, 1002)
	if c := read(); c.Status != store.EndpointRecoveryCheckChecked || c.Recovery != "pinned" || c.JobID == nil || *c.JobID != 1002 {
		t.Fatalf("answered check = %+v", c)
	}
	request(first, 1001, time.Second) // a replayed request does not reopen the answer
	if c := read(); c.Status != store.EndpointRecoveryCheckChecked {
		t.Fatalf("a replayed request reopened the check: %+v", c)
	}
	request(second, 1003, 3*time.Second)
	if c := read(); c.Status != store.EndpointRecoveryCheckQueued || c.CheckID != second || c.Recovery != "" || c.JobID != nil {
		t.Fatalf("a newer request kept the old answer: %+v", c)
	}
	answer(first, "no_recovery_action", 1004, 1004) // the replaced request's late answer
	if c := read(); c.Status != store.EndpointRecoveryCheckQueued || c.CheckID != second {
		t.Fatalf("a replaced request's answer landed: %+v", c)
	}
	apply(func(tx pgx.Tx) error {
		return s.ApplyEndpointRecoveryCheckAnsweredTx(ctx, tx, store.EndpointRecoveryCheck{
			TenantID: tenantA, TargetID: target, CheckID: second, Status: store.EndpointRecoveryCheckFailed,
			Failure: "the host could not probe the listener", EventSequence: 1005,
		})
	})
	if c := read(); c.Status != store.EndpointRecoveryCheckFailed || c.Failure == "" {
		t.Fatalf("failed check = %+v", c)
	}
	if _, found, err := s.GetEndpointRecoveryCheck(ctx, tenantB, target); err != nil || found {
		t.Fatalf("tenant B read tenant A's check: found=%v err=%v", found, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyEndpointRecoveryCheckAnsweredTx(ctx, tx, store.EndpointRecoveryCheck{
			TenantID: tenantA, TargetID: target, CheckID: second, Status: store.EndpointRecoveryCheckQueued, EventSequence: 1006,
		})
	}); err == nil {
		t.Fatal("an answer that is neither checked nor failed was accepted")
	}
}
