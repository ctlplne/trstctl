// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// issuanceApprovalAuthorityConsumer is the missing atomic consume seam pinned by
// AUD-77. Consumption must run in the caller's transaction so the approved
// authority and the operation it authorizes cannot be separated by a crash.
type issuanceApprovalAuthorityConsumer interface {
	ConsumeIssuanceApprovalTx(
		context.Context,
		pgx.Tx,
		string, // tenant ID
		string, // exact resource
		string, // exact action
		string, // bound requester
		int, // required distinct approvals
	) (store.IssuanceApproval, error)
}

// TestIssuanceApprovalAuthorityUnknownRequestCannotBeCreatedByReview proves that
// neither the read nor the review operation can manufacture the parent request it
// claims to evaluate. A genuine request must arrive through the request-opening
// path first.
func TestIssuanceApprovalAuthorityUnknownRequestCannotBeCreatedByReview(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	const resource, action = "identity/unknown", "revoke"

	if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, "alice", 1); err != nil || ok {
		t.Fatalf("count unknown request = (%v, %v), want (false, nil)", ok, err)
	}
	if _, err := s.GetIssuanceApproval(ctx, tenantA, resource, action); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("counting unknown request created authority: GetIssuanceApproval = %v, want ErrNoRows", err)
	}

	if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, "reviewer"); err == nil {
		t.Fatal("approval of an unknown request succeeded; review must never create its own authority")
	}
	if _, err := s.GetIssuanceApproval(ctx, tenantA, resource, action); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("approving unknown request created authority: GetIssuanceApproval = %v, want ErrNoRows", err)
	}
	if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, "alice", 1); err != nil || ok {
		t.Fatalf("unknown request gained authority after refused review = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestIssuanceApprovalAuthorityRequesterBindingCannotBeSwapped proves an approval
// opened for Alice cannot later authorize Mallory's otherwise-identical operation.
// The stored requester is authoritative; a caller-supplied replacement must fail
// closed instead of laundering old approvals into a new request.
func TestIssuanceApprovalAuthorityRequesterBindingCannotBeSwapped(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	const resource, action = "identity/requester-bound", "revoke"
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, "alice", 1); err != nil {
		t.Fatalf("open Alice's request: %v", err)
	}
	if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, "reviewer"); err != nil {
		t.Fatalf("approve Alice's request: %v", err)
	}

	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, "mallory", 1); !errors.Is(err, store.ErrIssuanceApprovalRequesterMismatch) {
		t.Fatalf("attempt requester swap = %v, want ErrIssuanceApprovalRequesterMismatch", err)
	}
	got, err := s.GetIssuanceApproval(ctx, tenantA, resource, action)
	if err != nil {
		t.Fatalf("get requester-bound authority: %v", err)
	}
	if got.Requester != "alice" {
		t.Fatalf("requester after reopen = %q, want the first binding %q", got.Requester, "alice")
	}

	if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, "mallory", 1); err != nil {
		t.Fatalf("check with swapped requester: %v", err)
	} else if ok {
		t.Fatal("Alice's approved request authorized Mallory; requester mismatch must fail closed")
	}
}

// TestIssuanceApprovalAuthorityExpiredOrSupersededCannotAuthorize proves quorum is
// only authority while its exact request is live. The status and expiry columns are
// deliberately exercised through PostgreSQL: they are durable authorization state,
// not process-local timers.
func TestIssuanceApprovalAuthorityExpiredOrSupersededCannotAuthorize(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(context.Context, *store.Store, string, string) error
	}{
		{
			name: "expired",
			apply: func(ctx context.Context, s *store.Store, resource, action string) error {
				return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx,
						`UPDATE issuance_approval_requests
						    SET expires_at = $4
						  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
						tenantA, resource, action, time.Now().UTC().Add(-time.Minute))
					return err
				})
			},
		},
		{
			name: "superseded",
			apply: func(ctx context.Context, s *store.Store, resource, action string) error {
				return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx,
						`UPDATE issuance_approval_requests
						    SET status = 'superseded'
						  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
						tenantA, resource, action)
					return err
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			seedTwoTenants(t, s)

			resource, action := "identity/"+tc.name, "revoke"
			if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, "alice", 1); err != nil {
				t.Fatalf("open request: %v", err)
			}
			if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, "reviewer"); err != nil {
				t.Fatalf("approve request: %v", err)
			}
			if err := tc.apply(ctx, s, resource, action); err != nil {
				t.Fatalf("persist %s authority state: %v", tc.name, err)
			}

			if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, "alice", 1); err != nil {
				t.Fatalf("check %s authority: %v", tc.name, err)
			} else if ok {
				t.Fatalf("%s request retained approval authority; only a live exact request may authorize", tc.name)
			}
		})
	}
}

// TestIssuanceApprovalAuthorityConsumptionIsSingleUse proves approval is a one-shot
// capability, not a standing permission for every future operation with the same
// resource/action tuple. The first consume succeeds atomically, the normal count
// predicate stops authorizing, and replayed consumption is refused.
func TestIssuanceApprovalAuthorityConsumptionIsSingleUse(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	consumer, ok := any(s).(issuanceApprovalAuthorityConsumer)
	if !ok {
		t.Fatal("store is missing atomic ConsumeIssuanceApprovalTx; approved authority is reusable forever")
	}

	const resource, action, requester = "identity/single-use", "revoke", "alice"
	if err := s.OpenIssuanceApprovalRequest(ctx, tenantA, resource, action, requester, 1); err != nil {
		t.Fatalf("open request: %v", err)
	}
	if _, err := s.ApproveIssuance(ctx, tenantA, resource, action, "reviewer"); err != nil {
		t.Fatalf("approve request: %v", err)
	}

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := consumer.ConsumeIssuanceApprovalTx(ctx, tx, tenantA, resource, action, requester, 1)
		return err
	}); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if ok, err := s.HasDistinctApproval(ctx, tenantA, resource, action, requester, 1); err != nil {
		t.Fatalf("check consumed authority: %v", err)
	} else if ok {
		t.Fatal("consumed approval authority remained reusable")
	}

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := consumer.ConsumeIssuanceApprovalTx(ctx, tx, tenantA, resource, action, requester, 1)
		return err
	}); err == nil {
		t.Fatal("second consume succeeded; approval authority must be single-use")
	}
}
