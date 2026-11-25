// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestRetainedDelegatedMinterAccessDecisionCannotCompleteQuorum(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const requestID = "77000000-0000-4000-8000-000000000976"
	const requester = "cr972-retained-access-service"
	const minter = "cr972-retained-access-minter"
	if _, err := s.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantA, TokenHash: privacy.SubjectRef(tenantA, "cr972-retained-access-holder"),
		Subject: requester, MintedBy: minter,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyAccessChangeRequestCreatedTx(ctx, tx, store.AccessChangeRequest{
			TenantID: tenantA, ID: requestID, RequestedAction: "grant", RequesterSubject: requester,
			NHIID: "cr972-nhi", NHIKind: "certificate", DisplayName: "CR-972 test", Resource: "cr972-resource",
			Entitlement: "use", ChangeRef: "CR-972", Reason: "test retained decision",
			RequiredApprovals: 2, CreatedAt: now,
		}); err != nil {
			return err
		}
		// A historical decision is already in the projection before the fence.
		return s.ApplyAccessChangeRequestDecidedTx(ctx, tx, tenantA, store.AccessChangeDecision{
			RequestID: requestID, ApproverSubject: minter, Decision: "approved", DecidedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.CheckAccessChangeDecisionAuthorityTx(ctx, tx, tenantA, requestID, "cr972-independent"); err != nil {
			return err
		}
		return s.ApplyAccessChangeRequestDecidedTx(ctx, tx, tenantA, store.AccessChangeDecision{
			RequestID: requestID, ApproverSubject: "cr972-independent", Decision: "approved", DecidedAt: now.Add(time.Second),
		})
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAccessChangeRequest(ctx, tenantA, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || got.ApprovalCount != 1 || len(got.Decisions) != 2 {
		t.Fatalf("retained minter vote completed access-change quorum: %+v", got)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.CheckAccessChangeDecisionAuthorityTx(ctx, tx, tenantA, requestID, "cr972-independent-2"); err != nil {
			return err
		}
		return s.ApplyAccessChangeRequestDecidedTx(ctx, tx, tenantA, store.AccessChangeDecision{
			RequestID: requestID, ApproverSubject: "cr972-independent-2", Decision: "approved", DecidedAt: now.Add(2 * time.Second),
		})
	}); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetAccessChangeRequest(ctx, tenantA, requestID)
	if err != nil || got.Status != "approved" || got.ApprovalCount != 2 {
		t.Fatalf("independent quorum: got=%+v err=%v", got, err)
	}

	// A previously terminal-looking row must reopen if its only approval was
	// the minter's. The audit decision stays visible, but a real reviewer can
	// supply the replacement approval.
	const oldApprovedID = "77000000-0000-4000-8000-000000000977"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyAccessChangeRequestCreatedTx(ctx, tx, store.AccessChangeRequest{
			TenantID: tenantA, ID: oldApprovedID, RequestedAction: "grant", RequesterSubject: requester,
			NHIID: "cr972-nhi", NHIKind: "certificate", DisplayName: "CR-972 old decision",
			Resource: "cr972-resource", Entitlement: "use", ChangeRef: "CR-972", Reason: "test old approval",
			RequiredApprovals: 1, CreatedAt: now,
		}); err != nil {
			return err
		}
		return s.ApplyAccessChangeRequestDecidedTx(ctx, tx, tenantA, store.AccessChangeDecision{
			RequestID: oldApprovedID, ApproverSubject: minter, Decision: "approved", DecidedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	old, err := s.GetAccessChangeRequest(ctx, tenantA, oldApprovedID)
	if err != nil || old.Status != "pending" || old.ApprovalCount != 0 || len(old.Decisions) != 1 {
		t.Fatalf("old minter-only approved row was still effective: got=%+v err=%v", old, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.CheckAccessChangeDecisionAuthorityTx(ctx, tx, tenantA, oldApprovedID, "cr972-old-independent"); err != nil {
			return err
		}
		return s.ApplyAccessChangeRequestDecidedTx(ctx, tx, tenantA, store.AccessChangeDecision{
			RequestID: oldApprovedID, ApproverSubject: "cr972-old-independent", Decision: "approved", DecidedAt: now.Add(time.Second),
		})
	}); err != nil {
		t.Fatal(err)
	}
	old, err = s.GetAccessChangeRequest(ctx, tenantA, oldApprovedID)
	if err != nil || old.Status != "approved" || old.ApprovalCount != 1 || len(old.Decisions) != 2 {
		t.Fatalf("old request did not accept independent reviewer: got=%+v err=%v", old, err)
	}
}
