// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/store"
)

func TestPAMCommandActionsReplayAndStayTenantScopedA262(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantA = "a2620000-0000-4000-8000-000000000001"
	const tenantB = "b2620000-0000-4000-8000-000000000002"
	seedTenant(t, s, tenantA)
	seedTenant(t, s, tenantB)
	session, connection := "a2620000-0000-4000-8000-000000000003", "a2620000-0000-4000-8000-000000000004"
	at := time.Date(2026, 11, 5, 12, 0, 0, 123456000, time.UTC)
	deadline := at.Add(30 * time.Second)
	action := store.PAMCommandAction{Decision: accessrules.Decision{ID: accessrules.ActionID(session, connection, 7, 1, 1), SessionID: session, JobID: 7, Attempt: 1, Protocol: "postgres", Observation: accessrules.Observation{ConnectionID: connection, Ordinal: 1, Phase: "bind", Operations: []string{"DROP"}, RuleIDs: []string{"a2620000-0000-4000-8000-000000000005"}, MessageDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Status: accessrules.StatusPending, Reason: "review_required", ObservedAt: at, DecidedAt: at, ReviewExpiresAt: &deadline}, SourceEventID: "a2620000-0000-4000-8000-000000000006"}
	apply := func(a store.PAMCommandAction) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPAMCommandBlockedTx(ctx, tx, tenantA, a) })
	}
	if err := apply(action); err != nil {
		t.Fatal(err)
	}
	if err := apply(action); err != nil {
		t.Fatalf("identical held occurrence did not replay after SQL time decoding: %v", err)
	}
	altered := action
	altered.MessageDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := apply(altered); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("different occurrence metadata was silently accepted: %v", err)
	}
	if _, err := s.GetPAMCommandAction(ctx, tenantB, action.ID); !errors.Is(err, store.ErrPAMCommandActionNotFound) {
		t.Fatalf("other tenant read action: %v", err)
	}
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pam_command_actions WHERE tenant_id=$1`, tenantA).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("RLS exposed another tenant's action")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	terminal := action
	terminal.Status = accessrules.StatusCanceled
	terminal.Reason = "client_canceled"
	terminal.DecidedAt = at.Add(time.Second)
	terminal.SourceEventID = "a2620000-0000-4000-8000-000000000007"
	if err := apply(terminal); err != nil {
		t.Fatal(err)
	}
	if err := apply(action); err != nil {
		t.Fatalf("original hold did not safely replay after terminal decision: %v", err)
	}
	row, err := s.GetPAMCommandAction(ctx, tenantA, action.ID)
	if err != nil || row.Status != accessrules.StatusCanceled || !row.ObservedAt.Equal(at) {
		t.Fatalf("terminal action regressed: %+v %v", row, err)
	}
	page, err := s.ListPAMCommandActions(ctx, tenantA, session, 2, nil, "")
	if err != nil || len(page) != 1 {
		t.Fatalf("session page = %d %v", len(page), err)
	}
	page, err = s.ListPAMCommandActions(ctx, tenantA, session, 2, &at, action.ID)
	if err != nil || len(page) != 0 {
		t.Fatalf("stable time/ID cursor repeated its boundary: %d %v", len(page), err)
	}
}
