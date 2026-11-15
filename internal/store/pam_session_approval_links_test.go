// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestPAMSessionApprovalLinkIsRecordedOnceG1L6: the approval a session's
// activation consumed is recorded once. Replaying the activation records
// nothing new, a different approval for the same session is refused, a
// session whose activation was never recorded reads none, and another
// tenant reads nothing of it.
func TestPAMSessionApprovalLinkIsRecordedOnceG1L6(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	session, approval := googleuuid.NewString(), googleuuid.NewString()
	at := time.Now().UTC()
	apply := func(tenantID, approvalID string) error {
		return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyPAMSessionApprovalLinkTx(ctx, tx, tenantID, session, approvalID, at)
		})
	}
	read := func(tenantID, sessionID string) (string, bool) {
		t.Helper()
		var id string
		var found bool
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			var err error
			id, found, err = s.PAMSessionApprovalLinkTx(ctx, tx, tenantID, sessionID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return id, found
	}
	if err := apply(tenantA, approval); err != nil {
		t.Fatal(err)
	}
	if err := apply(tenantA, approval); err != nil {
		t.Fatalf("replaying the activation: %v", err)
	}
	if err := apply(tenantA, googleuuid.NewString()); err == nil {
		t.Fatal("a different approval for the same session was recorded")
	}
	if id, found := read(tenantA, session); !found || id != approval {
		t.Fatalf("the session's link reads %q (%v), want %s", id, found, approval)
	}
	if _, found := read(tenantA, googleuuid.NewString()); found {
		t.Fatal("a session whose activation was never recorded reads a link")
	}
	const otherTenant = "61600000-0000-4000-8000-0000000000b6"
	if _, found := read(otherTenant, session); found {
		t.Fatal("another tenant reads the session's link")
	}
	if store.PAMApprovalLinkRecorded == store.PAMApprovalLinkDerived || store.PAMApprovalLinkRecorded == "" {
		t.Fatal("the link states are not distinct")
	}
}
