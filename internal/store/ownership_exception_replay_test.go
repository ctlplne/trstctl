// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestOwnershipExceptionRevocationReplaysAcrossCheckpointOverlap(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	seedTenant(t, s, tenantA)
	grantedAt := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	revokedAt := grantedAt.Add(time.Minute)
	grant := store.OwnershipException{
		ID: "41a69078-4c8a-45a9-8945-bb39372337a9", TenantID: tenantA,
		IdentityID: uuid(tenantA, 2), Reason: "temporary QA exception",
		GrantedBy: "owner@example.test", GrantedAt: grantedAt,
		ExpiresAt:      grantedAt.Add(time.Hour),
		CreatedEventID: "a67662d4-fdae-4784-a5a7-68661f51d97c", LastEventSeq: 100,
	}
	applyGrant := func() error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyOwnershipExceptionGrantedTx(ctx, tx, grant)
		})
	}
	applyRevoke := func(actor, reason string, seq uint64) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyOwnershipExceptionRevokedTx(ctx, tx, tenantA, grant.ID, actor, reason, revokedAt, seq)
		})
	}
	if err := applyGrant(); err != nil {
		t.Fatal(err)
	}
	if err := applyRevoke("security@example.test", "exception closed", 101); err != nil {
		t.Fatal(err)
	}
	before, err := s.GetOwnershipException(ctx, tenantA, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The event checkpoint can lag a committed read-model row. Replaying the
	// retained grant and revoke must leave the exact authority unchanged.
	if err := applyGrant(); err != nil {
		t.Fatal(err)
	}
	if err := applyRevoke("security@example.test", "exception closed", 101); err != nil {
		t.Fatalf("same revoke event after checkpoint overlap: %v", err)
	}
	after, err := s.GetOwnershipException(ctx, tenantA, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("replay changed revocation: before=%+v after=%+v", before, after)
	}
	if err := applyRevoke("other@example.test", "different decision", 101); err == nil {
		t.Fatal("different revoke evidence reused the same event sequence")
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE ownership_readiness_exceptions
			SET revoked_by = 'retained:qa-redacted', revocation_reason = ''
			WHERE tenant_id = $1 AND id = $2`, tenantA, grant.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := applyRevoke("security@example.test", "exception closed", 101); err != nil {
		t.Fatalf("privacy-redacted revoke event after checkpoint overlap: %v", err)
	}
	redacted, err := s.GetOwnershipException(ctx, tenantA, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if redacted.RevokedBy != "retained:qa-redacted" || redacted.RevocationReason != "" {
		t.Fatalf("replay restored erased actor or reason: %+v", redacted)
	}
}
