// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestDynamicSecretTenantEpochRotatesAcrossOffboardAndReregistrationAUD108(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()

	first, err := s.DynamicSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.DynamicSecretTenantEpoch(ctx, tenantA); err != nil || again != first {
		t.Fatalf("stable tenant epoch = %q, %v; want %q", again, err, first)
	}
	if first == "" {
		t.Fatal("dynamic-secret tenant epoch is empty")
	}

	attestation, err := s.OffboardTenant(ctx, tenantA)
	if err != nil || !attestation.Complete {
		t.Fatalf("offboard = %+v, %v", attestation, err)
	}
	if _, err := s.DynamicSecretTenantEpoch(ctx, tenantA); !errors.Is(err, store.ErrDynamicSecretTenantEpochMismatch) {
		t.Fatalf("epoch for offboarded tenant error = %v, want lifecycle mismatch", err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "tenant-a-reregistered"}); err != nil {
		t.Fatal(err)
	}
	second, err := s.DynamicSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if second == "" || second == first {
		t.Fatalf("re-registration epoch = %q, want nonempty and different from %q", second, first)
	}

	// The same public lease id may be recreated by the new registration. An old
	// terminal event must carry its first epoch through projection; resolving the
	// target row's new epoch would let retained history kill the new command.
	now := time.Date(2026, 8, 11, 11, 0, 0, 0, time.UTC)
	lease := store.DynamicSecretLease{
		ID: "lease-aud108-reregistered", TenantID: tenantA, TenantEpoch: second,
		IdempotencyKey: "aud108-reregistered", RequestBinding: "sha256:aud108-reregistered",
		Provider: "postgresql", Role: "reader", IssueOutboxID: 8107,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), HardExpiresAt: now.Add(2 * time.Hour), UpdatedAt: now,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeasePendingTx(ctx, tx, lease)
	}); err != nil {
		t.Fatal(err)
	}
	err = s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseIssuanceFailedForEpochTx(
			ctx, tx, tenantA, first, lease.ID, "stale first-registration failure", now.Add(time.Second))
	})
	if !errors.Is(err, store.ErrDynamicSecretTenantEpochMismatch) {
		t.Fatalf("old-epoch failure error = %v, want tenant epoch mismatch", err)
	}

	operation := store.DynamicSecretOperation{
		TenantID: tenantA, TenantEpoch: second, OperationID: "same-public-operation",
		IdempotencyKey: "same-operation-command", RequestBinding: "sha256:same-operation-command",
		Action: "renew", LeaseID: lease.ID, Response: []byte(`{"lease_id":"lease-aud108-reregistered"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretOperationRequestedTx(ctx, tx, operation)
	}); err != nil {
		t.Fatalf("seed re-registered operation: %v", err)
	}

	// Every v2 result path validates registration authority before looking up or
	// locking the same public command. These deliberately valid-looking first-
	// registration results must all remain inert against the recreated IDs.
	issued := lease
	issued.TenantEpoch = first
	issued.BackendRef = "stale-backend"
	issued.SealedCredential = []byte("stale-sealed-credential")
	staleTransitions := []struct {
		name  string
		apply func(pgx.Tx) error
	}{
		{
			name: "prepared",
			apply: func(tx pgx.Tx) error {
				return s.ApplyDynamicSecretLeasePreparedForEpochTx(
					ctx, tx, tenantA, first, lease.ID, lease.Provider,
					[]byte("stale-sealed-preparation"), now.Add(time.Second))
			},
		},
		{
			name: "issued",
			apply: func(tx pgx.Tx) error {
				return s.ApplyDynamicSecretLeaseIssuedTx(ctx, tx, issued)
			},
		},
		{
			name: "renewed",
			apply: func(tx pgx.Tx) error {
				return s.ApplyDynamicSecretLeaseRenewedForEpochTx(
					ctx, tx, tenantA, first, lease.ID, now.Add(90*time.Minute), now.Add(time.Second))
			},
		},
		{
			name: "revocation completed",
			apply: func(tx pgx.Tx) error {
				return s.ApplyDynamicSecretLeaseRevocationCompletedForEpochTx(
					ctx, tx, tenantA, first, lease.ID, now.Add(time.Second))
			},
		},
		{
			name: "revocation failed",
			apply: func(tx pgx.Tx) error {
				return s.ApplyDynamicSecretLeaseRevocationFailedForEpochTx(
					ctx, tx, tenantA, first, lease.ID, "stale revoke failure", now.Add(time.Second))
			},
		},
		{
			name: "operation completed",
			apply: func(tx pgx.Tx) error {
				return s.ApplyDynamicSecretOperationCompletedForEpochTx(
					ctx, tx, tenantA, first, operation.OperationID, operation.RequestBinding,
					operation.Action, operation.LeaseID, now.Add(time.Second))
			},
		},
	}
	for _, transition := range staleTransitions {
		t.Run(transition.name, func(t *testing.T) {
			err := s.WithTenantProjection(ctx, tenantA, transition.apply)
			if !errors.Is(err, store.ErrDynamicSecretTenantEpochMismatch) {
				t.Fatalf("old-epoch transition error = %v, want tenant epoch mismatch", err)
			}
		})
	}
	retained, err := s.GetDynamicSecretLease(ctx, tenantA, lease.ID)
	if err != nil || retained.State != store.DynamicSecretLeasePending || retained.TenantEpoch != second {
		t.Fatalf("old failure changed re-registered lease: %+v err=%v", retained, err)
	}
	retainedOperation, err := s.GetDynamicSecretOperation(ctx, tenantA, operation.OperationID)
	if err != nil || retainedOperation.Status != store.DynamicSecretOperationPending || retainedOperation.TenantEpoch != second {
		t.Fatalf("old terminal changed re-registered operation: %+v err=%v", retainedOperation, err)
	}
}

func TestDynamicSecretPreparedAndIssuedReplayRequiresExactCanonicalResultAUD108(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	epoch, err := s.DynamicSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	// Keep sub-microsecond bits so exact replay proves PostgreSQL timestamp
	// canonicalization rather than relying on already-rounded fixtures.
	now := time.Date(2026, 8, 11, 12, 0, 0, 731, time.UTC)
	lease := store.DynamicSecretLease{
		ID: "lease-aud108-exact-result", TenantID: tenantA, TenantEpoch: epoch,
		IdempotencyKey: "aud108-exact-result", RequestBinding: "sha256:aud108-exact-result",
		Provider: "postgresql", Role: "reader", IssueOutboxID: 8108,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), HardExpiresAt: now.Add(2 * time.Hour), UpdatedAt: now,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeasePendingTx(ctx, tx, lease)
	}); err != nil {
		t.Fatal(err)
	}

	preparedAt := now.Add(time.Second)
	applyPrepared := func(sealed []byte, at time.Time) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyDynamicSecretLeasePreparedForEpochTx(ctx, tx, tenantA, epoch, lease.ID, lease.Provider, sealed, at)
		})
	}
	if err := applyPrepared([]byte("sealed-preparation-a"), preparedAt); err != nil {
		t.Fatal(err)
	}
	if err := applyPrepared([]byte("sealed-preparation-a"), preparedAt); err != nil {
		t.Fatalf("exact preparation replay: %v", err)
	}
	if err := applyPrepared([]byte("sealed-preparation-b"), preparedAt); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("conflicting preparation replay error = %v, want ErrIdempotencyConflict", err)
	}
	prepared, err := s.GetDynamicSecretLease(ctx, tenantA, lease.ID)
	if err != nil || prepared.TenantEpoch != epoch || prepared.PreparationDigest == "" ||
		prepared.PreparedAt == nil || !prepared.PreparedAt.Equal(preparedAt.Truncate(time.Microsecond)) {
		t.Fatalf("public prepared authority = %+v err=%v", prepared, err)
	}

	issued := lease
	issued.BackendRef = "trstctl_reader_aud108"
	issued.SealedCredential = []byte("sealed-credential-a")
	issued.IssuedAt = now.Add(2 * time.Second)
	issued.UpdatedAt = issued.IssuedAt
	applyIssued := func(candidate store.DynamicSecretLease) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyDynamicSecretLeaseIssuedTx(ctx, tx, candidate)
		})
	}
	if err := applyIssued(issued); err != nil {
		t.Fatal(err)
	}
	if err := applyIssued(issued); err != nil {
		t.Fatalf("exact issued replay: %v", err)
	}
	conflict := issued
	conflict.SealedCredential = []byte("sealed-credential-b")
	if err := applyIssued(conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("conflicting issued ciphertext error = %v, want ErrIdempotencyConflict", err)
	}
	conflict = issued
	conflict.BackendRef = "trstctl_reader_replaced"
	if err := applyIssued(conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("conflicting issued backend identity error = %v, want ErrIdempotencyConflict", err)
	}
	if err := applyPrepared([]byte("sealed-preparation-a"), preparedAt); err != nil {
		t.Fatalf("exact preparation replay after terminal transition: %v", err)
	}
	if err := applyPrepared([]byte("sealed-preparation-b"), preparedAt); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("conflicting old preparation after terminal error = %v, want ErrIdempotencyConflict", err)
	}
	active, err := s.GetDynamicSecretLease(ctx, tenantA, lease.ID)
	if err != nil || active.TenantEpoch != epoch || active.CredentialDigest == "" ||
		active.PreparationDigest == "" || active.PreparedAt == nil {
		t.Fatalf("public issued authority = %+v err=%v", active, err)
	}

	// Simulate upgraded terminal rows whose pre-migration preparation ciphertext
	// was already cleared. A digest without the canonical event time is incomplete
	// proof, and a time without the digest is incomplete proof. Neither replay may
	// bless whichever retained event happens to arrive first.
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE dynamic_secret_leases
		   SET prepared_at = NULL
		 WHERE tenant_id = $1 AND id = $2`, tenantA, lease.ID); err != nil {
		t.Fatalf("erase migrated preparation time proof fixture: %v", err)
	}
	if err := applyPrepared([]byte("sealed-preparation-a"), preparedAt); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("terminal preparation without retained time proof error = %v, want ErrIdempotencyConflict", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE dynamic_secret_leases
		   SET preparation_digest = '', prepared_at = $3
		 WHERE tenant_id = $1 AND id = $2`, tenantA, lease.ID, preparedAt); err != nil {
		t.Fatalf("erase migrated preparation digest proof fixture: %v", err)
	}
	if err := applyPrepared([]byte("sealed-preparation-a"), preparedAt); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("terminal preparation without retained digest proof error = %v, want ErrIdempotencyConflict", err)
	}
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseRevocationRequestedTx(
			ctx, tx, tenantA, lease.ID, 9108, now.Add(3*time.Second))
	}); err != nil {
		t.Fatalf("revoke exact-result fixture: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE dynamic_secret_leases
		   SET credential_digest = ''
		 WHERE tenant_id = $1 AND id = $2`, tenantA, lease.ID); err != nil {
		t.Fatalf("erase migrated credential proof fixture: %v", err)
	}
	if err := applyIssued(issued); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("revoked credential without retained proof error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestDynamicSecretEpochIsTenantRLSScopedAUD108(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	epochB, err := s.DynamicSecretTenantEpoch(ctx, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantB, epochB)
	})
	if !errors.Is(err, store.ErrDynamicSecretTenantEpochMismatch) {
		t.Fatalf("tenant A epoch lookup error = %v, want lifecycle mismatch hidden by RLS", err)
	}
}

func TestDynamicSecretTerminalResolverCannotSynthesizeTenantEpochAUD108(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111218"
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{
		TenantID: tenantID, Name: "terminal-authority-test", EventSeq: 40,
	}); err != nil {
		t.Fatal(err)
	}

	err := s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		_, resolveErr := s.ResolveDynamicSecretTenantEpochTx(ctx, tx, tenantID, "", 41)
		return resolveErr
	})
	if !errors.Is(err, store.ErrDynamicSecretTenantEpochMismatch) {
		t.Fatalf("terminal resolver error = %v, want tenant epoch mismatch", err)
	}
	var count int
	if err := s.SystemPool().QueryRow(ctx, `
		SELECT count(*)
		  FROM application_secret_tenant_epochs
		 WHERE tenant_id = $1`, tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("terminal resolver synthesized %d tenant epoch rows", count)
	}

	var epoch string
	if err := s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		var resolveErr error
		epoch, resolveErr = s.ResolveDynamicSecretPendingTenantEpochTx(ctx, tx, tenantID, "", 41)
		return resolveErr
	}); err != nil {
		t.Fatalf("pending resolver: %v", err)
	}
	if epoch == "" {
		t.Fatal("pending resolver created an empty epoch")
	}
}
