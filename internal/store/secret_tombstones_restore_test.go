// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A236-L5: a restore batch that brings a deleted secret back reserves it only
// against the exact kept deletion it planned, under the name's lock: another
// deletion time or a purged tombstone is stale and reserves nothing, the exact
// one reserves, and a purge then refuses the reserved name.
func TestRestoreBatchReservesOnlyItsExactTombstoneA236L5(t *testing.T) {
	ctx := context.Background()
	s := newOperationApprovalStore(t)
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	const name = "a236l5-store/db/password"
	deletedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO secret_store_tombstones (tenant_id, name, version, created_at, deleted_at, deleted_event_id)
			 VALUES ($1, $2, 2, $3, $3, $4)`, tenantA, name, deletedAt, googleuuid.NewString()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_store_tombstone_versions (tenant_id, name, version, sealed, written_at)
			 VALUES ($1, $2, 1, 'sealed-1', $3), ($1, $2, 2, 'sealed-2', $3)`, tenantA, name, deletedAt)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	batch := func() store.ApplicationSecretImportBatch {
		return store.ApplicationSecretImportBatch{
			TenantID: tenantA, EventID: googleuuid.NewString(), TenantEpoch: epoch, RequestBinding: strings.Repeat("e", 64),
			Payload:   []byte(`{"items":[{"name":"a236l5-store/db/password"}]}`),
			Actor:     &events.Actor{Subject: "restorer", Roles: []string{"operator"}},
			EventTime: time.Now().UTC(), Names: []string{name}, Operation: store.ApplicationSecretBatchRestore,
		}
	}
	reserve := func(b store.ApplicationSecretImportBatch, ref store.ApplicationSecretTombstoneRef) error {
		return s.RunApplicationSecretVersionBatchCommand(ctx, b,
			[]store.ApplicationSecretVersionFence{{Name: name, ExpectedVersion: 0, Tombstone: &ref}},
			func(context.Context, store.ApplicationSecretImportBatch) error { return nil })
	}
	other := batch()
	if err := reserve(other, store.ApplicationSecretTombstoneRef{Version: 2, DeletedAt: deletedAt.Add(time.Microsecond)}); !errors.Is(err, store.ErrApplicationSecretBatchStale) {
		t.Fatalf("a batch naming another deletion = %v, want ErrApplicationSecretBatchStale", err)
	}
	if _, err := s.GetApplicationSecretImportBatch(ctx, tenantA, other.EventID); !store.IsNotFound(err) {
		t.Fatalf("a stale restore reserved a batch: %v", err)
	}
	exact := batch()
	if err := reserve(exact, store.ApplicationSecretTombstoneRef{Version: 2, DeletedAt: deletedAt}); err != nil {
		t.Fatalf("the exact restore reservation: %v", err)
	}
	if _, err := s.PurgeDeletedSecret(ctx, tenantA, name); !errors.Is(err, store.ErrApplicationSecretMutationInFlight) {
		t.Fatalf("a purge of a reserved name = %v, want ErrApplicationSecretMutationInFlight", err)
	}
	// The reservation ends unprojected; once released the tombstone can go,
	// and a restore that still names it is stale.
	if _, err := s.SystemPool().Exec(ctx,
		`DELETE FROM application_secret_import_batches WHERE tenant_id = $1 AND event_id = $2`, tenantA, exact.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`DELETE FROM application_secret_import_name_fences WHERE tenant_id = $1 AND secret_name = $2`, tenantA, name); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.PurgeDeletedSecret(ctx, tenantA, name); err != nil || !ok {
		t.Fatalf("purge of the released tombstone = %v err=%v", ok, err)
	}
	if err := reserve(batch(), store.ApplicationSecretTombstoneRef{Version: 2, DeletedAt: deletedAt}); !errors.Is(err, store.ErrApplicationSecretBatchStale) {
		t.Fatalf("a restore of a purged tombstone = %v, want ErrApplicationSecretBatchStale", err)
	}
}
