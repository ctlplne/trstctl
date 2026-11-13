// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// A236-L4: deleting a secret keeps it, with its sealed history, as a tombstone
// only its own tenant sees; a restore must name that exact tombstone (version,
// deletion time, sealed value) and finds no live secret under the name; the
// newest deletion replaces an older tombstone; the retention purge removes
// only tombstones deleted before the cutoff.
func TestDeletedSecretTombstoneRestoresOnlyItsExactDeletionA236L4(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	const name = "a236l4-store/db/password"
	base := time.Now().UTC().Truncate(time.Millisecond)
	apply := func(m store.ApplicationSecretMutation) error {
		m.TenantID, m.TenantEpoch, m.Name = tenantA, epoch, name
		m.EventID = googleuuid.NewString()
		m.SemanticDigest, m.RequestBinding = strings.Repeat("a", 64), strings.Repeat("b", 64)
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyApplicationSecretMutationTx(ctx, tx, m)
		})
	}
	must := func(m store.ApplicationSecretMutation) {
		t.Helper()
		if err := apply(m); err != nil {
			t.Fatalf("%s: %v", m.Action, err)
		}
	}
	must(store.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: []byte("sealed-one"), OccurredAt: base})
	must(store.ApplicationSecretMutation{Action: "rotate", ExpectedVersion: 1, ResultVersion: 2, Sealed: []byte("sealed-two"), OccurredAt: base.Add(time.Second)})
	deletedAt := base.Add(2 * time.Second)
	must(store.ApplicationSecretMutation{Action: "delete", ExpectedVersion: 2, OccurredAt: deletedAt})

	kept, sealed, err := s.GetDeletedSecret(ctx, tenantA, name)
	if err != nil || kept.Version != 2 || kept.Versions != 2 || !kept.DeletedAt.Equal(deletedAt) || !bytes.Equal(sealed, []byte("sealed-two")) {
		t.Fatalf("tombstone = %+v sealed=%q err=%v", kept, sealed, err)
	}
	if _, _, err := s.GetDeletedSecret(ctx, tenantB, name); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("another tenant sees the tombstone: %v", err)
	}
	listed := func(tenantID string, hidden []string) bool {
		t.Helper()
		items, err := s.ListDeletedSecrets(ctx, tenantID, hidden, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			if item.Name == name {
				return true
			}
		}
		return false
	}
	if !listed(tenantA, nil) || listed(tenantB, nil) || listed(tenantA, []string{"a236l4-store/"}) {
		t.Fatal("the deleted list is not confined to its tenant and visible prefixes")
	}

	undelete := func(version int, at time.Time, value string) error {
		return apply(store.ApplicationSecretMutation{Action: "undelete", ExpectedVersion: version, ResultVersion: version,
			SourceVersion: version, SourceWrittenAt: at, Sealed: []byte(value), OccurredAt: base.Add(time.Minute)})
	}
	for _, drift := range []struct {
		name    string
		version int
		at      time.Time
		value   string
	}{
		{"another deletion time", 2, deletedAt.Add(time.Millisecond), "sealed-two"},
		{"another sealed value", 2, deletedAt, "sealed-one"},
		{"another version", 1, deletedAt, "sealed-one"},
	} {
		if err := undelete(drift.version, drift.at, drift.value); !errors.Is(err, store.ErrApprovalDrifted) {
			t.Fatalf("a restore naming %s = %v, want ErrApprovalDrifted", drift.name, err)
		}
	}

	// A live secret under the name refuses the restore; deleting it replaces
	// the older tombstone, so the older restore no longer applies.
	must(store.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: []byte("sealed-three"), OccurredAt: base.Add(3 * time.Second)})
	if err := undelete(2, deletedAt, "sealed-two"); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("a restore over a live secret = %v, want ErrApprovalDrifted", err)
	}
	secondDeletion := base.Add(4 * time.Second)
	must(store.ApplicationSecretMutation{Action: "delete", ExpectedVersion: 1, OccurredAt: secondDeletion})
	if err := undelete(2, deletedAt, "sealed-two"); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("a restore of the replaced tombstone = %v, want ErrApprovalDrifted", err)
	}
	if err := undelete(1, secondDeletion, "sealed-three"); err != nil {
		t.Fatalf("the exact restore: %v", err)
	}
	live, err := s.GetSecret(ctx, tenantA, name)
	if err != nil || live.Version != 1 || !bytes.Equal(live.Sealed, []byte("sealed-three")) {
		t.Fatalf("restored secret = %+v err=%v", live, err)
	}
	if _, _, err := s.GetDeletedSecret(ctx, tenantA, name); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("the tombstone outlived its restore: %v", err)
	}

	// The retention purge removes tombstones deleted before the cutoff only.
	must(store.ApplicationSecretMutation{Action: "delete", ExpectedVersion: 1, OccurredAt: base.Add(5 * time.Second)})
	purged, err := s.PurgeDeletedSecretsBefore(ctx, base, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range purged {
		if p.Name == name {
			t.Fatalf("the purge removed a tombstone deleted after the cutoff: %+v", purged)
		}
	}
	purged, err = s.PurgeDeletedSecretsBefore(ctx, base.Add(time.Minute), 1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range purged {
		found = found || p.TenantID == tenantA && p.Name == name
	}
	if !found {
		t.Fatalf("the purge past the deletion missed the tombstone: %+v", purged)
	}
	if _, _, err := s.GetDeletedSecret(ctx, tenantA, name); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("a purged tombstone is still kept: %v", err)
	}
}

// A236-L4: a deleted secret's sealed history moves with its tenant's key
// domain like the live store: the tenant-domain migration re-wraps the
// tombstone's versions for that tenant only, and a resumed pass changes none.
func TestDeletedSecretTombstoneMovesWithTheTenantKeyDomainA236L4(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: tenantID}); err != nil {
			t.Fatal(err)
		}
	}
	deployment := migrationTestKEK(t, 0x51)
	domainKey := migrationTestKEK(t, 0x52)
	domain := []byte("tenant=11111111-1111-1111-1111-111111111111;domain=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb;generation=1")
	legacy, err := seal.Seal(deployment, []byte("tombstoned-value"), []byte("secret:aad"))
	if err != nil {
		t.Fatal(err)
	}
	const name = "a236l4-domain/kept"
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`INSERT INTO secret_store_tombstones (tenant_id, name, version, created_at, deleted_at, deleted_event_id)
				 VALUES ($1, $2, 1, now(), now(), $3)`, tenantID, name, googleuuid.NewString()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO secret_store_tombstone_versions (tenant_id, name, version, sealed, written_at)
				 VALUES ($1, $2, 1, $3, now())`, tenantID, name, legacy)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	rewriter, err := tenantseal.NewHistoryRewrapper(deployment, domainKey, domain)
	if err != nil {
		t.Fatal(err)
	}
	const stage = "secret_store_tombstone_versions.sealed"
	transform := func(before []byte) ([]byte, bool, error) {
		return rewriter.Transform("postgres."+stage, 1, before)
	}
	if changed, err := s.RewriteTenantKeyDomainCiphertextStage(ctx, tenantA, stage, transform); err != nil || changed != 1 {
		t.Fatalf("rewrite tenant A tombstones changed=%d err=%v, want 1", changed, err)
	}
	if changed, err := s.RewriteTenantKeyDomainCiphertextStage(ctx, tenantA, stage, transform); err != nil || changed != 0 {
		t.Fatalf("resumed rewrite changed=%d err=%v, want 0", changed, err)
	}
	for _, tenantID := range []string{tenantA, tenantB} {
		var sealed []byte
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT sealed FROM secret_store_tombstone_versions WHERE tenant_id = $1 AND name = $2`,
				tenantID, name).Scan(&sealed)
		}); err != nil {
			t.Fatal(err)
		}
		if tenantID == tenantB {
			if !bytes.Equal(sealed, legacy) {
				t.Fatal("tenant B's tombstone changed during tenant A's migration")
			}
			continue
		}
		if err := seal.ValidateDomain(domainKey, sealed, domain); err != nil {
			t.Fatalf("tenant A's tombstone is not under its key domain: %v", err)
		}
	}
}

// A236-L4: a purge never pulls a tombstone from under a recorded restore. A
// restore's fence claim checks its exact tombstone under the name's lock; while
// the fence holds the name, an operator purge refuses and the retention sweep
// skips it; once the name is free the purge applies, and a restore claimed
// after the purge finds nothing and records no fence.
func TestDeletedSecretPurgeWaitsForAnInFlightRestoreA236L4(t *testing.T) {
	s := newOperationApprovalStore(t)
	ctx := context.Background()
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	const name = "a236l4-fence/db/password"
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	apply := func(m store.ApplicationSecretMutation) {
		t.Helper()
		m.TenantID, m.TenantEpoch, m.Name = tenantA, epoch, name
		m.EventID = googleuuid.NewString()
		m.SemanticDigest, m.RequestBinding = strings.Repeat("a", 64), strings.Repeat("b", 64)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyApplicationSecretMutationTx(ctx, tx, m)
		}); err != nil {
			t.Fatalf("%s: %v", m.Action, err)
		}
	}
	apply(store.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: []byte("sealed-fence"), OccurredAt: base})
	deletedAt := base.Add(time.Second)
	apply(store.ApplicationSecretMutation{Action: "delete", ExpectedVersion: 1, OccurredAt: deletedAt})

	claim := func(ref store.ApplicationSecretTombstoneRef) error {
		_, err := s.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
			TenantID: tenantA, Name: name, Operation: "undelete", EventID: googleuuid.NewString(),
			EventType: projections.EventApplicationSecretUndeleted, SchemaVersion: projections.ApplicationSecretMutationSchemaVersion,
			RequestBinding: strings.Repeat("c", 64), Payload: []byte(`{"action":"undelete"}`), Tombstone: &ref,
		})
		return err
	}
	if err := claim(store.ApplicationSecretTombstoneRef{Version: 1, DeletedAt: deletedAt.Add(time.Millisecond)}); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("a claim naming another deletion = %v, want ErrSecretNotFound", err)
	}
	if err := claim(store.ApplicationSecretTombstoneRef{Version: 1, DeletedAt: deletedAt}); err != nil {
		t.Fatalf("the exact restore claim: %v", err)
	}
	if _, err := s.PurgeDeletedSecret(ctx, tenantA, name); !errors.Is(err, store.ErrApplicationSecretMutationInFlight) {
		t.Fatalf("a purge under an in-flight restore = %v, want ErrApplicationSecretMutationInFlight", err)
	}
	purged, err := s.PurgeDeletedSecretsBefore(ctx, time.Now().UTC().Add(time.Hour), 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range purged {
		if p.TenantID == tenantA && p.Name == name {
			t.Fatal("the retention sweep purged a tombstone an in-flight restore holds")
		}
	}
	if _, _, err := s.GetDeletedSecret(ctx, tenantA, name); err != nil {
		t.Fatalf("the held tombstone is gone: %v", err)
	}

	// The command ends without being recorded; the name is free again.
	if _, err := s.SystemPool().Exec(ctx,
		`DELETE FROM application_secret_mutation_fences WHERE tenant_id = $1 AND secret_name = $2`, tenantA, name); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.PurgeDeletedSecret(ctx, tenantA, name); err != nil || !ok {
		t.Fatalf("purge of a free tombstone = %v err=%v", ok, err)
	}
	if err := claim(store.ApplicationSecretTombstoneRef{Version: 1, DeletedAt: deletedAt}); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("a restore claimed after the purge = %v, want ErrSecretNotFound", err)
	}
	if _, err := s.GetApplicationSecretMutationFence(ctx, tenantA, name); !store.IsNotFound(err) {
		t.Fatalf("a refused restore left a fence: %v", err)
	}
}
