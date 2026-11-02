// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A236: a versioned batch reserves every name at its planned version. A moved
// version refuses the reservation, a reserved name refuses single-secret and
// competing batch writers, and the projection writes every new version, the
// receipt and the release in one transaction, once.
func TestApplicationSecretVersionBatchFencesA236(t *testing.T) {
	ctx := context.Background()
	s := newOperationApprovalStore(t)
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"versioned-batch-test/a", "versioned-batch-test/b"}
	const eventID = "9e783bba-616c-5da7-b334-8235249d5801"
	cleanup := func() {
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM application_secret_import_batches WHERE tenant_id = $1 AND event_id = ANY($2::uuid[])`, tenantA, []string{eventID, "9e783bba-616c-5da7-b334-8235249d5802"})
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM application_secret_import_receipts WHERE tenant_id = $1 AND event_id = $2`, tenantA, eventID)
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM secret_store_versions WHERE tenant_id = $1 AND name = ANY($2)`, tenantA, names)
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM secret_store WHERE tenant_id = $1 AND name = ANY($2)`, tenantA, names)
	}
	cleanup()
	defer cleanup()
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO secret_store (tenant_id, name, sealed, version) VALUES ($1, $2, $3, 1)`,
			tenantA, names[0], []byte("sealed-a1")); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at) VALUES ($1, $2, 1, $3, now())`,
			tenantA, names[0], []byte("sealed-a1"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	batch := store.ApplicationSecretImportBatch{
		TenantID: tenantA, EventID: eventID, TenantEpoch: epoch, RequestBinding: strings.Repeat("d", 64),
		Payload:   []byte(`{"items":[{"name":"versioned-batch-test/a"},{"name":"versioned-batch-test/b"}]}`),
		Actor:     &events.Actor{Subject: "promoter", Roles: []string{"operator"}},
		EventTime: time.Now().UTC(), Names: names, Operation: store.ApplicationSecretBatchPromotion,
	}
	fences := []store.ApplicationSecretVersionFence{{Name: names[0], ExpectedVersion: 1}, {Name: names[1], ExpectedVersion: 0}}
	crash := errors.New("crash after reservation")
	run := func(b store.ApplicationSecretImportBatch, f []store.ApplicationSecretVersionFence) error {
		return s.RunApplicationSecretVersionBatchCommand(ctx, b, f, func(context.Context, store.ApplicationSecretImportBatch) error { return crash })
	}

	stale := []store.ApplicationSecretVersionFence{{Name: names[0], ExpectedVersion: 2}, {Name: names[1], ExpectedVersion: 0}}
	if err := run(batch, stale); !errors.Is(err, store.ErrApplicationSecretBatchStale) {
		t.Fatalf("a moved version was reserved: %v", err)
	}
	if _, err := s.GetApplicationSecretImportBatch(ctx, tenantA, eventID); !store.IsNotFound(err) {
		t.Fatalf("a stale reservation left a batch: %v", err)
	}
	if err := run(batch, fences); !errors.Is(err, crash) {
		t.Fatalf("reservation: %v", err)
	}
	if err := run(batch, fences); !errors.Is(err, crash) {
		t.Fatalf("an exact crash retry was refused: %v", err)
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: names[0], Operation: "rotate",
		EventID: "9e783bba-616c-5da7-b334-8235249d5803", EventType: "secret.rotated",
		SchemaVersion: 2, RequestBinding: strings.Repeat("d", 64), Payload: []byte(`{"action":"rotate"}`),
	}); !errors.Is(err, store.ErrApplicationSecretMutationInFlight) {
		t.Fatalf("a single-secret writer bypassed the batch reservation: %v", err)
	}
	competing := batch
	competing.EventID = "9e783bba-616c-5da7-b334-8235249d5802"
	competing.Operation = store.ApplicationSecretBatchRestore
	if err := run(competing, fences); !errors.Is(err, store.ErrApplicationSecretMutationInFlight) {
		t.Fatalf("a competing batch bypassed the reservation: %v", err)
	}
	if _, err := s.ClaimApplicationSecretImportBatch(ctx, batch); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("an import claimed a promotion's reservation: %v", err)
	}

	batch.EventTime = batch.EventTime.UTC().Truncate(time.Microsecond)
	canonical, err := s.GetApplicationSecretImportBatch(ctx, tenantA, eventID)
	if err != nil || canonical.Operation != store.ApplicationSecretBatchPromotion {
		t.Fatalf("reserved batch: %+v %v", canonical, err)
	}
	canonical.PayloadDigest = crypto.SHA256Hex(canonical.Payload)
	items := []store.ApplicationSecretVersionItem{
		{Name: names[0], ExpectedVersion: 1, ResultVersion: 2, Sealed: []byte("sealed-a2")},
		{Name: names[1], ExpectedVersion: 0, ResultVersion: 1, Sealed: []byte("sealed-b1")},
	}
	apply := func() error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyApplicationSecretVersionBatchTx(ctx, tx, canonical, strings.Repeat("e", 64), items, false)
		})
	}
	if err := apply(); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := apply(); err != nil {
		t.Fatalf("the same event was not idempotent: %v", err)
	}
	a, err := s.GetSecret(ctx, tenantA, names[0])
	if err != nil || a.Version != 2 || string(a.Sealed) != "sealed-a2" {
		t.Fatalf("a: %+v %v", a, err)
	}
	if b, err := s.GetSecret(ctx, tenantA, names[1]); err != nil || b.Version != 1 {
		t.Fatalf("b: %+v %v", b, err)
	}
	if v1, err := s.GetSecretVersion(ctx, tenantA, names[0], 1); err != nil || string(v1.Sealed) != "sealed-a1" {
		t.Fatalf("history lost: %+v %v", v1, err)
	}
	if _, err := s.GetApplicationSecretImportBatch(ctx, tenantA, eventID); !store.IsNotFound(err) {
		t.Fatalf("the reservation was not released: %v", err)
	}
	receipt, err := s.GetApplicationSecretImportReceipt(ctx, tenantA, eventID)
	if err != nil || len(receipt.Items) != 2 || receipt.Items[0].Version != 2 {
		t.Fatalf("receipt: %+v %v", receipt, err)
	}
	if _, err := s.GetApplicationSecretImportReceipt(ctx, tenantB, eventID); !store.IsNotFound(err) {
		t.Fatalf("another tenant read the receipt: %v", err)
	}
}

// A236: a version whose credential a rotation retired, revoked or let expire
// is named as such; the live version is not.
func TestSecretVersionCredentialStateA236(t *testing.T) {
	ctx := context.Background()
	s := newOperationApprovalStore(t)
	const name = "credential-state-test/db"
	now := time.Now().UTC()
	insert := func(id, phase string, expected, result, ttl int, expires *time.Time) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO secret_static_rotation_commands
				(tenant_id, id, tenant_epoch, provider, secret_key, old_ref, phase, expected_version, result_version,
				 idempotency_key_digest, request_binding, ttl_seconds, new_expires_at, created_at, updated_at)
				VALUES ($1, $2, 'epoch', 'pg', $3, 'old', $4, $5, $6, $7, $7, $8, $9, $10, $10)`,
				tenantA, id, name, phase, expected, result, strings.Repeat("f", 64), ttl, expires, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM secret_static_rotation_commands WHERE tenant_id = $1 AND secret_key = $2`, tenantA, name)
	}()
	past := now.Add(-time.Hour)
	// v1 → v2 completed (v1 retired); v2 → v3 rolled back (v3 revoked, v2 stays
	// live; the rollback republished v2's value as v4); v4 → v5 a lease rotation
	// whose lease has expired (v4 retired, v5 expired); v6 is unknown to any.
	insert("9e783bba-616c-5da7-b334-8235249d5811", "completed", 1, 2, 0, nil)
	insert("9e783bba-616c-5da7-b334-8235249d5812", "rolled_back", 2, 3, 0, nil)
	insert("9e783bba-616c-5da7-b334-8235249d5813", "completed", 4, 5, 3600, &past)
	for version, want := range map[int]string{
		1: store.SecretCredentialRetired, 2: "", 3: store.SecretCredentialRevoked,
		4: store.SecretCredentialRetired, 5: store.SecretCredentialExpired, 6: "",
	} {
		got, err := s.SecretVersionCredentialState(ctx, tenantA, name, version, now)
		if err != nil || got.State != want {
			t.Fatalf("version %d: %+v %v, want %q", version, got, err, want)
		}
	}
	if got, _ := s.SecretVersionCredentialState(ctx, tenantB, name, 1, now); got.State != "" {
		t.Fatalf("another tenant's rotation applied: %+v", got)
	}
}
