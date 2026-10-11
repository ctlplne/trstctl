// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestApplicationSecretImportFencesAndProjectionRollback(t *testing.T) {
	ctx := context.Background()
	s := newOperationApprovalStore(t)
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"batch-atomic-test/a", "batch-atomic-test/b"}
	batch := store.ApplicationSecretImportBatch{
		TenantID: tenantA, EventID: "7bd2f615-651c-51f4-9c37-31a562b0e60d",
		TenantEpoch: epoch, RequestBinding: strings.Repeat("b", 64),
		Payload:   []byte(`{"items":[{"name":"batch-atomic-test/a"},{"name":"batch-atomic-test/b"}]}`),
		Actor:     &events.Actor{Subject: "batch-atomic-tester", Roles: []string{"operator"}},
		EventTime: time.Now().UTC(), Names: names,
	}
	defer func() {
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM application_secret_import_batches WHERE tenant_id = $1 AND event_id = $2`, tenantA, batch.EventID)
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM application_secret_import_receipts WHERE tenant_id = $1 AND event_id = $2`, tenantA, batch.EventID)
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM secret_store_versions WHERE tenant_id = $1 AND name = ANY($2)`, tenantA, names)
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM secret_store WHERE tenant_id = $1 AND name = ANY($2)`, tenantA, names)
	}()
	canonical, err := s.ClaimApplicationSecretImportBatch(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimApplicationSecretImportBatch(ctx, batch); err != nil {
		t.Fatalf("exact crash retry rejected: %v", err)
	}
	other := batch
	other.EventID = "7bd2f615-651c-51f4-9c37-31a562b0e60e"
	if _, err := s.ClaimApplicationSecretImportBatch(ctx, other); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("competing batch did not hit per-name fence: %v", err)
	}
	if _, err := s.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: names[0], Operation: "create",
		EventID: "7bd2f615-651c-51f4-9c37-31a562b0e60f", EventType: "secret.created",
		SchemaVersion: 2, RequestBinding: strings.Repeat("b", 64),
		Payload: []byte(`{"action":"create"}`),
	}); !errors.Is(err, store.ErrApplicationSecretMutationInFlight) {
		t.Fatalf("single-name writer bypassed batch fence: %v", err)
	}
	// Inject a late existing row to force the second insert to fail. The first
	// insert, version row, and receipt must all roll back in one SQL transaction.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO secret_store (tenant_id, name, sealed, version)
			VALUES ($1, $2, $3, 1)`, tenantA, names[1], []byte("fixture"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	items := []store.ApplicationSecretImportSealedItem{
		{Name: names[0], Sealed: []byte("sealed-a")},
		{Name: names[1], Sealed: []byte("sealed-b")},
	}
	apply := func() error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyApplicationSecretImportTx(ctx, tx, canonical,
				strings.Repeat("c", 64), items, false)
		})
	}
	if err := apply(); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("late second-name collision did not reject whole batch: %v", err)
	}
	if _, err := s.GetSecret(ctx, tenantA, names[0]); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("failed import left first name visible: %v", err)
	}
	if _, err := s.GetApplicationSecretImportReceipt(ctx, tenantA, batch.EventID); !store.IsNotFound(err) {
		t.Fatalf("failed import left a receipt: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM secret_store WHERE tenant_id = $1 AND name = $2`, tenantA, names[1])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatalf("crash retry could not project complete batch: %v", err)
	}
	if err := apply(); err != nil {
		t.Fatalf("same event was not idempotent: %v", err)
	}
	receipt, err := s.GetApplicationSecretImportReceipt(ctx, tenantA, batch.EventID)
	if err != nil || len(receipt.Items) != 2 {
		t.Fatalf("committed receipt items=%d err=%v", len(receipt.Items), err)
	}
	if _, err := s.GetApplicationSecretImportReceipt(ctx, tenantB, batch.EventID); !store.IsNotFound(err) {
		t.Fatalf("other tenant read the batch receipt: %v", err)
	}
}

func TestPrivacyPreparationRetiresPendingBatchWithErasedAADName(t *testing.T) {
	ctx := context.Background()
	s := newOperationApprovalStore(t)
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	const subject = "batch-import-erasure-subject"
	command, err := json.Marshal(projections.ApplicationSecretBatchImport{
		TenantEpoch: epoch, IdempotencyKeyDigest: strings.Repeat("a", 64),
		RequestBinding: strings.Repeat("b", 64), CommandEvidence: strings.Repeat("c", 64),
		Surface: "native", Items: []projections.ApplicationSecretBatchImportItem{
			{Name: "batch-import-erasure-subject/a", Sealed: []byte("sealed-a")},
			{Name: "other/b", Sealed: []byte("sealed-b")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	batch := store.ApplicationSecretImportBatch{
		TenantID: tenantA, EventID: "7bd2f615-651c-51f4-9c37-31a562b0e610",
		TenantEpoch: epoch, RequestBinding: strings.Repeat("b", 64),
		Payload: command,
		Actor:   &events.Actor{Subject: "import-operator"}, EventTime: time.Now().UTC(),
		Names: []string{"batch-import-erasure-subject/a", "other/b"},
	}
	if _, err := s.ClaimApplicationSecretImportBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	actorOnly := batch
	actorOnly.EventID = "7bd2f615-651c-51f4-9c37-31a562b0e611"
	actorOnly.RequestBinding = strings.Repeat("e", 64)
	actorOnly.Actor = &events.Actor{Subject: subject, Roles: []string{"operator"}}
	actorOnly.Names = []string{"unaffected/c", "unaffected/d"}
	actorOnly.Payload, err = json.Marshal(projections.ApplicationSecretBatchImport{
		TenantEpoch: epoch, IdempotencyKeyDigest: strings.Repeat("d", 64),
		RequestBinding: strings.Repeat("e", 64), CommandEvidence: strings.Repeat("f", 64),
		Surface: "native", Items: []projections.ApplicationSecretBatchImportItem{
			{Name: "unaffected/c", Sealed: []byte("sealed-c")},
			{Name: "unaffected/d", Sealed: []byte("sealed-d")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimApplicationSecretImportBatch(ctx, actorOnly); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM privacy_subject_erasure_preparations WHERE tenant_id = $1 AND operation_id = $2`, tenantA, "sha256:"+strings.Repeat("1", 64))
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM application_secret_import_batches WHERE tenant_id = $1 AND event_id = $2`, tenantA, batch.EventID)
		_, _ = s.SystemPool().Exec(context.Background(), `DELETE FROM application_secret_import_batches WHERE tenant_id = $1 AND event_id = $2`, tenantA, actorOnly.EventID)
	}()
	ref := privacy.SubjectRef(tenantA, subject)
	prepared, err := s.PreparePrivacySubjectErasure(ctx, tenantA, subject,
		store.PrivacySubjectErasurePreparation{
			PrivacySubjectErasure: store.PrivacySubjectErasure{
				TenantID: tenantA, SubjectRef: ref,
				RequestedByRef: privacy.SubjectRef(tenantA, "erasure-admin"),
				Reason:         "verified erasure", ErasedAt: time.Now().UTC(),
			},
			OperationID:        "sha256:" + strings.Repeat("1", 64),
			RequestBinding:     strings.Repeat("2", 64),
			EventID:            "sha256:" + strings.Repeat("3", 64),
			RewriteOperationID: "batch-import-erasure-rewrite",
			TargetGeneration:   "batch-import-erasure-generation",
			EventActor:         &events.Actor{Subject: privacy.Placeholder(privacy.SubjectRef(tenantA, "erasure-admin")), Roles: []string{"privacy-admin"}},
		})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Counts["application_secret_import_batches"] != 2 ||
		len(prepared.RecoveryFences) != 2 ||
		prepared.RecoveryFences[0] != (store.PrivacyRecoveryFenceDisposition{
			Kind:    store.PrivacyRecoveryFenceApplicationSecretImport,
			EventID: batch.EventID, Disposition: store.PrivacyRecoveryFenceDeleted,
		}) || prepared.RecoveryFences[1] != (store.PrivacyRecoveryFenceDisposition{
		Kind:    store.PrivacyRecoveryFenceApplicationSecretImport,
		EventID: actorOnly.EventID, Disposition: store.PrivacyRecoveryFencePseudonymized,
	}) {
		t.Fatalf("prepared import recovery disposition: %+v", prepared)
	}
	if _, err := s.GetApplicationSecretImportBatch(ctx, tenantA, batch.EventID); !store.IsNotFound(err) {
		t.Fatalf("raw pending import survived privacy preparation: %v", err)
	}
	rewritten, err := s.GetApplicationSecretImportBatch(ctx, tenantA, actorOnly.EventID)
	if err != nil || rewritten.Actor == nil || rewritten.Actor.Subject == subject ||
		!strings.HasPrefix(rewritten.Actor.Subject, "erased:") ||
		!strings.EqualFold(rewritten.Names[0], actorOnly.Names[0]) {
		t.Fatalf("actor-only batch did not retain pseudonymized recovery: actor=%+v err=%v", rewritten.Actor, err)
	}
}
