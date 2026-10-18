// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestCASignerHandleClaimFirstWriterAndOffboardTombstone(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "CA claim fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	const handle = "private-ca-signing-handle"
	const ceremonyA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const ceremonyB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if err := s.ClaimCASignerHandle(ctx, tenantA, ceremonyA, handle); err != nil {
		t.Fatalf("first tenant claim: %v", err)
	}
	if err := s.ClaimCASignerHandle(ctx, tenantA, ceremonyA, handle); err != nil {
		t.Fatalf("same ceremony retry: %v", err)
	}
	if err := s.ClaimCASignerHandle(ctx, tenantA, ceremonyB, handle); !errors.Is(err, store.ErrCASignerHandleClaimed) {
		t.Fatalf("same tenant, different ceremony = %v; want conflict", err)
	}
	if err := s.ClaimCASignerHandle(ctx, tenantB, ceremonyB, handle); !errors.Is(err, store.ErrCASignerHandleClaimed) {
		t.Fatalf("neighbor claim = %v; want conflict", err)
	}
	if _, err := s.OffboardTenant(ctx, tenantA); err != nil {
		t.Fatalf("offboard claim owner: %v", err)
	}
	if err := s.ClaimCASignerHandle(ctx, tenantB, ceremonyB, handle); !errors.Is(err, store.ErrCASignerHandleClaimed) {
		t.Fatalf("neighbor claim after owner offboard = %v; want permanent denial", err)
	}
	const claimPartition = "00000000-0000-0000-0000-000000000003"
	var owner *string
	var state string
	if err := s.SystemPool().QueryRow(ctx, `SELECT owner_tenant_id::text, state FROM ca_signer_handle_claims
		 WHERE tenant_id = $1`, claimPartition).Scan(&owner, &state); err != nil {
		t.Fatalf("read offboard tombstone: %v", err)
	}
	if owner != nil || state != "retired" {
		t.Fatalf("offboard claim owner=%v state=%q; want scrubbed permanent tombstone", owner, state)
	}
}

func TestCASignerPreparationFirstWriterAndOffboardScrub(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "CSR preparation fixture"}); err != nil {
		t.Fatal(err)
	}
	const ceremonyID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const handle = "ca-hierarchy-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if err := s.ClaimCASignerHandle(ctx, tenantA, ceremonyID, handle); err != nil {
		t.Fatal(err)
	}
	first := store.CASignerPreparation{
		TenantID: tenantA, CeremonyID: ceremonyID, Handle: handle,
		IssuerSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Purpose:      "prepare-existing-ca:reviewed", CSRPEM: "public CSR first",
		EventID:      "ca-existing-import-csr-" + ceremonyID,
		EventTime:    time.Now().UTC().Truncate(time.Microsecond),
		EventActor:   []byte(`{"subject":"operator","roles":["admin"]}`),
		EventPayload: []byte(`{"csr_sha256":"first"}`),
	}
	reserved, err := s.ReserveCASignerPreparation(ctx, first)
	if err != nil || reserved.Handle != handle || reserved.CSRPEM != first.CSRPEM || reserved.Status != "pending" {
		t.Fatalf("first reservation = %+v, %v", reserved, err)
	}
	retry := first
	retry.CSRPEM = "public CSR different ECDSA signature"
	retry.EventPayload = []byte(`{"csr_sha256":"second"}`)
	recovered, err := s.ReserveCASignerPreparation(ctx, retry)
	if err != nil || recovered.CSRPEM != first.CSRPEM || string(recovered.EventPayload) != string(first.EventPayload) {
		t.Fatalf("concurrent retry replaced the first response/event: %+v, %v", recovered, err)
	}
	if err := s.CompleteCASignerPreparation(ctx, reserved); err != nil {
		t.Fatalf("complete first event: %v", err)
	}
	readback, err := s.GetCASignerPreparation(ctx, tenantA, ceremonyID, handle)
	if err != nil || readback.Status != "completed" || readback.CSRPEM != first.CSRPEM {
		t.Fatalf("durable readback = %+v, %v", readback, err)
	}
	if _, err := s.ReserveCASignerPreparation(ctx, store.CASignerPreparation{
		TenantID: tenantA, CeremonyID: ceremonyID, Handle: handle,
		IssuerSHA256: first.IssuerSHA256, Purpose: "different review", CSRPEM: first.CSRPEM,
		EventID: first.EventID, EventTime: first.EventTime,
		EventActor: first.EventActor, EventPayload: first.EventPayload,
	}); !errors.Is(err, store.ErrCASignerHandleClaimed) {
		t.Fatalf("different reviewed purpose = %v; want first-writer refusal", err)
	}
	if _, err := s.OffboardTenant(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	const partition = "00000000-0000-0000-0000-000000000003"
	var csr *string
	if err := s.SystemPool().QueryRow(ctx, `SELECT preparation_csr_pem FROM ca_signer_handle_claims
		 WHERE tenant_id = $1`, partition).Scan(&csr); err != nil {
		t.Fatal(err)
	}
	if csr != nil {
		t.Fatalf("offboard retained public CSR receipt in global fence")
	}
}
