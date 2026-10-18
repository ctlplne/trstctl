// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"testing"

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
