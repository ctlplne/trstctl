// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A stale attestation can already be durable after a preceding owner edit or
// deletion. It must grant no authority and must not stop the shared log tail.
func TestStaleOwnershipAttestationIsReplayableNoop(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedAgentJobTenant(t, ctx, st, tenantA)
	owner, err := st.CreateOwner(ctx, store.Owner{
		TenantID: tenantA, Kind: store.OwnerTeam, Name: "Payments",
		ApplicationID: "APP-1", Environment: "prod",
	})
	if err != nil {
		t.Fatal(err)
	}
	staleDigest, err := store.OwnerModelDigest(owner)
	if err != nil {
		t.Fatal(err)
	}
	owner.ApplicationID = "APP-2"
	if err := st.UpdateOwner(ctx, owner); err != nil {
		t.Fatal(err)
	}
	apply := func() error {
		return st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return st.ApplyOwnershipAttestedTx(ctx, tx, tenantA, owner.ID, "operator@example.test", staleDigest, time.Now().UTC())
		})
	}
	if err := apply(); err != nil {
		t.Fatalf("stale model attestation blocked replay: %v", err)
	}
	got, err := st.GetOwner(ctx, tenantA, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.OwnershipAttested() {
		t.Fatal("stale digest granted ownership authority")
	}
	currentDigest, err := store.OwnerModelDigest(got)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyOwnershipAttestedTx(ctx, tx, tenantA, owner.ID, "operator@example.test", currentDigest, time.Now().UTC())
	}); err != nil {
		t.Fatalf("current model attestation was refused: %v", err)
	}
	got, err = st.GetOwner(ctx, tenantA, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.OwnershipAttested() {
		t.Fatal("current model attestation did not grant ownership authority")
	}
	if err := st.DeleteOwner(ctx, tenantA, owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatalf("deleted owner attestation blocked replay: %v", err)
	}
}
