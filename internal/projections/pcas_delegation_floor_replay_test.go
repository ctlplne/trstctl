// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"math"
	"testing"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/delegation"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

func TestPCASHistoricalOverflowDoesNotStopOtherTenantCatchUpOrRebuild(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	st.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	log := openLog(t)
	for _, tenant := range []struct{ id, name string }{{tenantA, "Poisoned"}, {tenantB, "Healthy"}} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant.id, Data: tenantRegistered(tenant.name)}); err != nil {
			t.Fatal(err)
		}
	}
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	receipt := delegation.Receipt{Command: delegation.Command{TenantID: tenantA, OperationID: "old-overflow", Kind: "scope", ScopeID: "root", EpochFloor: uint64(math.MaxInt64) + 1}, AppliedFloor: uint64(math.MaxInt64) + 1}
	body, err := receipt.SignedBody()
	if err != nil {
		t.Fatal(err)
	}
	receipt.PublicKeyDER = key.Public().DER
	receipt.Signature, err = key.Sign(body, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	overflow, err := succession.Encode(succession.DelegationAppliedV1{TenantID: tenantA, ReceiptJSON: receiptJSON})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, overflow); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated(uuid.NewString(), "later healthy owner")}); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st, projections.WithEventProjection(pcasstore.NewDelegationProjection(st)))
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("historical PCAS floor blocked other tenant: %v", err)
	}
	if n := ownerCount(t, st, tenantB); n != 1 {
		t.Fatalf("healthy owner count = %d after catch-up", n)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("PCAS tenant quarantine=%v err=%v", quarantined, err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild blocked after signed historical floor: %v", err)
	}
	if n := ownerCount(t, st, tenantB); n != 1 {
		t.Fatalf("healthy owner count = %d after rebuild", n)
	}
}
