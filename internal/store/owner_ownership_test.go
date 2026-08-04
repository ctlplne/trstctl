// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// Ownership depth, and the distinction the whole queue rests on (epic I1).
//
// Empty means UNKNOWN, never "none". An estate that predates this model has
// owners nobody can retroactively classify, and treating blank as a deliberate
// answer would hide exactly the rows the unowned queue exists to surface.

func TestTheApplicationModelRoundTrips(t *testing.T) {
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)

	created, err := st.CreateOwner(ctx, store.Owner{
		TenantID: tenantID, Kind: store.OwnerTeam, Name: "Payments", Email: "pay@example.test",
		ApplicationID: "APP-1042", Service: "checkout", BusinessUnit: "Retail", Environment: "prod",
	})
	if err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	got, err := st.GetOwner(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("GetOwner: %v", err)
	}
	if got.ApplicationID != "APP-1042" || got.Service != "checkout" ||
		got.BusinessUnit != "Retail" || got.Environment != "prod" {
		t.Fatalf("application model did not round-trip: %+v", got)
	}
	if got.OwnershipAttested() {
		t.Error("a freshly created owner reports as attested; nobody has confirmed it yet, and " +
			"never-attested is a more urgent state than attested-long-ago")
	}
	if !got.OwnershipComplete() {
		t.Error("an owner with an application and an environment is not reported complete")
	}
}

// An attestation must survive an ordinary update. Losing it would move the owner
// back into the queue and train operators to click through a re-confirmation.
func TestAnAttestationIsNotErasedByAnOrdinaryUpdate(t *testing.T) {
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)

	attested := time.Now().UTC().Truncate(time.Second)
	created, err := st.CreateOwner(ctx, store.Owner{
		TenantID: tenantID, Kind: store.OwnerTeam, Name: "Payments", Email: "pay@example.test",
		ApplicationID: "APP-1", Environment: "prod",
	})
	if err != nil {
		t.Fatal(err)
	}
	created.OwnershipVerifiedAt = &attested
	if err := st.UpdateOwner(ctx, created); err != nil {
		t.Fatalf("attest: %v", err)
	}

	// A later edit that says nothing about attestation must not clear it.
	created.OwnershipVerifiedAt = nil
	created.Service = "checkout"
	if err := st.UpdateOwner(ctx, created); err != nil {
		t.Fatalf("edit: %v", err)
	}
	got, err := st.GetOwner(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.OwnershipAttested() {
		t.Fatal("an ordinary edit cleared the ownership attestation; the owner would silently " +
			"return to the unowned queue and be re-confirmed for no reason, which teaches " +
			"operators to click through it")
	}
}

// Empty is unknown, not none — and OwnershipComplete has to say so.
func TestABlankApplicationIsNotTreatedAsAnAnswer(t *testing.T) {
	t.Parallel()
	for _, o := range []store.Owner{
		{},
		{ApplicationID: "APP-1"},
		{Environment: "prod"},
		{ApplicationID: "   ", Environment: "prod"},
	} {
		if o.OwnershipComplete() {
			t.Errorf("%+v reported complete; a blank field is nobody having said, not somebody "+
				"saying none, and the queue is built on telling those apart", o)
		}
	}
}
