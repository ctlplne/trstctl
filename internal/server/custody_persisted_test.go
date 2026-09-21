// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Custody must be PERSISTED, not merely assigned (epic B5, re-audited).
//
// This test exists because B5 shipped without it and was wrong for it. The
// schema had four custody columns, the issuing code set them, the API served
// them, and the event that carries state from one to the other had no fields for
// them — so every certificate recorded blanks while three layers of the system
// agreed custody had been captured.
//
// The key_origin half surfaced while implementing B2, because B2's own claim
// depended on it. The other three surfaced only by going back and looking, which
// is the honest lesson: a test asserting a value was ASSIGNED cannot see this,
// and every test B5 had was that kind.
//
// So this one reads the database.

func TestCustodyReachesTheDatabaseAndNotJustTheStruct(t *testing.T) {
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)

	owner, err := h.store.CreateOwner(ctx, store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "P", Email: "custody@example.test",
	})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "custody.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issue"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}
	dispatchOutbox(t, h, 1)

	// Read through the store's own reader rather than raw SQL: it selects the
	// custody columns already, and using it means this test exercises the same
	// path the API serves from.
	certs := dispatcherCertificates(t, h)
	if len(certs) == 0 {
		t.Fatal("no certificate was recorded, so this test proves nothing about custody")
	}

	for _, c := range certs {
		r := struct{ origin, storage string }{c.KeyOrigin, c.KeyStorage}
		// This deployment has no CSR on record, so it takes the deprecated
		// server-keygen path — which is exactly the case an auditor most needs
		// recorded, because a credential on it is one to plan to replace.
		if r.origin != string(custody.OriginControlPlane) {
			t.Errorf("key_origin = %q, want %q", r.origin, custody.OriginControlPlane)
		}
		// First-issuance recovery retains the control-plane-generated key in
		// a tenant-bound encrypted record. Reporting only temporary memory
		// storage would hide that retained copy from the operator.
		if r.storage != string(custody.StorageSealedStore) {
			t.Errorf("key_storage = %q, want %q", r.storage, custody.StorageSealedStore)
		}
		// The generator returns and seals the private key for delivery. Its
		// exportability is known, so it must survive the event and projection
		// instead of appearing as an unanswered custody question.
		if c.KeyExportable != string(custody.Exportable) {
			t.Errorf("key_exportable = %q, want %q", c.KeyExportable, custody.Exportable)
		}
	}
}

// The event that carries custody must carry ALL of it.
//
// A structural check beside the behavioral one above, because the failure mode
// is a field added to the database and to the API and not to the event in
// between — and that gap is invisible from either end.
func TestTheCertificateEventCarriesEveryCustodyFieldTheRowHas(t *testing.T) {
	t.Parallel()
	// Every custody column the schema defines must have somewhere to travel.
	// Adding a column without a matching event field is the exact shape of the
	// defect this re-audit found, three times over.
	for _, field := range []string{"KeyOrigin", "KeyStorage", "KeyExportable", "KeyGeneratedBy"} {
		if !certificateRecordedCarries(field) {
			t.Errorf("projections.CertificateRecorded has no %s field, so any value the issuing "+
				"code sets for it is dropped at the projection boundary and the column stays "+
				"empty while the code, the schema and the API all agree it was recorded", field)
		}
	}
}

// certificateRecordedCarries reports whether the projection event has a field.
func certificateRecordedCarries(name string) bool {
	t := reflect.TypeOf(projections.CertificateRecorded{})
	_, ok := t.FieldByName(name)
	return ok
}
