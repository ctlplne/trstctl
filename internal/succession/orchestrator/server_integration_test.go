// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"testing"

	pcasstore "trstctl.com/trstctl/internal/succession/store"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/orchestrator"
)

// TestINT04_LicensedOutboxFactory_DrivesMint proves the server-registration path
// (INT-04): the PCAS licensed-outbox handler — built via the factory the control-plane
// attach seam registers with the signer client as the minter — routes a
// pcas.succession-request message to a real mint over the signer transport, recorded
// and high-water advanced, over real Postgres. This is the production caller for the
// INT-03 worker (the same path the running server drives on a queued request).
func TestINT04_LicensedOutboxFactory_DrivesMint(t *testing.T) {
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	client := serveProductionSigner(t)
	const id = "spiffe://d/int04"
	if _, err := client.GenerateKeyHandle(ctx, crypto.ECDSAP256, succession.KeyHandle(id, 0)); err != nil {
		t.Fatalf("onboard genesis: %v", err)
	}

	// Build the handler exactly as internal/server does: the out-of-process signer
	// client is the succession minter.
	h, err := orchestrator.NewLicensedOutboxFactory()(editionseam.LicensedOutboxDeps{Store: cs, Minter: client})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// A pcas.succession-request message is handled -> a real record appears.
	handled, err := h.DeliverLicensed(ctx, coreorch.Message{
		Destination: orchestrator.RequestDestination, TenantID: tenantA,
		Payload: reqPayload("req-int04", id, crypto.ECDSAP384),
	})
	if !handled || err != nil {
		t.Fatalf("succession-request: handled=%v err=%v, want true,nil", handled, err)
	}
	assertRecord(t, cs, id, 1, 0)
	assertHighWater(t, cs, id, 1)

	// A pcas.rp-publish message is acknowledged (handled, no error).
	handled, err = h.DeliverLicensed(ctx, coreorch.Message{
		Destination: orchestrator.PublishDestination, TenantID: tenantA, Payload: []byte("{}"),
	})
	if !handled || err != nil {
		t.Fatalf("rp-publish: handled=%v err=%v, want true,nil", handled, err)
	}

	// A non-PCAS destination is NOT handled, so a composed handler can try the next.
	handled, err = h.DeliverLicensed(ctx, coreorch.Message{Destination: "other.thing", TenantID: tenantA})
	if handled || err != nil {
		t.Fatalf("foreign destination: handled=%v err=%v, want false,nil", handled, err)
	}
}

// TestINT04_FailsClosedWithoutSigner: the handler built with no minter (no
// out-of-process signer configured) fails closed on a succession request rather than
// silently succeeding.
func TestINT04_FailsClosedWithoutSigner(t *testing.T) {
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h, err := orchestrator.NewLicensedOutboxFactory()(editionseam.LicensedOutboxDeps{Store: cs, Minter: nil})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	handled, err := h.DeliverLicensed(ctx, coreorch.Message{
		Destination: orchestrator.RequestDestination, TenantID: tenantA,
		Payload: reqPayload("req-x", "spiffe://d/int04-nominter", crypto.ECDSAP384),
	})
	if !handled || err == nil {
		t.Fatalf("no-signer succession-request: handled=%v err=%v, want true + error (fail closed)", handled, err)
	}
}
