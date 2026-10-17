// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package intwire

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"errors"
	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// A root accepted by the served API must have an immutable source event. A
// PostgreSQL read-model rebuild cannot silently erase signer trust authority.
func TestAGIDRootAnchorRebuildsFromSourceEvent(t *testing.T) {
	h := newHarness(t, tenantRestart)
	eventID := delegation.RootAnchorEventID(h.tenant, "root-key")
	recorded, found, err := h.log.EventByID(h.ctx, eventID)
	if err != nil || !found {
		t.Fatalf("root source event: found=%t err=%v", found, err)
	}
	if recorded.TenantID != h.tenant || recorded.Type != delegation.TypeRootAnchorRegistered {
		t.Fatalf("root source event has wrong authority: %s %s", recorded.TenantID, recorded.Type)
	}
	before, err := agidstore.New(h.store).ListRootAnchors(h.ctx, h.tenant)
	if err != nil || len(before) != 1 {
		t.Fatalf("root before rebuild: count=%d err=%v", len(before), err)
	}
	if err := h.store.WithTenant(h.ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(h.ctx, `DELETE FROM agent_root_anchors WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	changed := generateSigner(t)
	if _, err := h.api.RegisterRootAnchor(h.ctx, h.tenant, agidapi.RootAnchorRequest{
		KeyID: "root-key", PublicDER: changed.Public().DER, AuthRef: "fido2:changed",
	}); !errors.Is(err, corestore.ErrIdempotencyConflict) {
		t.Fatalf("changed key after read-model loss = %v, want first-writer conflict", err)
	}
	if _, err := h.api.RegisterRootAnchor(h.ctx, h.tenant, agidapi.RootAnchorRequest{
		KeyID: before[0].KeyID, PublicDER: before[0].PublicDER, AuthRef: before[0].AuthRef,
	}); err != nil {
		t.Fatalf("exact retry after projection loss: %v", err)
	}
	if err := h.store.WithTenant(h.ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(h.ctx, `DELETE FROM agent_root_anchors WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(h.store, projections.WithEventProjection(agidstore.NewRootAnchorProjection(h.store)))
	if err := projector.Rebuild(h.ctx, h.log); err != nil {
		t.Fatalf("rebuild root read model: %v", err)
	}
	after, err := agidstore.New(h.store).ListRootAnchors(context.Background(), h.tenant)
	if err != nil || len(after) != 1 {
		t.Fatalf("root after rebuild: count=%d err=%v", len(after), err)
	}
	if before[0].KeyID != after[0].KeyID || before[0].AuthRef != after[0].AuthRef ||
		!bytes.Equal(before[0].PublicDER, after[0].PublicDER) {
		t.Fatal("event-only rebuild changed the exact root trust tuple")
	}
}

func TestAGIDLegacyRootRequiresExactSignerBeforeEventBackfill(t *testing.T) {
	h := newHarness(t, tenantHard)
	legacy := generateSigner(t)
	row := agidstore.RootAnchor{KeyID: "legacy-root", PublicDER: legacy.Public().DER, AuthRef: "fido2:legacy"}
	if err := agidstore.New(h.store).RegisterRootAnchor(h.ctx, h.tenant, row); err != nil {
		t.Fatal(err)
	}
	changed := generateSigner(t)
	if _, err := h.api.RegisterRootAnchor(h.ctx, h.tenant, agidapi.RootAnchorRequest{
		KeyID: row.KeyID, PublicDER: changed.Public().DER, AuthRef: "fido2:changed",
	}); !errors.Is(err, corestore.ErrIdempotencyConflict) {
		t.Fatalf("changed legacy root = %v, want pre-append first-writer conflict", err)
	}
	if _, found, err := h.log.EventByID(h.ctx, delegation.RootAnchorEventID(h.tenant, row.KeyID)); err != nil || found {
		t.Fatalf("rejected legacy conflict appended authority: found=%t err=%v", found, err)
	}
	if err := agidstore.BackfillLegacyRootAnchorEvents(h.ctx, h.store, h.log, nil); err == nil {
		t.Fatal("one-shot rebuild accepted SQL-only root without signer readback")
	}
	if err := agidstore.BackfillLegacyRootAnchorEvents(h.ctx, h.store, h.log, h.client); err == nil {
		t.Fatal("startup backfill accepted root absent from the isolated signer")
	}
	if err := h.client.ProvisionAgentRootAnchor(h.ctx, h.tenant, row.KeyID, row.PublicDER, row.AuthRef); err != nil {
		t.Fatal(err)
	}
	if err := agidstore.BackfillLegacyRootAnchorEvents(h.ctx, h.store, h.log, h.client); err != nil {
		t.Fatalf("signer-verified backfill: %v", err)
	}
	if err := agidstore.BackfillLegacyRootAnchorEvents(h.ctx, h.store, h.log, nil); err != nil {
		t.Fatalf("repeat one-shot preflight after canonical event: %v", err)
	}
	ev, found, err := h.log.EventByID(h.ctx, delegation.RootAnchorEventID(h.tenant, row.KeyID))
	if err != nil || !found || ev.Type != delegation.TypeRootAnchorRegistered {
		t.Fatalf("backfilled event: found=%t type=%s err=%v", found, ev.Type, err)
	}
}
