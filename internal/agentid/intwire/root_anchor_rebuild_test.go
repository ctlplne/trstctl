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

// A historical SQL row from the old control-plane-only registration path must
// not keep the entire product offline when the isolated signer has no floor.
// Preserve the observed tuple as an explicitly unprovisioned source fact, so a
// rebuild cannot silently discard its first-writer fence or claim authority.
func TestAGIDLegacySignerAbsentRecoversAsUnprovisionedSourceEvent(t *testing.T) {
	h := newHarness(t, tenantHard)
	legacy := generateSigner(t)
	row := agidstore.RootAnchor{KeyID: "legacy-unprovisioned", PublicDER: legacy.Public().DER, AuthRef: "fido2:legacy"}
	if err := agidstore.New(h.store).RegisterRootAnchor(h.ctx, h.tenant, row); err != nil {
		t.Fatal(err)
	}
	if err := agidstore.RecoverLegacyRootAnchorEvents(h.ctx, h.store, h.log, h.client); err != nil {
		t.Fatalf("startup recovery: %v", err)
	}
	orphan, found, err := h.log.EventByID(h.ctx, delegation.RootAnchorUnprovisionedEventID(h.tenant, row.KeyID))
	if err != nil || !found || orphan.Type != delegation.TypeRootAnchorUnprovisioned {
		t.Fatalf("unprovisioned source event: found=%t type=%s err=%v", found, orphan.Type, err)
	}
	if _, found, err := h.log.EventByID(h.ctx, delegation.RootAnchorEventID(h.tenant, row.KeyID)); err != nil || found {
		t.Fatalf("absent signer must not create registered authority: found=%t err=%v", found, err)
	}
	if err := agidstore.BackfillLegacyRootAnchorEvents(h.ctx, h.store, h.log, nil); err != nil {
		t.Fatalf("one-shot preflight after unprovisioned source event: %v", err)
	}
	projector := projections.New(h.store, projections.WithEventProjection(agidstore.NewRootAnchorProjection(h.store)))
	if err := projector.Rebuild(h.ctx, h.log); err != nil {
		t.Fatalf("rebuild unprovisioned legacy root: %v", err)
	}
	listed, err := h.api.ListRootAnchors(h.ctx, h.tenant)
	if err != nil {
		t.Fatalf("list replayed legacy roots: %v", err)
	}
	var observed *agidapi.RootAnchorResponse
	for i := range listed.Anchors {
		if listed.Anchors[i].KeyID == row.KeyID {
			observed = &listed.Anchors[i]
		}
	}
	if observed == nil || observed.Provisioned {
		t.Fatalf("replayed legacy root must remain visible but unprovisioned: found=%t", observed != nil)
	}
	if _, err := h.api.RegisterRootAnchor(h.ctx, h.tenant, agidapi.RootAnchorRequest{
		KeyID: row.KeyID, PublicDER: row.PublicDER, AuthRef: row.AuthRef,
	}); err != nil {
		t.Fatalf("explicit exact operator registration: %v", err)
	}
	listed, err = h.api.ListRootAnchors(h.ctx, h.tenant)
	if err != nil {
		t.Fatalf("list provisioned legacy roots: %v", err)
	}
	observed = nil
	for i := range listed.Anchors {
		if listed.Anchors[i].KeyID == row.KeyID {
			observed = &listed.Anchors[i]
		}
	}
	if observed == nil || !observed.Provisioned {
		t.Fatalf("explicit exact registration should provision signer: found=%t", observed != nil)
	}
}

type rootAnchorReadFunc func(context.Context, string, string) ([]byte, string, error)

func (f rootAnchorReadFunc) ReadAgentRootAnchor(ctx context.Context, tenantID, keyID string) ([]byte, string, error) {
	return f(ctx, tenantID, keyID)
}

func TestAGIDLegacyRecoveryNeverMasksSignerFailureOrDifferentTuple(t *testing.T) {
	h := newHarness(t, tenantHard)
	legacy := generateSigner(t)
	row := agidstore.RootAnchor{KeyID: "legacy-unverified", PublicDER: legacy.Public().DER, AuthRef: "fido2:legacy"}
	if err := agidstore.New(h.store).RegisterRootAnchor(h.ctx, h.tenant, row); err != nil {
		t.Fatal(err)
	}
	for name, reader := range map[string]rootAnchorReadFunc{
		"signer unavailable": func(context.Context, string, string) ([]byte, string, error) {
			return nil, "", errors.New("signer transport unavailable")
		},
		"different signer tuple": func(context.Context, string, string) ([]byte, string, error) {
			return generateSigner(t).Public().DER, row.AuthRef, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := agidstore.RecoverLegacyRootAnchorEvents(h.ctx, h.store, h.log, reader); err == nil {
				t.Fatal("legacy recovery accepted unverified signer authority")
			}
			if _, found, err := h.log.EventByID(h.ctx, delegation.RootAnchorUnprovisionedEventID(h.tenant, row.KeyID)); err != nil || found {
				t.Fatalf("unverified tuple emitted an unprovisioned event: found=%t err=%v", found, err)
			}
		})
	}
}

func TestAGIDLegacyUnprovisionedSignerLaterAppearsGetsVerifiedSourceEvent(t *testing.T) {
	h := newHarness(t, tenantHard)
	legacy := generateSigner(t)
	row := agidstore.RootAnchor{KeyID: "legacy-later-signer", PublicDER: legacy.Public().DER, AuthRef: "fido2:legacy"}
	if err := agidstore.New(h.store).RegisterRootAnchor(h.ctx, h.tenant, row); err != nil {
		t.Fatal(err)
	}
	if err := agidstore.RecoverLegacyRootAnchorEvents(h.ctx, h.store, h.log, h.client); err != nil {
		t.Fatalf("record signer-absent legacy tuple: %v", err)
	}
	if err := h.client.ProvisionAgentRootAnchor(h.ctx, h.tenant, row.KeyID, row.PublicDER, row.AuthRef); err != nil {
		t.Fatalf("exact signer provision: %v", err)
	}
	if err := agidstore.RecoverLegacyRootAnchorEvents(h.ctx, h.store, h.log, h.client); err != nil {
		t.Fatalf("reconcile signer-verified legacy tuple: %v", err)
	}
	registered, found, err := h.log.EventByID(h.ctx, delegation.RootAnchorEventID(h.tenant, row.KeyID))
	if err != nil || !found || registered.Type != delegation.TypeRootAnchorRegistered {
		t.Fatalf("verified source event: found=%t type=%s err=%v", found, registered.Type, err)
	}
}
