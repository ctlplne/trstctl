// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package intwire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// A150: an attestor registered through the API is held by the separate signer
// process, keeps its first writer, survives a signer restart and a read-model
// rebuild, and the restarted signer verifies attested issuance against it.
func TestAGIDAttestorThroughSignerSurvivesRestartAndRebuild(t *testing.T) {
	h := newHarness(t, tenantRestart)
	listed, err := h.api.ListAttestors(h.ctx, h.tenant)
	if err != nil || listed.Count != 1 {
		t.Fatalf("attestors after registration: %+v, %v", listed, err)
	}
	got := listed.Attestors[0]
	if got.KeyID != "attestor-1" || got.Method != "software" || got.Class != "software" || !got.Provisioned ||
		!bytes.Equal(got.PublicDER, h.attestor.Public().DER) {
		t.Fatalf("listed attestor = %+v", got)
	}
	if _, found, err := h.log.EventByID(h.ctx, delegation.AttestorEventID(h.tenant, "attestor-1")); err != nil || !found {
		t.Fatalf("attestor source event: found=%t err=%v", found, err)
	}

	other := generateSigner(t)
	if _, err := h.api.RegisterAttestor(h.ctx, h.tenant, agidapi.AttestorRequest{
		KeyID: "attestor-1", Method: "software", PublicDER: other.Public().DER,
	}); !errors.Is(err, corestore.ErrIdempotencyConflict) {
		t.Fatalf("changed attestor key = %v, want first-writer conflict", err)
	}
	if _, err := h.api.RegisterAttestor(h.ctx, h.tenant, agidapi.AttestorRequest{
		KeyID: "attestor-1", Method: "tpm", PublicDER: h.attestor.Public().DER,
	}); !errors.Is(err, corestore.ErrIdempotencyConflict) {
		t.Fatalf("changed attestor method = %v, want first-writer conflict", err)
	}
	if _, err := h.api.RegisterAttestor(h.ctx, h.tenant, agidapi.AttestorRequest{
		KeyID: "attestor-1", Method: "software", PublicDER: h.attestor.Public().DER,
	}); err != nil {
		t.Fatalf("exact retry: %v", err)
	}

	h.restartSigner(t)
	readDER, readMethod, err := h.client.ReadAgentAttestor(h.ctx, h.tenant, "attestor-1")
	if err != nil || !bytes.Equal(readDER, h.attestor.Public().DER) || readMethod != "software" {
		t.Fatalf("restarted signer readback: method=%q err=%v", readMethod, err)
	}
	h.issueAgent(t, "agent:after-signer-restart", "nonce-after-signer-restart")

	if err := h.store.WithTenant(h.ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(h.ctx, `DELETE FROM agent_attestors WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(h.store, projections.WithEventProjection(agidstore.NewAttestorProjection(h.store)))
	if err := projector.Rebuild(h.ctx, h.log); err != nil {
		t.Fatalf("rebuild attestor read model: %v", err)
	}
	rebuilt, err := h.api.ListAttestors(h.ctx, h.tenant)
	if err != nil || rebuilt.Count != 1 || rebuilt.Attestors[0].Method != "software" || !rebuilt.Attestors[0].Provisioned ||
		!bytes.Equal(rebuilt.Attestors[0].PublicDER, h.attestor.Public().DER) {
		t.Fatalf("attestors after rebuild: %+v, %v", rebuilt, err)
	}
}
