// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedOrdinaryKeyCompromiseRefusesServingX509BeforeApprovalOrEvent(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "serving-compromise-guard")
	ctx := t.Context()
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "compromise owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "compromised.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed} {
		if err := h.srv.orch.Transition(ctx, h.tenant, identity.ID, to, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	token := seedScopedToken(t, h.store, h.tenant, "identities:write", "identities:read")
	path := "/api/v1/identities/" + identity.ID + "/transitions"
	before, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, version, err := h.store.IdentityApprovalTarget(ctx, h.tenant, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReq(t, h, http.MethodPost, path+"/preview", token,
		map[string]any{"to": "revoked", "reason": "keyCompromise"})
	if status != http.StatusOK {
		t.Fatalf("ordinary compromise preview status %d: %s", status, body)
	}
	var preview struct {
		Ready                  bool     `json:"ready"`
		Warnings               []string `json:"warnings"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Ready || !strings.Contains(strings.Join(preview.Warnings, " "), "host containment") ||
		len(preview.PreviewWrites) != 0 || len(preview.PreviewExternalEffects) != 0 {
		t.Fatalf("ordinary preview advertised incomplete incident as ready: %s", body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path, token,
		"ordinary-compromise-must-refuse", map[string]any{
			"to": "revoked", "reason": "keyCompromise", "expected_version": version,
		})
	if status != http.StatusConflict || !strings.Contains(string(body), "host containment") ||
		!strings.Contains(string(body), "key_compromise_containment_required") ||
		!strings.Contains(string(body), "previewKeyCompromise") {
		t.Fatalf("ordinary compromise execution = %d %s, want actionable 409", status, body)
	}
	after, err := h.log.LastSequence(ctx)
	if err != nil || after != before || eventCount(t, h.log, h.tenant, projections.EventIdentityRevoked) != 0 {
		t.Fatalf("ordinary compromise changed event history: before=%d after=%d err=%v", before, after, err)
	}
	read, err := h.store.GetIdentity(ctx, h.tenant, identity.ID)
	if err != nil || read.Status != "deployed" {
		t.Fatalf("ordinary compromise changed serving identity: %+v %v", read, err)
	}
}
