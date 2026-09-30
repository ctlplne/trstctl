// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/shellca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedIdentityRevocationPreviewNamesUnsupportedRecordedExternalCA(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{
			{ID: "selected-shellca", Type: "shellca", Name: "Selected shell CA",
				CA: shellca.New(shellca.Config{Name: "Selected shell CA", Command: "/unused-in-preview"})},
			{ID: "selected-vault", Type: "vaultpki", Name: "Selected revocable CA",
				CA: revocationTestCA{revoke: func(context.Context, ca.RevokeRequest) error { return nil }}},
		}
	})
	ctx := t.Context()
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "Selected CA owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "selected-shellca.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"issuing_authority_source":"external","issuing_authority_id":"selected-shellca"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "test issuance"); err != nil {
		t.Fatal(err)
	}
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	fixture := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	certificate := recordRevocationTestLeaf(t, fixture, owner.ID, identity.Name, "selected-shellca", "preview-exact-issuer", "")
	if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
		IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "apache", Target: "preview-canary",
		Fingerprint: certificate.Fingerprint, Status: "verified", IdempotencyKey: "preview-shellca-deployed",
	}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "identities:write")
	before, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions/preview", token,
		map[string]any{"to": "revoked", "reason": "cessationOfOperation"})
	if status != http.StatusOK {
		t.Fatalf("preview status %d: %s", status, body)
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
	if preview.Ready || len(preview.Warnings) == 0 || !strings.Contains(strings.Join(preview.Warnings, " "), certificate.ID) ||
		!strings.Contains(strings.Join(preview.Warnings, " "), "issuing CA") {
		t.Fatalf("preview hid unsupported upstream revocation for exact certificate %s: %s", certificate.ID, body)
	}
	if len(preview.PreviewWrites) != 0 || len(preview.PreviewExternalEffects) != 0 {
		t.Fatalf("preview claimed an effect: %s", body)
	}
	after, err := h.log.LastSequence(ctx)
	if err != nil || after != before || eventCount(t, h.log, h.tenant, projections.EventIdentityRevoked) != 0 {
		t.Fatalf("preview changed event history: before=%d after=%d err=%v", before, after, err)
	}

	// A genuinely revocable external authority must remain ready. Otherwise a
	// blanket warning for every external certificate would hide the actual split.
	supported, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "selected-vault.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"issuing_authority_source":"external","issuing_authority_id":"selected-vault"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.Transition(ctx, h.tenant, supported.ID, orchestrator.StateIssued, "test supported issuance"); err != nil {
		t.Fatal(err)
	}
	supportedCert := recordRevocationTestLeaf(t, fixture, owner.ID, supported.Name, "selected-vault", "preview-supported-issuer", "")
	if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
		IdentityID: &supported.ID, Destination: "connector.deploy", Connector: "apache", Target: "supported-preview-canary",
		Fingerprint: supportedCert.Fingerprint, Status: "verified", IdempotencyKey: "preview-supported-deployed",
	}); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+supported.ID+"/transitions/preview", token,
		map[string]any{"to": "revoked", "reason": "cessationOfOperation"})
	if status != http.StatusOK || json.Unmarshal(body, &preview) != nil || !preview.Ready || len(preview.Warnings) != 0 {
		t.Fatalf("revocable recorded external CA was not ready: status=%d body=%s", status, body)
	}
}
