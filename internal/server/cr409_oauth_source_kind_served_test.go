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

func TestServedCR409ManualSourceCannotQueueOAuthProviderAction(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:write", "connectors:write", "secrets:read")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "manual-grant-fixture", "kind": "manual",
		"config": map[string]any{"findings": []any{map[string]any{
			"kind": "oauth_grant", "ref": "manual/okta/fixture", "provenance": "fixture", "fingerprint": "manual-oauth-grant-fixture",
		}}, "providers": []any{map[string]any{
			"provider": "okta", "base_url": "https://idp.example.test", "token_ref": "secret://manual/provider-token",
		}}}, // #nosec G101 -- fabricated secret reference fixture, no credential value (CWE-798)
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("manual source with extra provider config = %d %s", status, body)
	}
	run, err := h.srv.orch.QueueDiscoveryRun(t.Context(), h.tenant, store.DiscoveryRun{SourceID: source.ID, RequestedBy: "fixture-operator"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.StartDiscoveryRun(t.Context(), h.tenant, run.ID); err != nil {
		t.Fatal(err)
	}
	finding, err := h.srv.orch.RecordDiscoveryFinding(t.Context(), h.tenant, store.DiscoveryFinding{
		RunID: run.ID, SourceID: source.ID, Kind: "oauth_grant", Ref: "manual/okta/fixture",
		Fingerprint: "manual-oauth-grant-fixture", Metadata: json.RawMessage(`{"provider":"okta","app_id":"0oa-fixture","principal":"00u-fixture"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	before := servedEventCount(t, h, projections.EventDiscoveryFindingProviderAction)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+finding.ID+"/oauth-grant/revoke", tok,
		"cr409-manual-revoke", map[string]any{"reason": "fixture"})
	if status != http.StatusConflict {
		t.Errorf("manual source OAuth action = %d %s, want 409", status, body)
	}
	if got := servedEventCount(t, h, projections.EventDiscoveryFindingProviderAction); got != before {
		t.Fatalf("rejected action entered event log: %d -> %d", before, got)
	}
	// A row queued before the admission repair must also fail when the worker
	// re-reads its source. A manual source cannot become an OAuth credential
	// connection merely because an older request is already in the outbox.
	if _, err := h.srv.orch.QueueOAuthProviderAction(t.Context(), h.tenant, "cr409-old-row", "fixture-operator",
		orchestrator.OAuthProviderActionIntent{FindingID: finding.ID, SourceID: source.ID,
			Action: orchestrator.OAuthActionRevokeGrant, Provider: "okta", AppID: "0oa-fixture", Principal: "00u-fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	updated, err := h.store.GetDiscoveryFinding(t.Context(), h.tenant, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		ProviderActions map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"provider_actions"`
	}
	if err := json.Unmarshal(updated.Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	action := meta.ProviderActions[orchestrator.OAuthActionRevokeGrant]
	if action.Status != orchestrator.OAuthActionFailed || !strings.Contains(action.Detail, "does not own an OAuth grant admin connection") {
		t.Fatalf("old manual-source row was not denied at execution: status=%q detail=%q", action.Status, action.Detail)
	}
}

func TestServedCR394RejectsRawDiscoveryProviderReference(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:write")
	before := servedEventCount(t, h, projections.EventDiscoverySourceUpserted)
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "manual-raw-provider-fixture", "kind": "manual",
		"config": map[string]any{"findings": []any{map[string]any{
			"kind": "oauth_grant", "ref": "manual/okta/fixture", "provenance": "fixture", "fingerprint": "manual-oauth-grant-fixture",
		}}, "providers": []any{map[string]any{
			"provider": "okta", "base_url": "https://idp.example.test", "token_ref": "raw-reference-fixture",
		}}}, // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
	})
	if status != http.StatusBadRequest {
		t.Errorf("raw discovery provider reference = %d %s, want 400", status, body)
	}
	if got := servedEventCount(t, h, projections.EventDiscoverySourceUpserted); got != before {
		t.Fatalf("raw discovery reference entered source event log: %d -> %d", before, got)
	}
}
