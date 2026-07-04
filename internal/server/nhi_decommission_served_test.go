// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedNHIDecommissionCAPGOV04EndToEnd proves CAP-GOV-04 is served: the
// product takes departure, vendor-termination, and inactivity signals over the
// real API, resolves tenant-local NHIs, then drives revoke/retire lifecycle
// events instead of leaving decommissioning as tenant/member offboarding docs.
func TestServedNHIDecommissionCAPGOV04EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "identities:read", "identities:write", "nhi:read")
	ctx := context.Background()

	alice, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerUser, Name: "Alice Departing", Email: "alice@example.test"})
	if err != nil {
		t.Fatalf("create departed owner: %v", err)
	}
	vendor, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerVendor, Name: "Acme SaaS", Email: "support@acme.example"})
	if err != nil {
		t.Fatalf("create vendor owner: %v", err)
	}
	service, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerService, Name: "Batch service", Email: "svc@example.test"})
	if err != nil {
		t.Fatalf("create service owner: %v", err)
	}

	seedIdentity := func(id, kind, name, ownerID, status string, attrs map[string]any) string {
		t.Helper()
		raw, err := json.Marshal(attrs)
		if err != nil {
			t.Fatalf("marshal attrs for %s: %v", id, err)
		}
		if err := h.store.UpsertIdentity(ctx, store.Identity{
			ID: id, TenantID: h.tenant, Kind: store.IdentityKind(kind), Name: name,
			OwnerID: ownerID, Status: status, Attributes: raw,
		}); err != nil {
			t.Fatalf("seed identity %s: %v", id, err)
		}
		return id
	}

	departureID := seedIdentity("11111111-1111-1111-1111-11111111d001", "api_key", "github-token-alice", alice.ID, "deployed", map[string]any{
		"human_owner":  "alice@example.test",
		"last_used_at": time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
	})
	vendorID := seedIdentity("11111111-1111-1111-1111-11111111d002", "secret", "acme-webhook-secret", vendor.ID, "issued", map[string]any{
		"vendor": "Acme SaaS",
	})
	staleID := seedIdentity("11111111-1111-1111-1111-11111111d003", "workload_identity", "old-batch-job", service.ID, "revoked", map[string]any{
		"last_seen_at": "2026-01-02T03:04:05Z",
	})
	_ = seedIdentity("11111111-1111-1111-1111-11111111d004", "workload_identity", "active-batch-job", service.ID, "deployed", map[string]any{
		"last_seen_at": time.Now().UTC().Format(time.RFC3339),
	})

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/nhi/decommission", tok, "cap-gov-04-decommission", map[string]any{
		"reason": "CAP-GOV-04 owner departure, vendor termination, and inactivity decommission",
		"signals": []map[string]any{
			{"type": "departure", "subject": "alice@example.test", "evidence_refs": []string{"hris:departure/alice"}},
			{"type": "vendor_term", "vendor_name": "Acme SaaS", "evidence_refs": []string{"vendor:termination/acme"}},
			{"type": "inactivity", "inactive_before": "2026-03-01T00:00:00Z", "evidence_refs": []string{"usage:last-seen-cutoff"}},
		},
	})
	if status != http.StatusOK {
		t.Fatalf("decommission NHIs: status %d body %s", status, body)
	}
	var got struct {
		Capability string   `json:"capability"`
		Coverage   []string `json:"coverage"`
		Summary    struct {
			TotalMatched int `json:"total_matched"`
			Revoked      int `json:"revoked"`
			Retired      int `json:"retired"`
			Skipped      int `json:"skipped"`
			Failed       int `json:"failed"`
		} `json:"summary"`
		Items []struct {
			IdentityID string   `json:"identity_id"`
			Name       string   `json:"name"`
			SignalType string   `json:"signal_type"`
			Action     string   `json:"action"`
			From       string   `json:"from"`
			To         string   `json:"to"`
			Evidence   []string `json:"evidence_refs"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode decommission response: %v (%s)", err, body)
	}
	if got.Capability != "CAP-GOV-04" {
		t.Fatalf("capability = %q, want CAP-GOV-04", got.Capability)
	}
	for _, want := range []string{"departure", "vendor_term", "inactivity", "revoke", "retire"} {
		if !containsString(got.Coverage, want) {
			t.Fatalf("coverage %v missing %q", got.Coverage, want)
		}
	}
	if got.Summary.TotalMatched != 3 || got.Summary.Revoked != 2 || got.Summary.Retired != 1 || got.Summary.Skipped != 0 || got.Summary.Failed != 0 {
		t.Fatalf("summary = %+v, want 3 matched / 2 revoked / 1 retired / 0 skipped / 0 failed", got.Summary)
	}
	wantActions := map[string]struct {
		signal string
		action string
		to     string
	}{
		departureID: {signal: "departure", action: "revoked", to: "revoked"},
		vendorID:    {signal: "vendor_term", action: "revoked", to: "revoked"},
		staleID:     {signal: "inactivity", action: "retired", to: "retired"},
	}
	for _, item := range got.Items {
		want, ok := wantActions[item.IdentityID]
		if !ok {
			t.Fatalf("unexpected decommission item %+v", item)
		}
		if item.SignalType != want.signal || item.Action != want.action || item.To != want.to || len(item.Evidence) == 0 {
			t.Fatalf("item %s = %+v, want signal/action/to/evidence %+v", item.IdentityID, item, want)
		}
		delete(wantActions, item.IdentityID)
	}
	if len(wantActions) != 0 {
		t.Fatalf("missing decommission items: %+v", wantActions)
	}

	for id, want := range map[string]string{departureID: "revoked", vendorID: "revoked", staleID: "retired"} {
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id, tok, nil)
		if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"`+want+`"`)) {
			t.Fatalf("identity %s after decommission = %d %s, want status %s", id, status, body, want)
		}
	}

	seen := map[string]int{}
	if err := h.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != h.tenant {
			return nil
		}
		switch ev.Type {
		case projections.EventIdentityRevoked, projections.EventIdentityRetired:
			seen[ev.Type]++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if seen[projections.EventIdentityRevoked] < 2 || seen[projections.EventIdentityRetired] < 1 {
		t.Fatalf("decommission did not emit expected lifecycle events: %+v", seen)
	}
}
