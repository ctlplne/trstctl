// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestCR195AttesterTrustWritesRequireIssuerAdministration(t *testing.T) {
	fixture := servedDynamicK8sTrustFixture(t, "cr195-k8s-key")
	h := newOperatingServedHarness(t, config.Protocols{})
	manager := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "issuers:write")
	issuer := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	issuerAdmin := seedScopedToken(t, h.store, h.tenant, "issuers:write")
	trust := map[string]any{
		"name": "cr195-original", "method": "k8s_sat",
		"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": fixture.JWKS,
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", manager, "cr195-seed", trust)
	if status != http.StatusCreated {
		t.Fatalf("issuer manager could not seed trust source: %d %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
		t.Fatalf("decode seeded trust source: id=%q err=%v", created.ID, err)
	}
	path := "/api/v1/workloads/attester-trust-sources/" + created.ID
	for _, tc := range []struct {
		name, method, path, key string
		body                    any
	}{
		{"create", http.MethodPost, "/api/v1/workloads/attester-trust-sources", "cr195-issue-create", map[string]any{
			"name": "cr195-unauthorized", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": fixture.JWKS,
		}},
		{"replace", http.MethodPut, path, "cr195-issue-replace", trust},
		{"rotate", http.MethodPost, path + "/rotate", "cr195-issue-rotate", map[string]any{
			"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": fixture.JWKS, "reason": "key rollover",
		}},
		{"revoke", http.MethodPost, path + "/revoke", "cr195-issue-revoke", map[string]any{"reason": "operator review"}},
		{"delete", http.MethodDelete, path, "cr195-issue-delete", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			status, body := secretsReqKey(t, h, tc.method, tc.path, issuer, tc.key, tc.body)
			if status != http.StatusForbidden {
				t.Errorf("certs:issue-only trust mutation = %d %s, want 403", status, body)
			}
			if err := h.log.Replay(t.Context(), before+1, func(event events.Event) error {
				if strings.HasPrefix(event.Type, "workload.attester_trust_source.") {
					t.Errorf("denied trust mutation appended %s", event.Type)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", issuerAdmin, "cr195-admin-create", map[string]any{
		"name": "cr195-issuer-admin", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": fixture.JWKS,
	})
	if status != http.StatusCreated {
		t.Errorf("issuers:write-only administrator could not create trust source: %d %s", status, body)
	}
}

func TestCR195HistoricalTrustRequiresIssuerAdminReview(t *testing.T) {
	fixture := servedDynamicK8sTrustFixture(t, "cr195-legacy-key")
	h := newOperatingServedHarness(t, config.Protocols{})
	const id = "00000000-0000-4000-8000-000000019500"
	jwks, err := json.Marshal(fixture.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.WorkloadAttesterTrustSourceUpserted{
		ID: id, Name: "cr195-legacy", Method: "k8s_sat",
		Issuer: "https://kubernetes.default.svc", Audience: "trstctl",
		JWKS: jwks, Enabled: true, RotationVersion: 1,
		// A historical schema version cannot claim approval by adding a field.
		IssuerAdminApproved: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{
		Type:     projections.EventWorkloadAttesterTrustSourceUpserted,
		TenantID: h.tenant, SchemaVersion: 1, Time: time.Now().UTC(), Data: payload,
	}); err != nil {
		t.Fatal(err)
	}
	catchUpServedProjection(t, h)
	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/workloads/attester-trust-sources/"+id, reader, nil)
	if status != http.StatusOK {
		t.Fatalf("read historical source: %d %s", status, body)
	}
	var source struct {
		Enabled             bool `json:"enabled"`
		ConfiguredEnabled   bool `json:"configured_enabled"`
		AdminReviewRequired bool `json:"admin_review_required"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	if source.Enabled || !source.ConfiguredEnabled || !source.AdminReviewRequired {
		t.Errorf("historical source lost configured enabled state or review flag: %s", body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/workloads/attester-trust-sources", reader, nil)
	if status != http.StatusOK {
		t.Fatalf("list historical source: %d %s", status, body)
	}
	var listed struct {
		Items []struct {
			ID                  string `json:"id"`
			Enabled             bool   `json:"enabled"`
			ConfiguredEnabled   bool   `json:"configured_enabled"`
			AdminReviewRequired bool   `json:"admin_review_required"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil || len(listed.Items) != 1 ||
		listed.Items[0].ID != id || listed.Items[0].Enabled || !listed.Items[0].ConfiguredEnabled ||
		!listed.Items[0].AdminReviewRequired {
		t.Fatalf("list lost configured enabled state or review flag: %s err=%v", body, err)
	}
	effective, err := h.store.GetEffectiveWorkloadAttesterTrustSource(t.Context(), h.tenant, id)
	if err != nil || effective.Enabled {
		t.Errorf("unreviewed historical source still authorizes proof: enabled=%t err=%v", effective.Enabled, err)
	}
	usable, err := h.store.ListEnabledWorkloadAttesterTrustSources(t.Context(), h.tenant, "k8s_sat")
	if err != nil || len(usable) != 0 {
		t.Errorf("unreviewed historical source reached verifier: %d usable, err=%v", len(usable), err)
	}
	admin := seedScopedToken(t, h.store, h.tenant, "issuers:write")
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/workloads/attester-trust-sources/"+id,
		admin, "cr195-approve-historical", map[string]any{
			"name": "cr195-legacy", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc",
			"audience": "trstctl", "jwks": fixture.JWKS,
		})
	if status != http.StatusOK {
		t.Fatalf("issuer administrator could not review historical source: %d %s", status, body)
	}
	if err := json.Unmarshal(body, &source); err != nil || !source.Enabled || !source.ConfiguredEnabled || source.AdminReviewRequired {
		t.Errorf("issuer review did not restore eligible trust: %s err=%v", body, err)
	}
	const disabledID = "00000000-0000-4000-8000-000000019501"
	disabledPayload, err := json.Marshal(projections.WorkloadAttesterTrustSourceUpserted{
		ID: disabledID, Name: "cr195-disabled", Method: "k8s_sat",
		Issuer: "https://kubernetes.default.svc", Audience: "trstctl",
		JWKS: jwks, Enabled: false, RotationVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{
		Type:     projections.EventWorkloadAttesterTrustSourceUpserted,
		TenantID: h.tenant, SchemaVersion: 1, Time: time.Now().UTC(), Data: disabledPayload,
	}); err != nil {
		t.Fatal(err)
	}
	catchUpServedProjection(t, h)
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/workloads/attester-trust-sources/"+disabledID, reader, nil)
	if status != http.StatusOK {
		t.Fatalf("read historical disabled source: %d %s", status, body)
	}
	if err := json.Unmarshal(body, &source); err != nil || source.Enabled || source.ConfiguredEnabled || !source.AdminReviewRequired {
		t.Fatalf("historical disabled source lost configured state: %s err=%v", body, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/workloads/attester-trust-sources/"+disabledID,
		admin, "cr195-review-disabled", map[string]any{
			"name": "cr195-disabled", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc",
			"audience": "trstctl", "jwks": fixture.JWKS, "enabled": false,
		})
	if status != http.StatusOK {
		t.Fatalf("issuer administrator could not review disabled source: %d %s", status, body)
	}
	if err := json.Unmarshal(body, &source); err != nil || source.Enabled || source.ConfiguredEnabled || source.AdminReviewRequired {
		t.Errorf("issuer review enabled a previously disabled source: %s err=%v", body, err)
	}
}
