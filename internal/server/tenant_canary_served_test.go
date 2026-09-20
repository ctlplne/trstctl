// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedTenantCrossSurfaceCanaryTENANT003 is the live two-tenant served API
// canary for TENANT-003. Tenant B owns real graph, audit, semantic-query, profile,
// secret, and notification-channel records. A tenant A bearer principal probes the
// tenant B identifiers through the assembled HTTP handler and must see only scoped
// empty/not-found/catalog responses, never tenant B's names, IDs, endpoint, or value.
func TestServedTenantCrossSurfaceCanaryTENANT003(t *testing.T) {
	const (
		tenantB          = "22222222-2222-2222-2222-222222222222"
		bBootstrapName   = "tenant-b-bootstrap-canary"
		bOwnerName       = "tenant-b-graph-canary"
		bProfileName     = "tenant-b-profile-canary"
		bSecretName      = "tenant-b-secret-canary"
		bSecretValue     = "tenant-b-private-value-canary"
		bChannelLabel    = "tenant-b-webhook-canary"
		bChannelEndpoint = "https://tenant-b-notifications.example.test/hook"
	)

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), withAIEnabled())
	registerServedTenantID(t, h, tenantB, "tenant B cross-surface canary")

	if _, err := h.store.CreateOwner(context.Background(), store.Owner{
		TenantID: tenantB,
		Kind:     store.OwnerWorkload,
		Name:     bBootstrapName,
	}); err != nil {
		t.Fatalf("seed tenant B bootstrap owner: %v", err)
	}

	tenantBWriteToken := seedScopedToken(t, h.store, tenantB,
		string(authz.OwnersWrite),
		string(authz.ProfilesRead), string(authz.ProfilesWrite),
		string(authz.SecretsRead), string(authz.SecretsWrite),
		string(authz.NotificationsRead), string(authz.NotificationsWrite),
	)
	tenantAReadToken := seedScopedToken(t, h.store, h.tenant,
		string(authz.GraphRead), string(authz.OwnersRead), string(authz.AuditRead),
		string(authz.ProfilesRead), string(authz.SecretsRead), string(authz.NotificationsRead),
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tenantBWriteToken, map[string]any{
		"kind": "workload",
		"name": bOwnerName,
	})
	if status != http.StatusCreated {
		t.Fatalf("tenant B create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode tenant B owner: %v (%s)", err, body)
	}
	if owner.ID == "" {
		t.Fatalf("tenant B owner response missing id: %s", body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", tenantBWriteToken, "tenant-003-b-profile", map[string]any{
		"name": bProfileName,
		"spec": map[string]any{
			"allowed_key_algorithms": []string{"ECDSA"},
			"allowed_protocols":      []string{"acme"},
			"max_validity":           "720h",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("tenant B create profile: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tenantBWriteToken, map[string]any{
		"name":  bSecretName,
		"value": bSecretValue,
	})
	if status != http.StatusCreated {
		t.Fatalf("tenant B create secret: status %d body %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels", tenantBWriteToken, "tenant-003-b-channel", map[string]any{
		"id":           "webhook",
		"channel_type": "webhook",
		"label":        bChannelLabel,
		"endpoint_url": bChannelEndpoint,
		"enabled":      true,
	})
	if status != http.StatusCreated {
		t.Fatalf("tenant B create notification channel: status %d body %s", status, body)
	}

	forbidden := []string{
		tenantB,
		bBootstrapName,
		bOwnerName,
		owner.ID,
		bProfileName,
		bSecretName,
		bSecretValue,
		bChannelLabel,
		bChannelEndpoint,
	}

	graphNodeID := "wl:" + owner.ID
	tenantAProbe(t, h, tenantAReadToken, http.MethodGet, "/api/v1/graph", nil, http.StatusOK, forbidden)
	tenantAProbe(t, h, tenantAReadToken, http.MethodGet, "/api/v1/graph/reachable/"+url.PathEscape(graphNodeID), nil, http.StatusNotFound, forbidden)
	tenantAProbe(t, h, tenantAReadToken, http.MethodGet, "/api/v1/audit/events?q="+url.QueryEscape(bOwnerName), nil, http.StatusOK, forbidden)
	tenantAProbe(t, h, tenantAReadToken, http.MethodPost, "/api/v1/ai/query", map[string]any{
		"surfaces": []string{"owners", "graph", "log"},
		"subject":  bOwnerName,
		"question": "find the tenant B canary owner",
	}, http.StatusOK, forbidden)
	tenantAProbe(t, h, tenantAReadToken, http.MethodGet, "/api/v1/profiles/"+url.PathEscape(bProfileName)+"/versions/1", nil, http.StatusNotFound, forbidden)
	tenantAProbe(t, h, tenantAReadToken, http.MethodGet, "/api/v1/secrets/store/"+url.PathEscape(bSecretName), nil, http.StatusNotFound, forbidden)
	tenantAProbe(t, h, tenantAReadToken, http.MethodGet, "/api/v1/notification-channels/webhook", nil, http.StatusOK, forbidden)
	tenantAProbe(t, h, tenantAReadToken, http.MethodGet, "/api/v1/notification-channels", nil, http.StatusOK, forbidden)
}

func tenantAProbe(t *testing.T, h *servedHarness, token, method, path string, request any, wantStatus int, forbidden []string) {
	t.Helper()
	status, body := secretsReq(t, h, method, path, token, request)
	if status != wantStatus {
		t.Fatalf("%s %s: status %d body %s, want %d", method, path, status, body, wantStatus)
	}
	text := string(body)
	for _, marker := range forbidden {
		if marker != "" && strings.Contains(text, marker) {
			t.Fatalf("%s %s leaked tenant B marker %q in response: %s", method, path, marker, body)
		}
	}
}
