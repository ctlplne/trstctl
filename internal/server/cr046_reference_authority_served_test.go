// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
)

func TestCR046NotifierCannotSelectOrRepointAnotherPrincipalsSecret(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	h.srv.notifications.SetChannelResolver(notify.NewStoreChannelResolver(h.store))
	owner := seedScopedTokenSubject(t, h.store, h.tenant, "cr046-owner", "secrets:read", "secrets:write", "notifications:read", "notifications:write")
	notifier := seedScopedTokenSubject(t, h.store, h.tenant, "cr046-notifier", "notifications:read", "notifications:write")
	const ref = "secret://cr046/alerts/token"
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", owner,
		map[string]any{"name": "cr046/alerts/token", "value": "fixture"}); status != http.StatusCreated {
		t.Fatalf("store test secret: HTTP %d %s", status, body)
	}
	channel := func(endpoint string) map[string]any {
		return map[string]any{"id": "webhook", "channel_type": "webhook", "label": "CR-046 alerts",
			"endpoint_url": endpoint, "credential_ref": ref, "enabled": true}
	}
	first := "https://notifications.example.test/owner"
	second := "https://notifications.example.test/repointed"
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/notification-channels", notifier, channel(second)); status != http.StatusForbidden {
		t.Fatalf("notifier selected unreadable secret: HTTP %d %s, want 403", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/notification-channels", owner, channel(first)); status != http.StatusCreated {
		t.Fatalf("owner created channel: HTTP %d %s, want 201", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/notification-channels/webhook", notifier, channel(second)); status != http.StatusForbidden {
		t.Fatalf("notifier repointed owner's secret: HTTP %d %s, want 403", status, body)
	}
	stored, err := h.store.GetNotificationChannel(context.Background(), h.tenant, "webhook")
	if err != nil || stored.EndpointURL != first {
		t.Fatalf("channel destination changed after refused repoint: endpoint=%q err=%v", stored.EndpointURL, err)
	}
}
