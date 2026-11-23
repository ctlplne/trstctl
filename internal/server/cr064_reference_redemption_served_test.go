// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestCR064RemovedSecretMemberCannotRedeemRotatedNotificationCredential(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	sink := newFamilySink(t)
	h.srv.notificationTenantChannels.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() != "notifications.example.test" {
			return nil, errors.New("unexpected notification host")
		}
		localURL, err := url.Parse(sink.srv.URL + req.URL.Path)
		if err != nil {
			return nil, err
		}
		local := req.Clone(req.Context())
		local.URL = localURL
		local.Host = localURL.Host
		return sink.srv.Client().Do(local)
	})})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "cr064-admin", "access:write", "secrets:read", "secrets:write", "notifications:read", "notifications:write")
	leaver := seedScopedTokenSubject(t, h.store, h.tenant, "cr064-leaver", "secrets:read", "secrets:write", "notifications:read", "notifications:write")
	stayer := seedScopedTokenSubject(t, h.store, h.tenant, "cr064-stayer", "secrets:read", "secrets:write", "notifications:read", "notifications:write")
	call := func(tok, method, path, key string, payload any, want int) {
		t.Helper()
		status, body := secretsReqKey(t, h, method, path, tok, key, payload)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, body, want)
		}
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", "cr064-project", map[string]any{"slug": "vault64", "environments": []any{map[string]any{"slug": "prod", "restricted": true}}}, http.StatusCreated)
	for _, subject := range []string{"cr064-leaver", "cr064-stayer"} {
		call(admin, http.MethodPut, "/api/v1/secrets/projects/vault64/members/"+subject, "cr064-member-"+subject,
			map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	}
	call(leaver, http.MethodPost, "/api/v1/secrets/store", "cr064-store", map[string]any{"name": "vault64/prod/token", "value": t.Name() + "-v1"}, http.StatusCreated)
	call(leaver, http.MethodPost, "/api/v1/notification-channels", "cr064-channel", map[string]any{
		"id": "siem", "channel_type": "siem", "label": "CR-064 SIEM", "endpoint_url": "https://notifications.example.test/siem",
		"credential_ref": "secret://vault64/prod/token", "enabled": true,
	}, http.StatusCreated)
	trigger := func(tok, key string) {
		t.Helper()
		call(tok, http.MethodPost, "/api/v1/notification-channels/siem/test", key,
			map[string]any{"subject": "CR-064", "severity": "critical"}, http.StatusAccepted)
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain notification: %v", err)
		}
	}
	deliveries := func() int {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.headers["/siem"])
	}
	trigger(leaver, "cr064-before-removal")
	if got := deliveries(); got != 1 {
		t.Fatalf("authorized channel delivered %d times, want one", got)
	}
	status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/projects/vault64/members/cr064-leaver", admin, "cr064-remove", nil)
	if status/100 != 2 {
		t.Fatalf("remove former configurer: HTTP %d %s", status, body)
	}
	call(stayer, http.MethodPut, "/api/v1/secrets/store/vault64/prod/token", "cr064-rotate", map[string]any{"value": t.Name() + "-v2"}, http.StatusOK)
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/vault64/prod/token", leaver, nil); status == http.StatusOK {
		t.Fatalf("removed member retained direct read: %s", body)
	}
	trigger(leaver, "cr064-after-removal")
	if got := deliveries(); got != 1 {
		t.Fatalf("removed configurer's channel delivered again after secret rotation: %d deliveries", got)
	}
	call(stayer, http.MethodPut, "/api/v1/notification-channels/siem", "cr064-reauthorize", map[string]any{
		"id": "siem", "channel_type": "siem", "label": "CR-064 SIEM", "endpoint_url": "https://notifications.example.test/siem",
		"credential_ref": "secret://vault64/prod/token", "enabled": true,
	}, http.StatusOK)
	trigger(stayer, "cr064-after-reauthorization")
	if got := deliveries(); got != 2 {
		t.Fatalf("currently authorized member could not restore channel delivery: %d deliveries", got)
	}
	tokens, err := h.store.ListAPITokensPage(context.Background(), h.tenant, "00000000-0000-0000-0000-000000000000", "cr064-stayer", false, 10)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("find current configurer's token: count=%d err=%v", len(tokens), err)
	}
	call(admin, http.MethodDelete, "/api/v1/access/api-tokens/"+tokens[0].ID, "cr064-revoke-read", nil, http.StatusNoContent)
	trigger(admin, "cr064-after-read-revocation")
	if got := deliveries(); got != 2 {
		t.Fatalf("channel delivered after configurer lost secrets:read: %d deliveries", got)
	}
}
