// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestCR277ServedSecretSyncRejectsRemotePathEscapeBeforeQueue(t *testing.T) {
	standIn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer standIn.Close()
	const token = "fake-cr277-token" // #nosec G101 -- fabricated fixture credential, never a real service token (CWE-798)
	registry, minter, err := secretSyncTargetsFromConfig(context.Background(), []config.SecretSyncTargetConfig{
		{TenantID: servedTestTenant, ID: "rundeck-cr277", Type: "rundeck", Endpoint: standIn.URL, AllowInsecureLoopback: true, TokenRef: writeServedCredentialFile(t, "rundeck-cr277", token), Binding: "folder keys/project"},
		{TenantID: servedTestTenant, ID: "ovh-cr277", Type: "ovh-secret-manager", Endpoint: standIn.URL, AllowInsecureLoopback: true, TokenRef: writeServedCredentialFile(t, "ovh-cr277", token), Binding: "okms aaaaaaaa-1111-4222-8333-444444444444"},
	}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(minter.Close)
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) { d.TenantSecretSyncTargets = registry })
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "cr277-operator", "secrets:write", "secrets:read")
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", operator, "cr277-secret", map[string]any{"name": "cr277/source", "value": "fake-value"}); status != http.StatusCreated {
		t.Fatalf("create fixture secret = HTTP %d", status)
	}
	for _, target := range []string{"rundeck-cr277", "ovh-cr277"} {
		for _, remote := range []string{"../outside", "project/../../outside"} {
			request := map[string]any{"name": "cr277/source", "target": target, "remote_key": remote}
			status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/syncs/preview", operator, request)
			if status == http.StatusOK && strings.Contains(string(body), `"ready":true`) {
				t.Errorf("%s preview marked unsafe key %q ready", target, remote)
			}
			status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", operator, "cr277-"+target+"-"+remote, request)
			if status != http.StatusBadRequest {
				t.Errorf("%s execute unsafe key %q = HTTP %d; want 400", target, remote, status)
			}
		}
	}
	if h.hasEvent(t, "secret.sync.queued") {
		t.Fatal("unsafe remote key reached the immutable secret-sync event log")
	}
}
