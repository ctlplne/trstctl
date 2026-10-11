// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	configpkg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// The stock Vault CLI supplies X-Vault-Token but no custom idempotency header.
// A retry must not append twice, while a later disable/re-enable cycle must
// remain a fresh operator intent, including after the projection is rebuilt.
func TestVaultStockCLIMountAndPolicyLifecycle(t *testing.T) {
	ctx := context.Background()
	storeDir := t.TempDir()
	log, err := events.Open(ctx, configpkg.NATS{Mode: configpkg.NATSEmbedded, StoreDir: storeDir, SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	newHandler := func() *API {
		return New(nil, orchestrator.NewMemoryIdempotency(), nil, WithInsecureHeaderResolver(), WithEventLog(log))
	}
	coldRestart := func() *API {
		t.Helper()
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		log, err = events.Open(ctx, configpkg.NATS{Mode: configpkg.NATSEmbedded, StoreDir: storeDir, SyncAlways: true})
		if err != nil {
			t.Fatal(err)
		}
		return newHandler()
	}
	handler := newHandler()
	request := func(method, path string, body any, want int) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("X-Tenant-ID", vaultCompleteTenantA)
		req.Header.Set("X-Subject", "operator")
		req.Header.Set("X-Roles", "admin")
		req.Header.Set("X-Vault-Token", "trst_disposable_stock_cli_test")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, res.Code, want, res.Body.String())
		}
	}
	count := func(eventType string) int {
		t.Helper()
		head, err := log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if head == 0 {
			return 0
		}
		n := 0
		if err := log.ReplayTenantTypesThrough(ctx, vaultCompleteTenantA, 1, head, []string{eventType}, func(events.Event) error {
			n++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	mount := "/v1/sys/mounts/qa-stock-lifecycle"
	configuration := map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}
	request(http.MethodPost, mount, configuration, http.StatusNoContent)
	request(http.MethodPost, mount, configuration, http.StatusNoContent)
	first, err := handler.vaultCompat.snapshot(ctx, vaultCompleteTenantA)
	if err != nil {
		t.Fatal(err)
	}
	firstName, err := vaultKVStoreNameForGeneration(first.mounts["qa-stock-lifecycle"], first.mountEpochs["qa-stock-lifecycle"], "retained-check")
	if err != nil {
		t.Fatal(err)
	}
	if got := count(vaultMountEnabledEventType); got != 1 {
		t.Fatalf("mount enables after retry = %d, want 1", got)
	}
	request(http.MethodDelete, mount, nil, http.StatusNoContent)
	request(http.MethodDelete, mount, nil, http.StatusNoContent)
	if got := count(vaultMountDisabledEventType); got != 1 {
		t.Fatalf("mount disables after retry = %d, want 1", got)
	}
	handler = coldRestart()
	request(http.MethodPost, mount, configuration, http.StatusNoContent)
	second, err := handler.vaultCompat.snapshot(ctx, vaultCompleteTenantA)
	if err != nil {
		t.Fatal(err)
	}
	secondName, err := vaultKVStoreNameForGeneration(second.mounts["qa-stock-lifecycle"], second.mountEpochs["qa-stock-lifecycle"], "retained-check")
	if err != nil || firstName == secondName {
		t.Fatalf("re-enabled mount reused predecessor's KV name: first=%q second=%q err=%v", firstName, secondName, err)
	}
	legacyName, err := vaultKVStoreNameForGeneration(vaultCompatMount{Path: "legacy", Type: "kv"}, "", "retained-check")
	if err != nil || legacyName != "legacy/retained-check" {
		t.Fatalf("legacy active mount mapping = %q, %v", legacyName, err)
	}
	if got := count(vaultMountEnabledEventType); got != 2 {
		t.Fatalf("mount enables after cold re-enable = %d, want 2", got)
	}
	policy := "/v1/sys/policies/acl/qa-stock-lifecycle"
	definition := map[string]any{"policy": `path "secret/data/*" { capabilities = ["read"] }`}
	request(http.MethodPut, policy, definition, http.StatusNoContent)
	request(http.MethodPut, policy, definition, http.StatusNoContent)
	if got := count(vaultPolicyPutEventType); got != 1 {
		t.Fatalf("policy puts after retry = %d, want 1", got)
	}
	request(http.MethodDelete, policy, nil, http.StatusNoContent)
	request(http.MethodDelete, policy, nil, http.StatusNoContent)
	if got := count(vaultPolicyDeletedEventType); got != 1 {
		t.Fatalf("policy deletes after retry = %d, want 1", got)
	}
	handler = coldRestart()
	replayedMount, err := handler.vaultCompat.snapshot(ctx, vaultCompleteTenantA)
	if err != nil {
		t.Fatal(err)
	}
	replayedName, err := vaultKVStoreNameForGeneration(replayedMount.mounts["qa-stock-lifecycle"], replayedMount.mountEpochs["qa-stock-lifecycle"], "retained-check")
	if err != nil || replayedName != secondName {
		t.Fatalf("cold mount namespace changed: before=%q after=%q err=%v", secondName, replayedName, err)
	}
	request(http.MethodPut, policy, definition, http.StatusNoContent)
	if got := count(vaultPolicyPutEventType); got != 2 {
		t.Fatalf("policy puts after cold re-create = %d, want 2", got)
	}
}
