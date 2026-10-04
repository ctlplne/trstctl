// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/usage"
)

type secretQuotaProbe struct {
	refuse atomic.Bool
	broken atomic.Bool
	checks atomic.Int64
	fences atomic.Int64
}

func (p *secretQuotaProbe) AllowCreate(_ context.Context, _, resource string) error {
	if resource != usage.MeterSecretsStored {
		return nil
	}
	p.checks.Add(1)
	if p.broken.Load() {
		return fmt.Errorf("quota count unavailable: %w", usage.ErrQuotaUnavailable)
	}
	if p.refuse.Load() {
		return fmt.Errorf("stored secret cap reached: %w", usage.ErrQuotaExhausted)
	}
	return nil
}

func (p *secretQuotaProbe) WithCreationFence(ctx context.Context, _ string, resource string, fn func(context.Context) error) error {
	if resource == usage.MeterSecretsStored {
		p.fences.Add(1)
	}
	return fn(ctx)
}

func TestServedNativeAndVaultSecretFirstCreateRespectProviderQuota(t *testing.T) {
	quota := &secretQuotaProbe{}
	usage.SetQuotaChecker(quota)
	t.Cleanup(func() { usage.SetQuotaChecker(nil) })
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "stored-secret quota tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	vaultWrite := func(method, name, key, value string) (int, []byte) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"data": map[string]string{"password": value}})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(method, h.ts.URL+"/v1/secret/data/"+name, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		result, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, result
	}

	nativeBody := map[string]any{"name": "quota-native-existing", "value": "test-value-v1"}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		"quota-native-existing", nativeBody); status != http.StatusCreated {
		t.Fatalf("native initial create = %d: %s", status, body)
	}
	if status, body := vaultWrite(http.MethodPut, "quota-vault-existing", "quota-vault-existing", "test-value-v1"); status != http.StatusOK {
		t.Fatalf("Vault initial create = %d: %s", status, body)
	}
	quota.refuse.Store(true)

	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		"quota-native-refused", map[string]any{"name": "quota-native-refused", "value": "test-value"}); status != http.StatusTooManyRequests {
		t.Fatalf("native first create over cap = %d, want 429: %s", status, body)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		name := "quota-vault-refused-" + method
		if status, body := vaultWrite(method, name, "quota-vault-refused-"+method, "test-value"); status != http.StatusTooManyRequests {
			t.Fatalf("Vault %s first create over cap = %d, want 429: %s", method, status, body)
		}
		if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+name, token, nil); status != http.StatusNotFound {
			t.Fatalf("Vault %s refusal materialized secret = %d: %s", method, status, body)
		}
	}
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/quota-native-refused", token, nil); status != http.StatusNotFound {
		t.Fatalf("native refusal materialized secret = %d: %s", status, body)
	}
	if quota.checks.Load() < 5 || quota.fences.Load() < 5 {
		t.Fatalf("first-create quota seam not used for both surfaces: checks=%d fences=%d", quota.checks.Load(), quota.fences.Load())
	}

	// Lowering a cap blocks new stock, not maintenance or an exact AN-5 replay.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		"quota-native-existing", nativeBody); status != http.StatusCreated {
		t.Fatalf("exact retry after cap reduction = %d: %s", status, body)
	}
	if status, body := vaultWrite(http.MethodPut, "quota-vault-existing", "quota-vault-existing", "test-value-v1"); status != http.StatusOK {
		t.Fatalf("Vault exact retry after cap reduction = %d: %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/quota-native-existing", token,
		map[string]any{"value": "test-value-v2"}); status != http.StatusOK {
		t.Fatalf("native rotate under zero cap = %d: %s", status, body)
	}
	if status, body := vaultWrite(http.MethodPut, "quota-vault-existing", "quota-vault-rotate", "test-value-v2"); status != http.StatusOK {
		t.Fatalf("Vault rotate under zero cap = %d: %s", status, body)
	}
	for _, name := range []string{"quota-native-existing", "quota-vault-existing"} {
		if status, body := secretsReq(t, h, http.MethodDelete, "/api/v1/secrets/store/"+name, token, nil); status != http.StatusNoContent {
			t.Fatalf("delete %s under zero cap = %d: %s", name, status, body)
		}
	}

	quota.broken.Store(true)
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": "quota-counter-outage", "value": "test-value"}); status != http.StatusServiceUnavailable {
		t.Fatalf("quota count outage = %d, want retryable 503: %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/quota-counter-outage", token, nil); status != http.StatusNotFound {
		t.Fatalf("count outage materialized secret = %d: %s", status, body)
	}
}
