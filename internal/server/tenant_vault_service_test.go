// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// Never print response bodies here: a broken admission gate can return a key.
func tenantVaultRequest(t *testing.T, h *servedHarness, token, method, path, key string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, h.ts.URL+path, bytes.NewReader(raw))
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

func TestTenantVaultAdmissionRefusesMissingAndRestrictedService(t *testing.T) {
	for _, registered := range []bool{false, true} {
		name := "missing-registration"
		if registered {
			name = "restricted-existing-tenant"
		}
		t.Run(name, func(t *testing.T) {
			var state atomic.Int32
			h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
				d.TenantServiceCheck = func(context.Context, string) error {
					switch state.Load() {
					case 1:
						return tenancy.ErrServiceUnavailable
					case 2:
						return errors.New("private-authority-diagnostic")
					default:
						return nil
					}
				}
			})
			token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "policy:read", "policy:write", "keys:read", "keys:write")
			write := map[string]any{"data": map[string]string{"value": "tenant-vault-canary"}}
			if registered {
				registerServedTenant(t, h, "Vault service admission")
				if code, _ := tenantVaultRequest(t, h, token, http.MethodPost, "/v1/secret/data/service-check", "original-write", write); code != http.StatusOK {
					t.Fatalf("active write = %d", code)
				}
				if code, raw := tenantVaultRequest(t, h, token, http.MethodGet, "/v1/secret/data/service-check", "", nil); code != http.StatusOK || !bytes.Contains(raw, []byte("tenant-vault-canary")) {
					t.Fatalf("active read = %d, canary present=%t", code, bytes.Contains(raw, []byte("tenant-vault-canary")))
				}
			}
			cases := []struct {
				method, path, key string
				body              any
			}{
				{http.MethodGet, "/v1/auth/token/lookup-self", "", nil},
				{http.MethodGet, "/v1/secret/data/service-check", "", nil},
				{http.MethodPost, "/v1/secret/data/service-check", "original-write", write},
				{http.MethodPost, "/v1/secret/data/blocked-write", "new-write", write},
				{http.MethodPost, "/v1/pki/issue/default", "blocked-issue", map[string]any{"common_name": "blocked.example.test", "ttl": "15m"}},
				{http.MethodPut, "/v1/sys/policies/acl/blocked", "blocked-policy", map[string]any{"policy": `path "*" { capabilities = ["read"] }`}},
				{http.MethodPost, "/v1/sys/mounts/blocked", "blocked-mount", map[string]any{"type": "kv"}},
				{http.MethodPost, "/v1/transit/keys/blocked", "blocked-key", map[string]any{"type": "aes256-gcm96"}},
			}
			for _, mode := range []int32{1, 2} {
				if !registered && mode == 2 {
					continue
				}
				if registered {
					state.Store(mode)
				}
				want := http.StatusForbidden
				if registered && mode == 2 {
					want = http.StatusServiceUnavailable
				}
				before, err := h.log.LastSequence(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				for _, tc := range cases {
					code, raw := tenantVaultRequest(t, h, token, tc.method, tc.path, tc.key, tc.body)
					var refusal struct {
						Errors []string `json:"errors"`
					}
					if err := json.Unmarshal(raw, &refusal); err != nil || code != want || len(refusal.Errors) != 1 {
						t.Errorf("mode=%d %s %s = %d, want Vault-shaped %d refusal", mode, tc.method, tc.path, code, want)
					}
					for _, secret := range []string{"tenant-vault-canary", "PRIVATE KEY", "private-authority-diagnostic"} {
						if bytes.Contains(raw, []byte(secret)) {
							t.Errorf("mode=%d %s disclosed forbidden response material", mode, tc.path)
						}
					}
				}
				if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
					t.Errorf("refused Vault calls appended events: %d -> %d, err=%v", before, after, err)
				}
			}
			if registered {
				state.Store(0)
				if code, raw := tenantVaultRequest(t, h, token, http.MethodGet, "/v1/secret/data/service-check", "", nil); code != http.StatusOK || !bytes.Contains(raw, []byte("tenant-vault-canary")) {
					t.Fatalf("resumed read = %d", code)
				}
			}
		})
	}
}

func TestTenantVaultMutationHoldsLifecycleFence(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var armed atomic.Bool
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantServiceCheck = func(ctx context.Context, _ string) error {
			if !armed.Load() {
				return nil
			}
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	token := seedScopedToken(t, h.store, h.tenant, "secrets:write")
	armed.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.ts.URL+"/v1/secret/data/fenced", strings.NewReader(`{"data":{"value":"owned-test"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "fenced-vault-write")
	result := make(chan error, 1)
	go func() {
		resp, err := h.ts.Client().Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = errors.New("Vault mutation did not succeed after release")
			}
		}
		result <- err
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("Vault mutation skipped tenant service admission: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	called := false
	err = h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error { called = true; return nil })
	if called || !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Errorf("lifecycle crossed admitted Vault mutation: called=%t err=%v", called, err)
	}
	unblock()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Vault response retained lifecycle fence: %v", err)
	}
}
