// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// kvDouble answers the Key Vault certificate version get and update calls with
// the documented shapes; it accepts only the write credential.
type kvDouble struct {
	mu      sync.Mutex
	enabled map[string]bool
}

func (v *kvDouble) serve(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer kv-write-token" || r.URL.Query().Get("api-version") != "7.4" {
		http.Error(w, `{"error":{"code":"Forbidden"}}`, http.StatusForbidden)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/certificates/")
	enabled, ok := v.enabled[key]
	if !ok {
		http.Error(w, `{"error":{"code":"CertificateNotFound"}}`, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPatch {
		var body struct {
			Attributes struct {
				Enabled *bool `json:"enabled"`
			} `json:"attributes"`
		}
		raw, _ := io.ReadAll(r.Body)
		if json.Unmarshal(raw, &body) != nil || body.Attributes.Enabled == nil {
			http.Error(w, `{"error":{"code":"BadParameter"}}`, http.StatusBadRequest)
			return
		}
		enabled = *body.Attributes.Enabled
		v.enabled[key] = enabled
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": "https://" + r.Host + "/certificates/" + key,
		"attributes": map[string]any{"enabled": enabled, "updated": time.Now().Unix()}})
}

// N2: an Azure Key Vault disable action, labeled "not revoked". A certificate
// the inventory found in Key Vault is disabled there — the exact version,
// through the vault's own write credential configured beside its discovery
// source, from an outbox job — and every answer says it is not revoked: the
// inventory row stays active.
func TestServedKeyVaultDisableIsNotARevocationN2(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	vault := &kvDouble{enabled: map[string]bool{"web-cert/0123abcd": true}}
	srv := httptest.NewTLSServer(http.HandlerFunc(vault.serve))
	t.Cleanup(srv.Close)
	previous := keyVaultDisableClient
	t.Cleanup(func() { keyVaultDisableClient = previous })
	keyVaultDisableClient = func(string, bool, []string) (*http.Client, error) { return srv.Client(), nil }
	t.Setenv("TRSTCTL_TEST_KV_READ", "kv-read-token")
	t.Setenv("TRSTCTL_TEST_KV_WRITE", "kv-write-token")

	host := strings.TrimPrefix(srv.URL, "https://")
	source := func(name string, write bool) string {
		t.Helper()
		provider := map[string]any{"provider": "azure-keyvault", "vault_url": srv.URL, "token_ref": "env:TRSTCTL_TEST_KV_READ", // #nosec G101 -- test-only environment variable names, no credential values (CWE-798)
			"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32"}}
		if write {
			provider["write_token_ref"] = "env:TRSTCTL_TEST_KV_WRITE"
		}
		cfg, _ := json.Marshal(map[string]any{"providers": []any{provider}})
		src, err := h.srv.orch.UpsertDiscoverySource(ctx, h.tenant, store.DiscoverySource{Kind: "cloud_certificate", Name: name, Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		return src.ID
	}
	record := func(source, location, seed string) store.Certificate {
		t.Helper()
		notAfter := time.Now().Add(60 * 24 * time.Hour)
		c, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{Subject: "CN=web.n2.example.test",
			SANs: []string{"web.n2.example.test"}, Issuer: "CN=Public CA", Serial: seed, Fingerprint: crypto.SHA256Hex([]byte("n2-" + seed + "-" + host)),
			NotAfter: &notAfter, Source: source, DeploymentLocation: location})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "n2-admin", "identities:write", "certs:read")
	call := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		code, out := doBearer(t, h.ts, method, path, admin, key, body)
		if code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, out)
		}
		return out
	}

	cert := record("cloud-azure-keyvault", srv.URL+"/certificates/web-cert/0123abcd", "n2a")
	// Without a write credential beside the vault's discovery source, nothing is queued.
	source("n2 read-only vault", false)
	call(http.MethodPost, "/api/v1/certificates/"+cert.ID+"/key-vault-disable", "n2-no-route", map[string]any{"reason": "leaked"}, http.StatusConflict)
	// A certificate not found in Key Vault cannot be disabled there.
	other := record("discovered", "web.n2.example.test:443", "n2b")
	call(http.MethodPost, "/api/v1/certificates/"+other.ID+"/key-vault-disable", "n2-not-kv", map[string]any{"reason": "leaked"}, http.StatusBadRequest)

	source("n2 vault with a write credential", true)
	type disableView struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Revoked bool   `json:"revoked"`
		Note    string `json:"note"`
	}
	var queued disableView
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/certificates/"+cert.ID+"/key-vault-disable", "n2-disable",
		map[string]any{"reason": "private key exposed in a build log"}, http.StatusAccepted), &queued); err != nil {
		t.Fatal(err)
	}
	if queued.Status != "queued" || queued.Revoked || !strings.Contains(queued.Note, "not revoked") {
		t.Fatalf("queued disable = %+v", queued)
	}
	if vault.enabled["web-cert/0123abcd"] != true {
		t.Fatal("the vault was called before the outbox job ran")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if vault.enabled["web-cert/0123abcd"] {
		t.Fatal("the version is still enabled in the vault")
	}
	var list struct {
		Items []disableView `json:"items"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/certificates/"+cert.ID+"/key-vault-disables", "", nil, http.StatusOK), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Status != "disabled" || list.Items[0].Revoked || !strings.Contains(list.Items[0].Note, "not revoked") {
		t.Fatalf("disables = %+v", list.Items)
	}
	// Not a revocation: the inventory row stays active.
	if current, err := h.store.GetCertificate(ctx, h.tenant, cert.ID); err != nil || current.Status != "active" {
		t.Fatalf("certificate after the disable = %q %v; a disable is not a revocation", current.Status, err)
	}
	// The same command retried is the same disable.
	var again disableView
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/certificates/"+cert.ID+"/key-vault-disable", "n2-disable",
		map[string]any{"reason": "private key exposed in a build log"}, http.StatusAccepted), &again); err != nil || again.ID != queued.ID {
		t.Fatalf("retried disable = %+v %v, want %s", again, err, queued.ID)
	}
}
