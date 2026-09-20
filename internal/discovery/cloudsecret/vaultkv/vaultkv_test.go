// SPDX-License-Identifier: BUSL-1.1

package vaultkv_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/vaultkv"
)

func certPEM(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	der, _, err := ctlogtest.IssueCert(cn, dns...)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func vaultKVDouble(t *testing.T, values map[string]string, customMetadata map[string]map[string]string, seen *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Vault-Token") != "vault-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/secret/metadata/tls":
			keys := make([]string, 0, len(values))
			for name := range values {
				keys = append(keys, strings.TrimPrefix(name, "tls/"))
			}
			sort.Strings(keys)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/"):
			name := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"current_version": 2, "oldest_version": 1, "updated_time": "2026-08-25T00:00:00Z",
				"custom_metadata": customMetadata[name],
			}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
			name := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]string{
						"tls.crt": values[name],
					},
					"metadata": map[string]any{
						"custom_metadata": customMetadata[name],
					},
				},
			})
		default:
			http.Error(w, "unexpected Vault operation", http.StatusBadRequest)
		}
	}))
}

func TestVaultKVEnumerateCertificateSecrets(t *testing.T) {
	values := map[string]string{
		"tls/web": certPEM(t, "web.example.test", "web.example.test"),
		"tls/db":  "not a certificate",
		"tls/api": certPEM(t, "api.example.test", "api.example.test"),
	}
	customMetadata := map[string]map[string]string{
		"tls/web": {"type": "certificate"},
		"tls/db":  {"type": "certificate"},
		"tls/api": {"type": "opaque"},
	}
	var seen []string
	srv := vaultKVDouble(t, values, customMetadata, &seen)
	defer srv.Close()

	e, err := vaultkv.New(vaultkv.Config{
		VaultURL:       srv.URL,
		Mount:          "secret",
		PathPrefix:     "tls",
		Token:          cloudcert.StaticToken("vault-token"),
		HTTPClient:     srv.Client(),
		TagKey:         "type",
		TagValue:       "certificate",
		InspectContent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(found) != 3 {
		t.Fatalf("found %d metadata/certificate records, want 3: %+v", len(found), found)
	}
	got := found[0]
	for _, item := range found {
		if item.Kind == "x509_certificate" {
			got = item
		}
	}
	if got.Provider != "hashicorp-vault" || got.SecretName != "tls/web" {
		t.Fatalf("bad Vault finding identity: %+v", got)
	}
	if got.ResourceID != "vault://"+strings.TrimPrefix(srv.URL, "http://")+"/secret/tls/web" || got.Provenance != got.ResourceID {
		t.Fatalf("bad resource/provenance: %+v", got)
	}
	if got.Cert.SHA256Fingerprint == "" || len(got.Cert.DNSNames) != 1 {
		t.Fatalf("certificate metadata was not parsed: %+v", got.Cert)
	}
	if got.Metadata["tls.crt"] != "" || got.Metadata["secret_value"] != "" {
		t.Fatalf("secret value leaked into metadata: %+v", got.Metadata)
	}
	for _, op := range seen {
		if !strings.HasPrefix(op, "LIST ") && !strings.HasPrefix(op, "GET ") {
			t.Fatalf("Vault KV discovery invoked non-read-only operation %q; seen=%v", op, seen)
		}
	}
}

func TestVaultKVMetadataModeNeverReadsTheDataPath(t *testing.T) {
	var seen []string
	srv := vaultKVDouble(t, map[string]string{"tls/db": "do-not-read"}, map[string]map[string]string{"tls/db": {}}, &seen)
	defer srv.Close()
	e, err := vaultkv.New(vaultkv.Config{
		VaultURL: srv.URL, Mount: "secret", PathPrefix: "tls",
		Token: cloudcert.StaticToken("vault-token"), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil || len(found) != 1 || found[0].Kind != "cloud_secret_resource" {
		t.Fatalf("metadata inventory = %+v err=%v", found, err)
	}
	for _, operation := range seen {
		if strings.Contains(operation, "/data/") {
			t.Fatalf("metadata-only mode read the value-bearing data path: %v", seen)
		}
	}
}
