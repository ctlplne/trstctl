package azurekv_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/azurekv"
)

func certPEM(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	der, _, err := ctlogtest.IssueCert(cn, dns...)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func azureKVDouble(secrets map[string]string, tags map[string]map[string]string, seen *[]string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+strings.Trim(r.URL.Path, "/"))
		if got := r.Header.Get("Authorization"); got != "Bearer azure-token" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "secrets":
			items := make([]map[string]any, 0, len(secrets))
			for name := range secrets {
				items = append(items, map[string]any{
					"id":   srv.URL + "/secrets/" + name,
					"tags": tags[name],
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": items})
		case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "secrets":
			value, ok := secrets[parts[1]]
			if !ok {
				http.Error(w, "missing", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          srv.URL + "/secrets/" + parts[1],
				"value":       base64.StdEncoding.EncodeToString([]byte(value)),
				"contentType": "application/octet-stream;base64",
			})
		default:
			http.Error(w, "unexpected Azure Key Vault operation", http.StatusBadRequest)
		}
	}))
	return srv
}

func TestAzureKeyVaultEnumerateCertificateSecrets(t *testing.T) {
	secrets := map[string]string{
		"tls-web": certPEM(t, "azure-web.example.test", "azure-web.example.test"),
		"app-db":  "not a certificate",
		"tls-api": certPEM(t, "azure-api.example.test", "azure-api.example.test"),
	}
	tags := map[string]map[string]string{
		"tls-web": {"type": "certificate"},
		"app-db":  {"type": "certificate"},
		"tls-api": {"type": "opaque"},
	}
	var seen []string
	srv := azureKVDouble(secrets, tags, &seen)
	defer srv.Close()

	e, err := azurekv.New(azurekv.Config{
		VaultURL:   srv.URL,
		Token:      cloudcert.StaticToken("azure-token"),
		HTTPClient: srv.Client(),
		TagKey:     "type",
		TagValue:   "certificate",
		NamePrefix: "tls-",
	})
	if err != nil {
		t.Fatal(err)
	}

	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d TLS secrets, want 1: %+v", len(found), found)
	}
	got := found[0]
	if got.Provider != "azure-key-vault" || got.Location == "" {
		t.Fatalf("bad provider/location: %+v", got)
	}
	if got.SecretName != "tls-web" || !strings.HasSuffix(got.ResourceID, "/secrets/tls-web") {
		t.Fatalf("bad resource identity: %+v", got)
	}
	if got.Provenance != "azure-kv://"+got.Location+"/tls-web" {
		t.Fatalf("provenance = %q, want azure-kv path", got.Provenance)
	}
	if got.Cert.SHA256Fingerprint == "" || len(got.Cert.DNSNames) != 1 {
		t.Fatalf("certificate metadata was not parsed: %+v", got.Cert)
	}
	if got.Metadata["secret_value"] != "" || got.Metadata["value"] != "" {
		t.Fatalf("secret value leaked into metadata: %+v", got.Metadata)
	}
	for _, op := range seen {
		if !strings.HasPrefix(op, "GET ") {
			t.Fatalf("Azure Key Vault discovery invoked non-read-only operation %q; seen=%v", op, seen)
		}
	}
}
