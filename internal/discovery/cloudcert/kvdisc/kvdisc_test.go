package kvdisc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudcert/kvdisc"
)

// kvDouble is a faithful Key Vault double: read-only list + get, recording the
// HTTP methods so a test can prove discovery never writes.
func kvDouble(t *testing.T, names map[string][]byte, methods *[]string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*methods = append(*methods, r.Method)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/certificates":
			var vals []map[string]string
			for name := range names {
				vals = append(vals, map[string]string{"id": srv.URL + "/certificates/" + name})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": vals})
		case strings.HasPrefix(r.URL.Path, "/certificates/"):
			name := strings.TrimPrefix(r.URL.Path, "/certificates/")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":  srv.URL + r.URL.Path,
				"cer": base64.StdEncoding.EncodeToString(names[name]),
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	return srv
}

func certDER(t *testing.T, cn string, dns ...string) []byte {
	t.Helper()
	der, _, err := ctlogtest.IssueCert(cn, dns...)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestKeyVaultEnumerate(t *testing.T) {
	names := map[string][]byte{
		"web": certDER(t, "web", "web.example.com"),
		"api": certDER(t, "api", "api.example.com"),
	}
	var methods []string
	srv := kvDouble(t, names, &methods)
	defer srv.Close()

	e, err := kvdisc.New(kvdisc.Config{VaultURL: srv.URL, Token: cloudcert.StaticToken("test-token"), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d, want 2", len(found))
	}
	for _, f := range found {
		if f.Provider != "azure-keyvault" || len(f.Cert.DNSNames) != 1 || f.Cert.SHA256Fingerprint == "" {
			t.Errorf("found = %+v", f)
		}
	}
	// Read-only: every request was a GET.
	for _, m := range methods {
		if m != http.MethodGet {
			t.Errorf("discovery issued a %s request; must be read-only (GET)", m)
		}
	}
}

func TestKeyVaultRequiresToken(t *testing.T) {
	if _, err := kvdisc.New(kvdisc.Config{VaultURL: "https://v.vault.azure.net"}); err == nil {
		t.Error("New without a token provider should error")
	}
}
