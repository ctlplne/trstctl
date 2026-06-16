package gcmdisc_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudcert/gcmdisc"
)

func certPEM(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	der, _, err := ctlogtest.IssueCert(cn, dns...)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// gcmDouble is a faithful Certificate Manager double: read-only list, recording
// HTTP methods so a test can prove discovery never writes.
func gcmDouble(t *testing.T, certs map[string]string, methods *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*methods = append(*methods, r.Method)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/certificates") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var list []map[string]string
		for name, pemStr := range certs {
			list = append(list, map[string]string{"name": name, "pemCertificate": pemStr})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"certificates": list})
	}))
}

func TestGCMEnumerate(t *testing.T) {
	certs := map[string]string{
		"projects/p/locations/global/certificates/web": certPEM(t, "web", "web.example.com"),
		"projects/p/locations/global/certificates/api": certPEM(t, "api", "api.example.com"),
	}
	var methods []string
	srv := gcmDouble(t, certs, &methods)
	defer srv.Close()

	e, err := gcmdisc.New(gcmdisc.Config{
		Project: "p", Location: "global", Endpoint: srv.URL,
		Token: cloudcert.StaticToken("test-token"), HTTPClient: srv.Client(),
	})
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
		if f.Provider != "gcp-certmanager" || f.Location != "global" || len(f.Cert.DNSNames) != 1 {
			t.Errorf("found = %+v", f)
		}
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Errorf("discovery issued a %s request; must be read-only (GET)", m)
		}
	}
}

func TestGCMRequiresProjectAndToken(t *testing.T) {
	if _, err := gcmdisc.New(gcmdisc.Config{Location: "global", Token: cloudcert.StaticToken("x")}); err == nil {
		t.Error("New without project should error")
	}
	if _, err := gcmdisc.New(gcmdisc.Config{Project: "p", Location: "global"}); err == nil {
		t.Error("New without token should error")
	}
}
