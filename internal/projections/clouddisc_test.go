package projections_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudcert/acmdisc"
	"trstctl.com/trstctl/internal/discovery/cloudcert/gcmdisc"
	"trstctl.com/trstctl/internal/discovery/cloudcert/kvdisc"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

func cloudCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	der, _, err := ctlogtest.IssueCert(cn, cn)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// acmDoubleSrv answers ListCertificates + GetCertificate for one certificate.
func acmDoubleSrv(t *testing.T, arn string, der []byte, reads *int) *httptest.Server {
	t.Helper()
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reads++
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "CertificateManager.ListCertificates":
			_ = json.NewEncoder(w).Encode(map[string]any{"CertificateSummaryList": []map[string]string{{"CertificateArn": arn}}})
		case "CertificateManager.GetCertificate":
			_ = json.NewEncoder(w).Encode(map[string]any{"Certificate": pemStr})
		default:
			http.Error(w, "mutating op not allowed in discovery", http.StatusBadRequest)
		}
	}))
}

func kvDoubleSrv(t *testing.T, name string, der []byte) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/certificates":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{{"id": srv.URL + "/certificates/" + name}}})
		case strings.HasPrefix(r.URL.Path, "/certificates/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"cer": base64.StdEncoding.EncodeToString(der)})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	return srv
}

func gcmDoubleSrv(t *testing.T, name string, der []byte) *httptest.Server {
	t.Helper()
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]string{{"name": name, "pemCertificate": pemStr}},
		})
	}))
}

// TestCloudDiscoveryReconcilesToInventoryAndGraph is the S6.7 acceptance over
// embedded PostgreSQL: three provider connectors enumerate certificates from
// faithful cloud doubles, and the discoveries reconcile into the inventory and
// appear in the credential graph. Discovery is read-only and bounded.
func TestCloudDiscoveryReconcilesToInventoryAndGraph(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	acmDER := cloudCertDER(t, "acm.example.com")
	kvDER := cloudCertDER(t, "kv.example.com")
	gcmDER := cloudCertDER(t, "gcm.example.com")

	acmReads := 0
	acmSrv := acmDoubleSrv(t, "arn:aws:acm:us-east-1:1:certificate/x", acmDER, &acmReads)
	defer acmSrv.Close()
	kvSrv := kvDoubleSrv(t, "web", kvDER)
	defer kvSrv.Close()
	gcmSrv := gcmDoubleSrv(t, "projects/p/locations/global/certificates/web", gcmDER)
	defer gcmSrv.Close()

	acmE, err := acmdisc.New(acmdisc.Config{Region: "us-east-1", Endpoint: acmSrv.URL, AccessKeyID: "AK", SecretAccessKey: "SK", HTTPClient: acmSrv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	kvE, err := kvdisc.New(kvdisc.Config{VaultURL: kvSrv.URL, Token: cloudcert.StaticToken("tok"), HTTPClient: kvSrv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	gcmE, err := gcmdisc.New(gcmdisc.Config{Project: "p", Location: "global", Endpoint: gcmSrv.URL, Token: cloudcert.StaticToken("tok"), HTTPClient: gcmSrv.Client()})
	if err != nil {
		t.Fatal(err)
	}

	d := cloudcert.NewDiscoverer(cloudcert.NewStoreSink(s, tenantA), cloudcert.WithWorkers(2))
	defer d.Close()
	rep := d.Discover(ctx, []cloudcert.Provider{acmE, kvE, gcmE})
	if rep.Discovered != 3 || rep.Failed != 0 {
		t.Fatalf("report = %+v, want 3 discovered / 0 failed", rep)
	}
	if acmReads == 0 {
		t.Error("ACM double saw no read operations")
	}

	// Reconciled into the inventory.
	certs, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	subjects := map[string]string{} // subject -> source
	for _, c := range certs {
		subjects[c.Subject] = c.Source
	}
	for _, want := range []string{"CN=acm.example.com", "CN=kv.example.com", "CN=gcm.example.com"} {
		if _, ok := subjects[want]; !ok {
			t.Errorf("inventory missing discovered cert %q (have %v)", want, subjects)
		}
	}
	if !strings.HasPrefix(subjects["CN=acm.example.com"], "cloud-aws-acm") {
		t.Errorf("ACM cert source = %q, want cloud-aws-acm", subjects["CN=acm.example.com"])
	}

	// Present in the credential graph.
	g, err := graph.Build(ctx, s, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	credNames := map[string]bool{}
	for _, n := range g.Nodes() {
		if n.Kind == graph.KindCredential {
			credNames[n.Name] = true
		}
	}
	for _, want := range []string{"CN=acm.example.com", "CN=kv.example.com", "CN=gcm.example.com"} {
		if !credNames[want] {
			t.Errorf("graph missing credential node for %q", want)
		}
	}
}
