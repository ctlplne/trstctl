// SPDX-License-Identifier: BUSL-1.1

package gcpsm_test

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
	"trstctl.com/trstctl/internal/discovery/cloudsecret/gcpsm"
)

func certPEM(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	der, _, err := ctlogtest.IssueCert(cn, dns...)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func gcpSMDouble(t *testing.T, values map[string][]byte, labels map[string]map[string]string, methods *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*methods = append(*methods, r.Method)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/secrets") {
			var list []map[string]any
			for name := range values {
				list = append(list, map[string]any{
					"name":   "projects/p/secrets/" + name,
					"labels": labels[name],
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": list})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/versions/latest:access") {
			parts := strings.Split(r.URL.Path, "/")
			secretName := parts[len(parts)-3]
			_ = json.NewEncoder(w).Encode(map[string]any{
				"payload": map[string]string{"data": base64.StdEncoding.EncodeToString(values[secretName])},
			})
			return
		}
		http.NotFound(w, r)
	}))
}

func TestGCPSecretManagerEnumerateCertificateSecrets(t *testing.T) {
	values := map[string][]byte{
		"web": []byte(certPEM(t, "web.example.test", "web.example.test")),
		"db":  []byte("not a certificate"),
		"api": []byte(certPEM(t, "api.example.test", "api.example.test")),
	}
	labels := map[string]map[string]string{
		"web": {"type": "certificate"},
		"db":  {"type": "certificate"},
		"api": {"type": "opaque"},
	}
	var methods []string
	srv := gcpSMDouble(t, values, labels, &methods)
	defer srv.Close()

	e, err := gcpsm.New(gcpsm.Config{
		Project:        "p",
		Endpoint:       srv.URL,
		Token:          cloudcert.StaticToken("test-token"),
		HTTPClient:     srv.Client(),
		LabelKey:       "type",
		LabelValue:     "certificate",
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
	if got.Provider != "gcp-secret-manager" || got.Location != "p" || got.SecretName != "web" {
		t.Fatalf("bad GCP finding identity: %+v", got)
	}
	if got.ResourceID != "projects/p/secrets/web" || got.Provenance != "gcp-sm://p/web" {
		t.Fatalf("bad resource/provenance: %+v", got)
	}
	if got.Cert.SHA256Fingerprint == "" || len(got.Cert.DNSNames) != 1 {
		t.Fatalf("certificate metadata was not parsed: %+v", got.Cert)
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Fatalf("GCP SM discovery issued %s; it must stay read-only GET-only", m)
		}
	}
}

func TestGCPSecretManagerMetadataModeNeverAccessesAValue(t *testing.T) {
	var methods []string
	srv := gcpSMDouble(t, map[string][]byte{"db": []byte("do-not-read")}, map[string]map[string]string{"db": {}}, &methods)
	defer srv.Close()
	e, err := gcpsm.New(gcpsm.Config{Project: "p", Endpoint: srv.URL, Token: cloudcert.StaticToken("test-token"), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil || len(found) != 1 || found[0].Kind != "cloud_secret_resource" {
		t.Fatalf("metadata inventory = %+v err=%v", found, err)
	}
	if len(methods) != 1 {
		t.Fatalf("metadata-only mode made a value-access request: %v", methods)
	}
}
