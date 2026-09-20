// SPDX-License-Identifier: BUSL-1.1

package awssm_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/awssm"
)

func certPEM(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	der, _, err := ctlogtest.IssueCert(cn, dns...)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func awsSMDouble(secrets map[string]string, tags map[string]map[string]string, seen *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		*seen = append(*seen, target)
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch target {
		case "secretsmanager.ListSecrets":
			var list []map[string]any
			for name := range secrets {
				var tagList []map[string]string
				for k, v := range tags[name] {
					tagList = append(tagList, map[string]string{"Key": k, "Value": v})
				}
				list = append(list, map[string]any{
					"Name": name,
					"ARN":  "arn:aws:secretsmanager:us-east-1:111111111111:secret:" + name,
					"Tags": tagList,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"SecretList": list})
		case "secretsmanager.GetSecretValue":
			var req struct {
				SecretID string `json:"SecretId"`
			}
			_ = json.Unmarshal(body, &req)
			_ = json.NewEncoder(w).Encode(map[string]any{"SecretString": secrets[req.SecretID]})
		default:
			http.Error(w, "unexpected target "+target, http.StatusBadRequest)
		}
	}))
}

func TestAWSSecretsManagerEnumerateCertificateSecrets(t *testing.T) {
	secrets := map[string]string{
		"tls/web": certPEM(t, "web.example.test", "web.example.test"),
		"app/db":  "not a certificate",
		"tls/api": certPEM(t, "api.example.test", "api.example.test"),
	}
	tags := map[string]map[string]string{
		"tls/web": {"type": "certificate"},
		"app/db":  {"type": "certificate"},
		"tls/api": {"type": "opaque"},
	}
	var seen []string
	srv := awsSMDouble(secrets, tags, &seen)
	defer srv.Close()

	e, err := awssm.New(awssm.Config{
		Region:          "us-east-1",
		Endpoint:        srv.URL,
		AccessKeyID:     "AKID",
		SecretAccessKey: []byte("SECRET"),
		HTTPClient:      srv.Client(),
		TagKey:          "type",
		TagValue:        "certificate",
		NamePrefix:      "tls/",
		InspectContent:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d metadata/certificate records, want 2: %+v", len(found), found)
	}
	got := found[0]
	for _, item := range found {
		if item.Kind == "x509_certificate" {
			got = item
		}
	}
	if got.Provider != "aws-secrets-manager" || got.Location != "us-east-1" {
		t.Fatalf("bad provider/location: %+v", got)
	}
	if got.ResourceID != "arn:aws:secretsmanager:us-east-1:111111111111:secret:tls/web" || got.SecretName != "tls/web" {
		t.Fatalf("bad resource identity: %+v", got)
	}
	if got.Provenance != "aws-sm://us-east-1/tls/web" {
		t.Fatalf("provenance = %q, want aws-sm path", got.Provenance)
	}
	if got.Cert.SHA256Fingerprint == "" || len(got.Cert.DNSNames) != 1 {
		t.Fatalf("certificate metadata was not parsed: %+v", got.Cert)
	}
	if got.Metadata["secret_value"] != "" || got.Metadata["secret_string"] != "" {
		t.Fatalf("secret value leaked into metadata: %+v", got.Metadata)
	}
	for _, target := range seen {
		if target != "secretsmanager.ListSecrets" && target != "secretsmanager.GetSecretValue" {
			t.Fatalf("AWS SM discovery invoked non-read-only operation %q; seen=%v", target, seen)
		}
	}
}

func TestAWSSecretsManagerMetadataModeNeverGetsAValue(t *testing.T) {
	var seen []string
	srv := awsSMDouble(map[string]string{"app/db": "do-not-read"}, map[string]map[string]string{"app/db": {}}, &seen)
	defer srv.Close()
	e, err := awssm.New(awssm.Config{
		Region: "us-east-1", Endpoint: srv.URL, AccessKeyID: "AKID",
		SecretAccessKey: []byte("SECRET"), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	found, err := e.Enumerate(context.Background())
	if err != nil || len(found) != 1 || found[0].Kind != "cloud_secret_resource" {
		t.Fatalf("metadata inventory = %+v err=%v", found, err)
	}
	for _, target := range seen {
		if target == "secretsmanager.GetSecretValue" {
			t.Fatalf("metadata-only mode retrieved a secret value: %v", seen)
		}
	}
}
