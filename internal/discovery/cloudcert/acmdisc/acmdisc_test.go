package acmdisc_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert/acmdisc"
)

// acmDouble is a faithful AWS ACM double: it answers the read-only
// ListCertificates and GetCertificate operations and records every X-Amz-Target
// it sees, so a test can prove discovery never invokes a mutating operation.
func acmDouble(arnToPEM map[string]string, seen *[]string) *httptest.Server {
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
		case "CertificateManager.ListCertificates":
			var summaries []map[string]string
			for arn := range arnToPEM {
				summaries = append(summaries, map[string]string{"CertificateArn": arn})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"CertificateSummaryList": summaries})
		case "CertificateManager.GetCertificate":
			var req struct{ CertificateArn string }
			_ = json.Unmarshal(body, &req)
			_ = json.NewEncoder(w).Encode(map[string]any{"Certificate": arnToPEM[req.CertificateArn]})
		default:
			http.Error(w, "unexpected target "+target, http.StatusBadRequest)
		}
	}))
}

func certPEM(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	der, _, err := ctlogtest.IssueCert(cn, dns...)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestACMEnumerate(t *testing.T) {
	arns := map[string]string{
		"arn:aws:acm:us-east-1:1:certificate/aaa": certPEM(t, "one", "one.example.com"),
		"arn:aws:acm:us-east-1:1:certificate/bbb": certPEM(t, "two", "two.example.com"),
	}
	var seen []string
	srv := acmDouble(arns, &seen)
	defer srv.Close()

	e, err := acmdisc.New(acmdisc.Config{
		Region: "us-east-1", Endpoint: srv.URL,
		AccessKeyID: "AKID", SecretAccessKey: "SECRET", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d certs, want 2", len(found))
	}
	for _, f := range found {
		if f.Provider != "aws-acm" || f.Location != "us-east-1" {
			t.Errorf("found = %+v", f)
		}
		if len(f.Cert.DNSNames) != 1 || f.Cert.SHA256Fingerprint == "" {
			t.Errorf("parsed cert = %+v", f.Cert)
		}
	}
}

func TestACMReadOnly(t *testing.T) {
	arns := map[string]string{"arn:aws:acm:us-east-1:1:certificate/aaa": certPEM(t, "one", "one.example.com")}
	var seen []string
	srv := acmDouble(arns, &seen)
	defer srv.Close()

	e, _ := acmdisc.New(acmdisc.Config{Region: "us-east-1", Endpoint: srv.URL, AccessKeyID: "AKID", SecretAccessKey: "SECRET", HTTPClient: srv.Client()})
	if _, err := e.Enumerate(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, target := range seen {
		if target != "CertificateManager.ListCertificates" && target != "CertificateManager.GetCertificate" {
			t.Errorf("discovery invoked a non-read-only operation: %s", target)
		}
	}
	if len(seen) == 0 {
		t.Error("no operations recorded")
	}
}
