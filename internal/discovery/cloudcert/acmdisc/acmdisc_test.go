// SPDX-License-Identifier: BUSL-1.1

package acmdisc_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert/acmdisc"
)

// acmDouble is a faithful AWS ACM double: it answers the read-only
// ListCertificates and GetCertificate operations and records every X-Amz-Target
// it sees, so a test can prove discovery never invokes a mutating operation.
func acmDouble(arnToPEM map[string]string, seen *[]string) *httptest.Server {
	return acmChainDouble(arnToPEM, nil, seen)
}

// acmChainDouble is acmDouble whose GetCertificate also answers a
// certificate's CertificateChain, as ACM does for an issued or imported
// certificate with a chain.
func acmChainDouble(arnToPEM, arnToChain map[string]string, seen *[]string) *httptest.Server {
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
			answer := map[string]any{"Certificate": arnToPEM[req.CertificateArn]}
			if chain := arnToChain[req.CertificateArn]; chain != "" {
				answer["CertificateChain"] = chain
			}
			_ = json.NewEncoder(w).Encode(answer)
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

// TestACMEnumerateKeepsTheReturnedChainB13L1 is B13-L1: the certificate ACM
// returns is followed by the chain it returns, so the sink can keep the
// issuers for revocation probing, while the inventory metadata is still the
// leaf's. A certificate without a chain is returned as it was.
func TestACMEnumerateKeepsTheReturnedChainB13L1(t *testing.T) {
	leaf, issuer, alone := certPEM(t, "leaf", "leaf.example.com"), certPEM(t, "issuer"), certPEM(t, "alone", "alone.example.com")
	const chained, unchained = "arn:aws:acm:us-east-1:1:certificate/chained", "arn:aws:acm:us-east-1:1:certificate/alone"
	var seen []string
	srv := acmChainDouble(map[string]string{chained: leaf, unchained: alone}, map[string]string{chained: issuer}, &seen)
	defer srv.Close()
	e, err := acmdisc.New(acmdisc.Config{
		Region: "us-east-1", Endpoint: srv.URL,
		AccessKeyID: "AKID", SecretAccessKey: "SECRET", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil || len(found) != 2 {
		t.Fatalf("Enumerate = %d, %v", len(found), err)
	}
	for _, f := range found {
		switch f.ResourceID {
		case chained:
			if want := strings.TrimSpace(leaf) + "\n" + strings.TrimSpace(issuer) + "\n"; string(f.Raw) != want {
				t.Errorf("the chained certificate's bytes = %q, want the leaf then its chain", f.Raw)
			}
			if len(f.Cert.DNSNames) != 1 || f.Cert.DNSNames[0] != "leaf.example.com" {
				t.Errorf("the chained certificate's metadata = %+v, want the leaf's", f.Cert)
			}
		case unchained:
			if string(f.Raw) != alone {
				t.Errorf("a certificate without a chain = %q, want it as returned", f.Raw)
			}
		default:
			t.Errorf("unexpected listing %+v", f)
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
