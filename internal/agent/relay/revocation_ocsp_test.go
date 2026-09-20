// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/revocationhealth"
)

func TestRevocationProbePostsAndVerifiesRealOCSPResponseAUD38(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "AUD-38 OCSP CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "aud38.example"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, caKey, csrDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	responseDER, err := crypto.SignOCSPResponse(caDER, caKey, crypto.OCSPGood,
		leaf.SerialNumber, now.Add(-time.Minute), now.Add(time.Hour), time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
			t.Errorf("OCSP request = %s content-type %q", r.Method, r.Header.Get("Content-Type"))
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil || len(body) == 0 {
			t.Errorf("OCSP request body = %d bytes err=%v", len(body), readErr)
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(responseDER)
	}))
	t.Cleanup(server.Close)

	intent := relay.RevocationProbeIntent{
		ID: uuid.NewString(), Bucket: now.Format(time.RFC3339), BatchIndex: 1, BatchCount: 1,
		StaleWithinSeconds: 300, RequiredAgentRole: revocationhealth.RequiredRoleNetwork,
		Targets: []revocationhealth.Target{{
			Key: strings.Repeat("a", 64), Protocol: revocationhealth.ProtocolOCSP, Endpoint: server.URL,
			IssuerSubject: "CN=AUD-38 OCSP CA", IssuerFingerprint: "issuer-fingerprint", IssuerDER: caDER,
			CertificateID: uuid.NewString(), CertificateSubject: leaf.Subject,
			CertificateFingerprint: leaf.SHA256Fingerprint, CertificateSerial: leaf.SerialNumber, CertificateDER: leafDER,
		}},
	}
	report, err := relay.ProbeRevocation(context.Background(), server.Client(), intent)
	if err != nil {
		t.Fatalf("ProbeRevocation: %v", err)
	}
	if requests != 1 || !report.Healthy || len(report.Findings) != 1 {
		t.Fatalf("OCSP probe requests=%d healthy=%t findings=%+v", requests, report.Healthy, report.Findings)
	}
	finding := report.Findings[0]
	if finding.Protocol != revocationhealth.ProtocolOCSP || finding.Status != relay.RevocationFresh ||
		!finding.SignatureVerified || finding.ResponseStatus != crypto.OCSPGood || finding.NextUpdate == nil {
		t.Fatalf("verified OCSP finding = %+v", finding)
	}
}
