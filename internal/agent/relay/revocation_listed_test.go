// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// A211: a CRL answer says whether the signed list names the target's own
// serial, so a certificate known only from a scan reads revoked or not from
// its issuer's CRL rather than only from the list's freshness.
func TestRevocationCRLAnswerSaysWhetherItListsTheTargetSerial(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "A211 CRL CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	crlDER, err := crypto.CreateCRL(caDER, caKey, []crypto.RevokedSerial{{Serial: "a211", RevokedAt: now.Add(-time.Minute), Reason: 1}},
		1, now.Add(-time.Minute), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	t.Cleanup(server.Close)
	target := func(serial string) revocationhealth.Target {
		return revocationhealth.Target{
			Key: crypto.SHA256Hex([]byte(serial)), Protocol: revocationhealth.ProtocolCRL, Endpoint: server.URL + "/crl",
			IssuerSubject: "CN=A211 CRL CA", IssuerFingerprint: "issuer-fingerprint", IssuerDER: caDER,
			CertificateID: uuid.NewString(), CertificateSubject: "CN=" + serial,
			CertificateFingerprint: crypto.SHA256Hex([]byte("leaf " + serial)), CertificateSerial: serial,
		}
	}
	report, err := relay.ProbeRevocation(context.Background(), server.Client(), relay.RevocationProbeIntent{
		ID: uuid.NewString(), Bucket: now.Format(time.RFC3339), BatchIndex: 1, BatchCount: 1,
		StaleWithinSeconds: int((24 * time.Hour).Seconds()), RequiredAgentRole: revocationhealth.RequiredRoleNetwork,
		Targets: []revocationhealth.Target{target("a211"), target("b212")},
	})
	if err != nil || len(report.Findings) != 2 {
		t.Fatalf("probe = %+v err=%v", report, err)
	}
	listed := map[string]bool{}
	for _, finding := range report.Findings {
		if finding.CertificateListed == nil || !finding.SignatureVerified {
			t.Fatalf("CRL finding without a verified listing answer: %+v", finding)
		}
		listed[finding.TargetKey] = *finding.CertificateListed
	}
	if !listed[crypto.SHA256Hex([]byte("a211"))] || listed[crypto.SHA256Hex([]byte("b212"))] {
		t.Fatalf("listing answers = %v; want the revoked serial listed and the other not", listed)
	}
}
