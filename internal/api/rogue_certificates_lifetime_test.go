// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/store"
)

// A178: a publicly trusted TLS server certificate is held to the Baseline
// Requirements maximum for the date it was issued; a private one keeps the
// long-standing 398-day ceiling.
func TestRogueLifetimeFollowsTheDatedMaximumForPublicTLS(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	notBefore := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	leaf := func(id string, lifetime time.Duration, policies ...string) store.Certificate {
		der, err := certtest.TLSLeaf(id+".example.test", notBefore, notBefore.Add(lifetime), policies...)
		if err != nil {
			t.Fatal(err)
		}
		cert := roguePostureCert(id, "CN=Issuer", "ECDSA", nil)
		notAfter := notBefore.Add(lifetime)
		cert.NotBefore, cert.NotAfter, cert.CertificateDER = &notBefore, &notAfter, der
		return cert
	}
	day := 24 * time.Hour
	public := leaf("public-300", 300*day, "2.23.140.1.2.1")
	f, ok := rogueCertificateFindingForCertificate(public, now, nil)
	if !ok || !hasType(f, "lifetime_exceeds_policy") || f.PolicyMaxDays != 200 || f.LifetimeDays != 301 {
		t.Fatalf("a 300-day public TLS certificate issued 2026-04-01: ok=%v %+v", ok, f)
	}
	// Exactly 200 days apart is 201 BR days: one second over the maximum.
	exact := leaf("public-200", 200*day, "2.23.140.1.2.2")
	if f, ok := rogueCertificateFindingForCertificate(exact, now, nil); !ok || !hasType(f, "lifetime_exceeds_policy") || f.LifetimeDays != 201 {
		t.Fatalf("a public TLS certificate 200 days apart: ok=%v %+v", ok, f)
	}
	within := leaf("public-199", 200*day-time.Second, "2.23.140.1.2.1")
	if f, ok := rogueCertificateFindingForCertificate(within, now, nil); ok && hasType(f, "lifetime_exceeds_policy") {
		t.Fatalf("200 BR days is within the maximum: %+v", f)
	}
	private := leaf("private-300", 300*day)
	if f, ok := rogueCertificateFindingForCertificate(private, now, nil); ok && hasType(f, "lifetime_exceeds_policy") {
		t.Fatalf("a private 300-day certificate is under the 398-day ceiling: %+v", f)
	}
	privateLong := leaf("private-500", 500*day)
	if f, ok := rogueCertificateFindingForCertificate(privateLong, now, nil); !ok || !hasType(f, "lifetime_exceeds_policy") || f.PolicyMaxDays != 398 {
		t.Fatalf("a private 500-day certificate: ok=%v %+v", ok, f)
	}
}
