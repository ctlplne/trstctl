// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/keyposture"
	"trstctl.com/trstctl/internal/store"
)

func keypostureFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../keyposture/testdata/" + name) // #nosec G304 -- a fixed test fixture directory, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func roguePostureCert(id, issuer, keyAlgorithm string, pem []byte) store.Certificate {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	notBefore, notAfter := now.Add(-time.Hour), now.Add(30*24*time.Hour)
	owner := "owner-1"
	return store.Certificate{ID: id, Subject: "CN=" + id, Issuer: issuer, Fingerprint: "fp-" + id, KeyAlgorithm: keyAlgorithm,
		NotBefore: &notBefore, NotAfter: &notAfter, OwnerID: &owner, Status: "active", Source: "inventory", CertificatePEM: pem}
}

func hasType(f rogueCertificateFinding, typ string) bool {
	for _, got := range f.FindingTypes {
		if got == typ {
			return true
		}
	}
	return false
}

// Part 4 (known bug): the weak-key check read only the bare algorithm name, so
// "ecdsa" matched "dsa" and every ECDSA certificate was flagged at risk 85,
// while an RSA-1024 certificate never was. The rating now reads the
// certificate itself, or a recorded name, and says why.
func TestRoguePostureRatesKeysFromTheCertificateNotTheAlgorithmName(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	ecdsaCert := roguePostureCert("ecdsa", "CN=Internal CA", "ECDSA", keypostureFixture(t, "ecdsa-p256-ordinary.pem"))
	if f, ok := rogueCertificateFindingForCertificate(ecdsaCert, now, nil); ok {
		t.Fatalf("an ordinary ECDSA certificate became a finding: %+v", f)
	}
	rsaCert := roguePostureCert("rsa1024", "CN=Legacy CA", "RSA", keypostureFixture(t, "rsa-1024.pem"))
	f, ok := rogueCertificateFindingForCertificate(rsaCert, now, nil)
	if !ok || !hasType(f, "weak_key_algorithm") || len(f.WeakKeyReasons) == 0 || !strings.Contains(f.WeakKeyReasons[0], "RSA-1024 is below the 2048-bit minimum") || f.RiskScore < keyposture.RiskWeak {
		t.Fatalf("RSA-1024 certificate: %+v", f)
	}
	// A row that kept no bytes is rated from its recorded name.
	if f, ok := rogueCertificateFindingForCertificate(roguePostureCert("named", "CN=Legacy CA", "RSA-1024", nil), now, nil); !ok || !hasType(f, "weak_key_algorithm") {
		t.Fatalf("recorded RSA-1024: %+v", f)
	}
	if _, ok := rogueCertificateFindingForCertificate(roguePostureCert("named-ec", "CN=Legacy CA", "ECDSA", nil), now, nil); ok {
		t.Fatal("a recorded ECDSA row became a finding")
	}
}

// Part 4 Done-when: an inventory certificate under one of the eight eMudhra
// intermediates shows a distrusted-issuer finding, from its bytes (authority
// key identifier), from a discovery verdict, or from its recorded issuer name.
func TestRoguePostureNamesDistrustedIssuers(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	leaf := roguePostureCert("leaf", "CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US", "ECDSA", keypostureFixture(t, "leaf-under-em-ov-tls-ca-g3c.pem"))
	f, ok := rogueCertificateFindingForCertificate(leaf, now, nil)
	if !ok || !hasType(f, "distrusted_issuer") || f.Distrust == nil || f.Distrust.Entry != "EM OV TLS CA - G3C" || f.Distrust.How != "issuer_key_id" ||
		f.Severity != "critical" || !strings.Contains(f.Recommendation, "distrust list") || hasType(f, "weak_key_algorithm") {
		t.Fatalf("leaf under EM OV TLS CA - G3C: %+v", f)
	}
	byName := roguePostureCert("byname", "CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL", "ECDSA", nil)
	if f, ok := rogueCertificateFindingForCertificate(byName, now, nil); !ok || f.Distrust == nil || f.Distrust.How != keyposture.DistrustedByName {
		t.Fatalf("recorded issuer name: %+v", f)
	}
	discovered := map[string]keyposture.Verdict{"fp-cloud": {WeakReasons: []string{"the P-384 public key is 4·G: its private key is 4, which anyone can recover"}}}
	cloud := roguePostureCert("cloud", "CN=Cloud CA", "ECDSA", nil)
	if f, ok := rogueCertificateFindingForCertificate(cloud, now, discovered); !ok || !hasType(f, "weak_key_algorithm") || !strings.Contains(f.WeakKeyReasons[0], "4·G") {
		t.Fatalf("discovery verdict borrowed by fingerprint: %+v", f)
	}

	// A CT hit whose reader rated it carries the verdict too, and the summary counts it.
	meta := map[string]any{"subject": "CN=shop.example.test", "issuer": "CN=EM OV TLS CA - G3C"}
	keyposture.Verdict{DistrustEntry: "EM OV TLS CA - G3C", DistrustHow: "issuer_key_id", DistrustReason: "weak key"}.AddTo(meta)
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	ct := rogueCertificateFindingForCT(store.DiscoveryFinding{ID: "ct-1", Kind: "ct_unexpected_issuance", Fingerprint: "fp-ct", RiskScore: 50, Metadata: raw, DiscoveredAt: now})
	if !hasType(ct, "ct_unexpected_issuance") || !hasType(ct, "distrusted_issuer") || ct.Distrust == nil || ct.RiskScore < keyposture.RiskDistrusted || !strings.Contains(ct.Recommendation, "distrust list") {
		t.Fatalf("CT finding: %+v", ct)
	}
	var out rogueCertificatePostureResponse
	out.addRogueCertificateFinding(ct)
	out.addRogueCertificateFinding(f)
	if out.Summary.DistrustedIssuer != 2 {
		t.Fatalf("summary = %+v", out.Summary)
	}
}
