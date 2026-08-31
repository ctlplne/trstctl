// SPDX-License-Identifier: MPL-2.0

package ephemeral_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/ephemeral"
)

func TestRetainedLegacyApprovalPreservesExactCommand(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	ca, err := crypto.SelfSignedCACert(caKey, "legacy-approval-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	for _, subject := range []string{
		"repo:org/project:ref:refs/heads/main", "repo:org/project?ref=main",
		"a%2Fb", "é", "literal+name@host",
	} {
		t.Run(subject, func(t *testing.T) {
			// Reproduce the pre-canonical automatic constructor, not an
			// expectation derived from the new decoder's output.
			parts := strings.Split(subject, "/")
			for i, part := range parts {
				parts[i] = url.PathEscape(part)
			}
			uri := "spiffe://legacy.test/" + strings.Join(parts, "/")
			if _, err := crypto.ParseSPIFFEID(uri); err == nil {
				t.Fatal("legacy fixture unexpectedly passes strict SPIFFE parsing")
			}
			if _, err := crypto.SignSVID(ca, caKey, leafKey.Public().DER, uri, time.Minute); err == nil {
				t.Fatal("new automatic issuance accepted a legacy spelling")
			}
			csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{URIs: []string{uri}}, leafKey)
			if err != nil {
				t.Fatal(err)
			}
			// Only the test fixture uses ordinary nonreserved CSR signing.
			cert, err := crypto.SignLeafFromCSRWithProfile(ca, caKey, csr, time.Minute, crypto.LeafProfile{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := crypto.SPIFFEIDFromCert(cert); err == nil {
				t.Fatal("TLS identity extraction accepted a legacy spelling")
			}
			binding, err := ephemeral.NewApprovalBinding("1a382d7d-930b-42ba-aa1b-a9c4459d821b",
				ca, "retained-request", "github_oidc", subject, nil, leafKey.Public().DER, uri, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			eventTime := time.Now().UTC()
			before, err := binding.Digest()
			if err != nil {
				t.Fatal(err)
			}
			info, err := binding.ValidateCertificate(cert, "ephemeral:github_oidc", approvalTestTenant, eventTime)
			if err != nil {
				t.Fatalf("exact retained approval rejected: %v", err)
			}
			if len(info.URIs) != 1 || info.URIs[0] != uri {
				t.Fatal("historical URI was rewritten")
			}
			if after, err := binding.Digest(); err != nil || after != before {
				t.Fatal("reading history changed its approved command digest")
			}
			if got, err := ephemeral.SubjectFromSPIFFEID(uri); err != nil || got != subject {
				t.Fatalf("original subject changed: got %q, err %v", got, err)
			}
			for _, change := range []func(*ephemeral.ApprovalBinding){
				func(b *ephemeral.ApprovalBinding) {
					b.AttestationSubjectSHA256 = crypto.SHA256Hex([]byte("another-subject"))
				},
				func(b *ephemeral.ApprovalBinding) { b.PublicKeySHA256 = crypto.SHA256Hex([]byte("another-key")) },
				func(b *ephemeral.ApprovalBinding) { b.SPIFFEIDSHA256 = crypto.SHA256Hex([]byte(uri + "-other")) },
				func(b *ephemeral.ApprovalBinding) { b.CACertificateSHA256 = crypto.SHA256Hex([]byte("another-ca")) },
				func(b *ephemeral.ApprovalBinding) { b.AttestationMethod = "other-method" },
				func(b *ephemeral.ApprovalBinding) { b.TTLSeconds = 1 },
			} {
				changed := binding
				change(&changed)
				if _, err := changed.ValidateCertificate(cert, "ephemeral:github_oidc", approvalTestTenant, eventTime); err == nil {
					t.Fatal("changed retained authority accepted")
				}
			}
			corrupted := append([]byte(nil), cert...)
			corrupted[len(corrupted)-1] ^= 1
			if _, err := binding.ValidateCertificate(corrupted, "ephemeral:github_oidc", approvalTestTenant, eventTime); err == nil {
				t.Fatal("corrupted retained signature accepted")
			}
			if _, err := binding.ValidateCertificate(cert, "ephemeral:github_oidc", approvalTestTenant, info.NotAfter); err == nil {
				t.Fatal("replacement event time at expiry accepted")
			}
		})
	}
}

func TestRetainedLegacySubjectCannotRelaxReservedNamespace(t *testing.T) {
	const prefix = "spiffe://legacy.test/_trstctl/v1/tenant/" + approvalTestTenant + "/ephemeral/method/k8s_sat/subject/"
	for _, raw := range []string{
		prefix + "repo:org", prefix + "repo%3Aorg", prefix + "trstctl-hex-776562",
		strings.Replace(prefix, "/v1/", "/v2/", 1) + "web",
		strings.Replace(prefix, "/ephemeral/", "/broker/", 1) + "web",
		strings.Replace(prefix, "/_trstctl/", "/%5Ftrstctl/", 1) + "repo:org",
		"spiffe://legacy.test/x/../_trstctl/old:name",
		"spiffe://legacy.test/x/%2E%2E/_trstctl/old:name",
		"spiffe://legacy.test/a%2Fb", "spiffe://legacy.test/a//b",
		"spiffe://legacy.test/a/%2E/b", "spiffe://legacy.test/a/%2e%2e/b",
		"spiffe://legacy.test/a:b?", "spiffe://legacy.test/a:b#",
		"spiffe://legacy.test/a:b?query=value", "spiffe://legacy.test/a:b#fragment",
		"spiffe://user@legacy.test/a:b", "spiffe://legacy.test:443/a:b",
		"spiffe://Legacy.test/a:b", "SPIFFE://legacy.test/a:b",
		"spiffe://legacy.test/a%", "spiffe://legacy.test/" + strings.Repeat("a", crypto.MaxSPIFFEIDLength),
	} {
		if _, err := ephemeral.SubjectFromSPIFFEID(raw); err == nil {
			t.Errorf("unsafe retained name accepted: %q", raw)
		}
	}
	// The old decoder accepted this alternate percent spelling too. Reading
	// it is safe only because validation still checks its exact signed URI hash.
	if got, err := ephemeral.SubjectFromSPIFFEID("spiffe://legacy.test/repo%3Aorg/project"); err != nil || got != "repo:org/project" {
		t.Fatalf("retained percent spelling changed: got %q, err %v", got, err)
	}
}
