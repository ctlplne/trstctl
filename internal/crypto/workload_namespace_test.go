// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/asn1"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func TestWorkloadSPIFFESegmentCodecIsCanonicalAndReversible(t *testing.T) {
	for _, tc := range []struct{ raw, wire string }{
		{"web", "web"}, {"repo:org", "trstctl-hex-7265706f3a6f7267"},
		{"agent/7", "trstctl-hex-6167656e742f37"},
		{"trstctl-hex-a", "trstctl-hex-7472737463746c2d6865782d61"},
	} {
		wire, err := EncodeWorkloadSPIFFESegment(tc.raw)
		if err != nil || wire != tc.wire {
			t.Fatalf("unexpected canonical mapping for %q", tc.raw)
		}
		raw, err := DecodeWorkloadSPIFFESegment(tc.wire)
		if err != nil || raw != tc.raw {
			t.Fatalf("mapping is not reversible for %q", tc.raw)
		}
	}
	for _, wire := range []string{"", ".", "..", "a/b", "trstctl-hex-", "trstctl-hex-zz", "trstctl-hex-2e", "trstctl-hex-776562", "trstctl-hex-613A62", strings.Repeat("a", MaxSPIFFEIDLength+1)} {
		if _, err := DecodeWorkloadSPIFFESegment(wire); err == nil {
			t.Errorf("accepted invalid or noncanonical segment %q", wire)
		}
	}
	if err := quick.Check(func(raw string) bool {
		wire, err := EncodeWorkloadSPIFFESegment(raw)
		if err != nil || len(wire) > MaxSPIFFEIDLength {
			return true
		}
		decoded, err := DecodeWorkloadSPIFFESegment(wire)
		return err == nil && raw == decoded
	}, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}

type workloadNamespaceCountingSigner struct {
	DigestSigner
	calls int
}

func (s *workloadNamespaceCountingSigner) SignDigest(digest []byte, options SignOptions) ([]byte, error) {
	s.calls++
	return s.DigestSigner.SignDigest(digest, options)
}

func TestLeafProfilesCannotMintReservedWorkloadIdentities(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	ca, err := SelfSignedCACert(key, "Reserved workload namespace test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	for _, uri := range []string{
		"spiffe://served.test/_trstctl/v1/tenant/other/broker/agent-7",
		"spiffe://served.test/_trstctl",
		"spiffe://served.test/%5ftrstctl/v1/tenant/other",
		"SPIFFE://served.test/_trstctl/v1/tenant/other",
		"spiffe://served.test/other/../_trstctl/v1/tenant/other",
	} {
		csr, err := CreateCertificateRequest(CertificateRequestTemplate{URIs: []string{uri}}, leafKey)
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range []LeafProfile{{}, {PermittedURIPrefixes: []string{"spiffe://served.test/"}}} {
			signer := &workloadNamespaceCountingSigner{DigestSigner: key}
			der, err := SignLeafFromCSRWithProfile(ca, signer, csr, time.Minute, profile)
			if err == nil || !IsLeafProfileViolation(err) || len(der) != 0 || signer.calls != 0 {
				t.Errorf("ordinary CSR reached signing or was accepted for reserved URI %q (signs=%d)", uri, signer.calls)
			}
			// Opaque licensed subject algorithms enter through this same
			// backend-agnostic profile check after their signature verifier.
			if err := EnforceLeafProfileInfo(CSRInfo{URIs: []string{uri}}, time.Minute, profile); err == nil || !IsLeafProfileViolation(err) {
				t.Errorf("shared profile check allowed reserved URI %q", uri)
			}
		}
	}
}

func TestLeafProfilesPreserveNonReservedSPIFFEAndOrdinaryURIs(t *testing.T) {
	for _, uri := range []string{"spiffe://customer.example/ns/prod/service", "spiffe://customer.example/_trstctl-other/workload", "https://example.test/_trstctl/v1"} {
		if err := EnforceLeafProfileInfo(CSRInfo{URIs: []string{uri}}, time.Minute, LeafProfile{}); err != nil {
			t.Errorf("unrelated identity was rejected: %q: %v", uri, err)
		}
	}
}

func TestLeafProfileExtraExtensionsCannotOverrideIdentityPolicy(t *testing.T) {
	for _, oid := range []string{"2.5.29.17", "2.5.29.017", "2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.14", "2.5.29.35", "2.5.29.30", "2.5.29.31", "2.5.29.32", "1.3.6.1.5.5.7.1.1"} {
		profile := LeafProfile{ExtraExtensions: []CertificateExtension{{OID: oid, Value: []byte{0x05, 0x00}}}}
		if err := EnforceLeafProfileInfo(CSRInfo{}, time.Minute, profile); err == nil || !IsLeafProfileViolation(err) {
			t.Errorf("extra extension %s can override a core leaf-policy field", oid)
		}
	}
	// Prove the SAN override is real: a harmless CSR must not gain a protected
	// workload URI from ExtraExtensions after its parsed SANs were checked.
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	ca, err := SelfSignedCACert(key, "Extra extension guard test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "ordinary.example"}, key)
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte("spiffe://served.test/_trstctl/v1/tenant/other/attested/method/k8s_sat/subject/admin")}})
	if err != nil {
		t.Fatal(err)
	}
	signer := &workloadNamespaceCountingSigner{DigestSigner: key}
	der, err := SignLeafFromCSRWithProfile(ca, signer, csr, time.Minute, LeafProfile{ExtraExtensions: []CertificateExtension{{OID: "2.5.29.17", Value: san}}})
	if err == nil || !IsLeafProfileViolation(err) || len(der) != 0 || signer.calls != 0 {
		t.Fatal("extra SAN extension bypassed the validated CSR identity before signing")
	}
	if err := EnforceLeafProfileInfo(CSRInfo{}, time.Minute, LeafProfile{ExtraExtensions: []CertificateExtension{{OID: "1.3.6.1.4.1.57264.99.1", Value: []byte{0x05, 0x00}}}}); err != nil {
		t.Fatalf("non-core extension compatibility was lost: %v", err)
	}
}
