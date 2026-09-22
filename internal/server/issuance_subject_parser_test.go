// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/store"
)

func subjectAdmissionDispatcher() *issuanceDispatcher {
	return &issuanceDispatcher{parseSubjectCSR: pqc.ParsePureMLDSACSR, inspectHybridSubjectCSR: pqc.InspectHybridCSR}
}

func TestPQCSubjectAdmissionPreservesAllNamesAndRejectsWidenedHostBinding(t *testing.T) {
	d := subjectAdmissionDispatcher()
	for _, algorithm := range []crypto.Algorithm{pqc.MLDSA44, pqc.MLDSA65, pqc.MLDSA87} {
		t.Run(string(algorithm), func(t *testing.T) {
			for name, change := range map[string]func(*crypto.CertificateRequestTemplate){
				"allowed":       func(*crypto.CertificateRequestTemplate) {},
				"different-dns": func(t *crypto.CertificateRequestTemplate) { t.DNSNames = append(t.DNSNames, "other.example.test") },
				"different-cn":  func(t *crypto.CertificateRequestTemplate) { t.CommonName = "other.example.test" },
				"ip":            func(t *crypto.CertificateRequestTemplate) { t.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} },
				"email":         func(t *crypto.CertificateRequestTemplate) { t.EmailAddresses = []string{"admin@example.test"} },
				"uri":           func(t *crypto.CertificateRequestTemplate) { t.URIs = []string{"spiffe://other.example.test/admin"} },
			} {
				t.Run(name, func(t *testing.T) {
					tmpl := crypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}
					change(&tmpl)
					key, err := pqc.GenerateHostMLDSASubjectKey(tmpl, algorithm)
					if err != nil {
						t.Fatal(err)
					}
					defer key.Destroy()
					info, err := d.inspectSubjectCSR(key.CSRDER)
					if err != nil || info.KeyAlgorithm != string(algorithm) || info.CommonName != tmpl.CommonName ||
						!sameRenewalIdentifiers(info.DNSNames, tmpl.DNSNames) || !sameRenewalIdentifiers(info.IPAddresses, subjectAdmissionIPStrings(tmpl.IPAddresses)) ||
						!sameRenewalIdentifiers(info.EmailAddresses, tmpl.EmailAddresses) || !sameRenewalIdentifiers(info.URIs, tmpl.URIs) {
						t.Fatalf("verified algorithm or identifiers were changed: %v", err)
					}
					err = authorizeAgentCSRWithInspector(key.CSRDER, []string{"api.example.test"}, d.inspectSubjectCSR)
					if name == "allowed" && err != nil {
						t.Fatal(err)
					}
					if name != "allowed" && status.Code(err) != codes.PermissionDenied {
						t.Fatalf("widened binding: %v", err)
					}
					bad := bytes.Clone(key.CSRDER)
					bad[len(bad)-1] ^= 1
					if err := authorizeAgentCSRWithInspector(bad, []string{"api.example.test"}, d.inspectSubjectCSR); status.Code(err) != codes.InvalidArgument {
						t.Fatalf("invalid possession proof was not rejected before name admission: %v", err)
					}
					if _, _, err := inspectSubjectCSR(key.CSRDER, nil, nil); err == nil {
						t.Fatal("absent runtime accepted pure PQC")
					}
				})
			}
		})
	}
}

func TestPQCSubjectAdmissionVerifiesHybridProofAlongsideClassicalSignature(t *testing.T) {
	d := subjectAdmissionDispatcher()
	classical, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer classical.Destroy()
	postQuantum, err := pqc.GenerateKey(pqc.MLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	defer postQuantum.Destroy()
	ext, err := pqc.HybridLeafCSRExtraExtension(classical.Public(), postQuantum)
	if err != nil {
		t.Fatal(err)
	}
	for _, corruptProof := range []bool{false, true} {
		copied := ext
		copied.Value = bytes.Clone(ext.Value)
		if corruptProof {
			copied.Value[len(copied.Value)-1] ^= 1
		}
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}, ExtraExtensions: []crypto.CertificateExtension{copied}}, classical)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := crypto.InspectCSR(der); err != nil {
			t.Fatal("classical positive control:", err)
		}
		_, hybrid, err := inspectSubjectCSR(der, d.parseSubjectCSR, d.inspectHybridSubjectCSR)
		if corruptProof && err == nil {
			t.Fatal("classical signature concealed invalid PQC proof")
		}
		if !corruptProof && (err != nil || !hybrid) {
			t.Fatalf("valid hybrid refused: %v", err)
		}
	}
}

func TestPQCRequesterRenewalRetainsExactSubjectAndEnvelope(t *testing.T) {
	d := subjectAdmissionDispatcher()
	tmpl := crypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}
	key, err := pqc.GenerateHostMLDSASubjectKey(tmpl, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.CSRDER})
	der, names, err := decodeSubjectCSRWithInspector(raw, d.inspectSubjectCSR)
	if err != nil || !bytes.Equal(der, key.CSRDER) || !sameRenewalIdentifiers(names, tmpl.DNSNames) {
		t.Fatalf("PQC envelope: %v", err)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "PQC renewal test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pqc.SignLicensedLeafFromCSRWithProfile(caDER, ca, key.CSRDER, time.Minute, crypto.LeafProfile{ClampTTLToIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(leaf)
	if err != nil {
		t.Fatal(err)
	}
	predecessor := store.Certificate{CertificateDER: leaf, Fingerprint: info.SHA256Fingerprint}
	if err := validateRequesterRenewalCSRWithInspector(raw, predecessor, d.inspectSubjectCSR); err != nil {
		t.Fatal(err)
	}
	other, err := pqc.GenerateHostMLDSASubjectKey(tmpl, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	wrongKey := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: other.CSRDER})
	for name, candidate := range map[string][]byte{
		"changed-key":     wrongKey,
		"second-envelope": append(bytes.Clone(raw), raw...),
		"junk-prefix":     append([]byte("junk\n"), raw...),
		"trailing-bytes":  append(bytes.Clone(raw), []byte("junk")...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRequesterRenewalCSRWithInspector(candidate, predecessor, d.inspectSubjectCSR); err == nil {
				t.Fatal("unauthorized renewal accepted")
			}
		})
	}
	predecessor.Fingerprint = "wrong"
	if err := validateRequesterRenewalCSRWithInspector(raw, predecessor, d.inspectSubjectCSR); err == nil {
		t.Fatal("mismatched predecessor fingerprint accepted")
	}
}

func subjectAdmissionIPStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
