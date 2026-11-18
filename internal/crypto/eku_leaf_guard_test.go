// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// CR-052: the leaf signers never put ocspSigning or anyExtendedKeyUsage on a
// leaf, whichever form the profile names it in. ocspSigning makes a leaf a
// delegated OCSP responder for every certificate its CA issued (RFC 6960
// 4.2.2.2); the platform's own responder certificate is built separately. A
// CA that refuses timeStamping (the platform issuing CA) signs no such leaf.
func TestLeafSignersNeverIssueOCSPSigningOrAnyEKU(t *testing.T) {
	for _, ekus := range [][]string{
		{"ocspSigning"}, {"serverAuth", "ocspSigning"}, {"any"}, {"clientAuth", "any"},
		{"1.3.6.1.5.5.7.3.9"}, {"oid:1.3.6.1.5.5.7.3.9"}, {"2.5.29.37.0"}, {" 2.5.29.37.0 "},
	} {
		for _, refuseTimeStamping := range []bool{false, true} {
			if _, _, err := leafExtKeyUsage(ekus, refuseTimeStamping); err == nil {
				t.Errorf("leaf extended key usages %q were accepted", ekus)
			}
		}
	}
	known, custom, err := leafExtKeyUsage([]string{"serverAuth", "codeSigning", "1.3.6.1.4.1.311.10.3.12"}, true)
	if err != nil || len(known) != 2 || len(custom) != 1 {
		t.Fatalf("ordinary extended key usages: known %v custom %v (%v)", known, custom, err)
	}
	// A CA whose own timestamping certificate anchors trust (the platform
	// issuing CA) signs no other timeStamping leaf; another CA may.
	for _, ekus := range [][]string{{"timeStamping"}, {"serverAuth", "TimeStamping"}, {"1.3.6.1.5.5.7.3.8"}, {"oid:1.3.6.1.5.5.7.3.8"}} {
		if _, _, err := leafExtKeyUsage(ekus, true); err == nil {
			t.Errorf("a timeStamping leaf %q was accepted where the CA refuses timeStamping", ekus)
		}
	}
	if _, _, err := leafExtKeyUsage([]string{"timeStamping"}, false); err != nil {
		t.Errorf("a CA that allows timeStamping refused it: %v", err)
	}

	caKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := SelfSignedCACert(caKey, "CR-052 test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "leaf.cr052.test", DNSNames: []string{"leaf.cr052.test"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, LeafProfile{AllowedExtKeyUsage: []string{"serverAuth", "ocspSigning"}}); err == nil {
		t.Fatal("a leaf carrying ocspSigning was signed")
	}
	if _, err := SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, LeafProfile{AllowedExtKeyUsage: []string{"serverAuth"}}); err != nil {
		t.Fatalf("an ordinary serverAuth leaf was refused: %v", err)
	}
	if _, err := SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, LeafProfile{AllowedExtKeyUsage: []string{"timeStamping"}, RefuseTimeStamping: true}); err == nil || !IsLeafProfileViolation(err) {
		t.Fatalf("a timeStamping leaf was signed where the CA refuses it (%v)", err)
	}
}

// A retained leaf template binds the JSON encoding of its LeafProfile
// (issuance_preparation.go), so a retry after an upgrade must see the same
// encoding: RefuseTimeStamping, which the served choke points always set, is
// not part of it, and the encoding of a zero profile is pinned so the next
// field added to LeafProfile cannot change retained bindings unnoticed (CR-052
// review 2; AN-5).
func TestLeafTemplateEncodingIsUnchangedByRefuseTimeStamping(t *testing.T) {
	with, err := json.Marshal(LeafProfile{AllowedExtKeyUsage: []string{"serverAuth"}, RefuseTimeStamping: true})
	if err != nil {
		t.Fatal(err)
	}
	without, err := json.Marshal(LeafProfile{AllowedExtKeyUsage: []string{"serverAuth"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(with, without) {
		t.Fatalf("RefuseTimeStamping changed the retained-template encoding:\n%s\n%s", with, without)
	}
	zero, err := json.Marshal(LeafProfile{})
	if err != nil {
		t.Fatal(err)
	}
	// The digest at bfe1b14b1, before RefuseTimeStamping existed. Change it only
	// with a plan for templates retained under the previous encoding.
	if got := SHA256Hex(zero); got != "6b6eba677ed4e3491ef6f2e9fd5fdc5957fb0e06e0e91ffbfaf799946b83ca74" {
		t.Fatalf("the LeafProfile JSON encoding changed (sha256 %s): %s", got, zero)
	}
}
