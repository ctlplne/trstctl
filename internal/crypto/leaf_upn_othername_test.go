// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"
)

// A160-L1: a CSR's UPN otherName SAN never reaches an issued leaf. No issuing
// profile can express a user principal name, so the leaf carries only the SAN
// kinds a profile checks (DNS, IP, email, URI) taken from the parsed request;
// the otherName is dropped, never copied through as a raw extension.
func TestCSRUPNOtherNameNeverReachesTheLeafA160L1(t *testing.T) {
	ca, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := SelfSignedCACert(ca, "A160-L1 test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()

	const upn = "alice@corp.example"
	upnValue, err := asn1.MarshalWithParams(upn, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: upnValue})
	if err != nil {
		t.Fatal(err)
	}
	upnOID, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("laptop-17.corp.example")},
		{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(upnOID, explicit...)},
	})
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := CreateCertificateRequest(CertificateRequestTemplate{
		CommonName:      "laptop-17.corp.example",
		ExtraExtensions: []CertificateExtension{{OID: "2.5.29.17", Value: san}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := SignLeafFromCSRWithProfile(caDER, ca, csrDER, time.Hour, LeafProfile{})
	if err != nil {
		t.Fatalf("sign the CSR: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "laptop-17.corp.example" {
		t.Fatalf("leaf DNS names = %v, want the requested DNS name", leaf.DNSNames)
	}
	if bytes.Contains(leafDER, []byte(upn)) {
		t.Fatal("the issued leaf carries the CSR's user principal name")
	}
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &names); err != nil || len(rest) != 0 {
			t.Fatalf("leaf SAN does not parse: %v", err)
		}
		for _, name := range names {
			if name.Class == asn1.ClassContextSpecific && name.Tag == 0 {
				t.Fatal("the issued leaf's SAN carries an otherName")
			}
		}
	}
}
