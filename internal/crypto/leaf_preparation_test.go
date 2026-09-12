// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"
)

func TestLeafPreparationRetainsSignedSerialAndValidity(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	ca, err := SelfSignedCACert(key, "preparation CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "prepared.test", DNSNames: []string{"prepared.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	// A recorded clock from before this call, not the current signing clock.
	prepared.ValidityAnchor = prepared.ValidityAnchor.Add(-time.Minute)
	issued, err := SignLeafFromCSRWithPreparation(ca, key, csr, 10*time.Minute, LeafProfile{ClampTTLToIssuer: true}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(issued.DER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.SerialNumber.Bytes(), prepared.Serial) || !issued.ValidityAnchor.Equal(prepared.ValidityAnchor) ||
		!cert.NotAfter.Equal(prepared.ValidityAnchor.Add(10*time.Minute).Truncate(time.Second)) ||
		!cert.NotBefore.Equal(IssuanceNotBefore(prepared.ValidityAnchor).Truncate(time.Second)) {
		t.Fatal("leaf did not retain its prepared serial and validity bounds")
	}
	for _, invalid := range []LeafPreparation{
		{}, {Serial: []byte{0}, ValidityAnchor: prepared.ValidityAnchor},
		{Serial: []byte{0, 1}, ValidityAnchor: prepared.ValidityAnchor},
		{Serial: bytes.Repeat([]byte{1}, 17), ValidityAnchor: prepared.ValidityAnchor},
		{Serial: []byte{1}, ValidityAnchor: prepared.ValidityAnchor.Add(time.Nanosecond)},
	} {
		if leaf, err := SignLeafFromCSRWithPreparation(ca, key, csr, time.Minute, LeafProfile{}, invalid); err == nil || len(leaf.DER) != 0 {
			t.Fatal("invalid persisted preparation was accepted")
		}
	}
}
