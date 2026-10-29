// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"
)

func TestSVIDPreparationPreservesExactSigningInput(t *testing.T) {
	ca, key := clampTestCA(t, time.Hour)
	workload, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(workload.Destroy)
	prepared, err := NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	prepared.ValidityAnchor = prepared.ValidityAnchor.Add(-time.Minute)
	journal := &opaquePreparationJournal{DigestSigner: key}
	const identity = "spiffe://prepared.test/workload"
	first, err := SignSVIDWithPreparation(ca, journal, workload.Public().DER, identity, 10*time.Minute, prepared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignSVIDWithPreparation(ca, journal, workload.Public().DER, identity, 10*time.Minute, prepared)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || journal.calls != 2 || journal.signatures != 1 ||
		!bytes.Equal(leaf.SerialNumber.Bytes(), prepared.Serial) ||
		!leaf.NotBefore.Equal(IssuanceNotBefore(prepared.ValidityAnchor).Truncate(time.Second)) ||
		!leaf.NotAfter.Equal(prepared.ValidityAnchor.Add(10*time.Minute).Truncate(time.Second)) {
		t.Fatal("SVID retry changed its serial, validity, signing digest or signature")
	}
	if _, err := SignSVIDWithPreparation(ca, journal, workload.Public().DER, identity, 11*time.Minute, prepared); err == nil {
		t.Fatal("changed lifetime reused an operation signature")
	}
	if _, err := SignSVIDWithPreparation(ca, journal, workload.Public().DER, identity+"/changed", 10*time.Minute, prepared); err == nil {
		t.Fatal("changed SPIFFE identity reused an operation signature")
	}
	counted := &countingDigestSigner{DigestSigner: key}
	for _, invalid := range []LeafPreparation{{}, {Serial: []byte{0}, ValidityAnchor: prepared.ValidityAnchor}, {Serial: []byte{0, 1}, ValidityAnchor: prepared.ValidityAnchor}, {Serial: bytes.Repeat([]byte{1}, 17), ValidityAnchor: prepared.ValidityAnchor}, {Serial: []byte{1}, ValidityAnchor: prepared.ValidityAnchor.Add(time.Nanosecond)}} {
		if der, err := SignSVIDWithPreparation(ca, counted, workload.Public().DER, identity, time.Minute, invalid); err == nil || len(der) != 0 || counted.calls != 0 {
			t.Fatal("invalid retained preparation reached the signer")
		}
	}
}
