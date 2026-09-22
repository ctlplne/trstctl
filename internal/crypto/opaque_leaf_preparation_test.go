// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestOpaqueLeafPreparationRetainsCertificateAcrossRetries(t *testing.T) {
	ca, key := clampTestCA(t, time.Hour)
	prepared, err := NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	prepared.ValidityAnchor = prepared.ValidityAnchor.Add(-time.Minute)
	request := opaquePreparationRequest(t)
	journal := &opaquePreparationJournal{DigestSigner: key}
	first, err := SignOpaqueLeafFromVerifiedRequestWithPreparation(ca, journal, request, 24*time.Hour, LeafProfile{ClampTTLToIssuer: true}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignOpaqueLeafFromVerifiedRequestWithPreparation(ca, journal, request, 24*time.Hour, LeafProfile{ClampTTLToIssuer: true}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.DER, second.DER) || journal.signatures != 1 || journal.calls != 2 {
		t.Fatal("retry changed the prepared certificate or required a new signature")
	}
	leaf, err := x509.ParseCertificate(first.DER)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(ca)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.SerialNumber.Bytes(), prepared.Serial) || !first.ValidityAnchor.Equal(prepared.ValidityAnchor) || !second.ValidityAnchor.Equal(prepared.ValidityAnchor) || !leaf.NotBefore.Equal(IssuanceNotBefore(prepared.ValidityAnchor).Truncate(time.Second)) || !leaf.NotAfter.Equal(issuer.NotAfter) {
		t.Fatal("serial or issuer-clamped validity changed")
	}
	if err := VerifyLeafSignedByCA(first.DER, ca); err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Info.CommonName = "different.example.test"
	if _, err := SignOpaqueLeafFromVerifiedRequestWithPreparation(ca, journal, changed, 24*time.Hour, LeafProfile{ClampTTLToIssuer: true}, prepared); err == nil {
		t.Fatal("a changed request reused an existing operation signature")
	}
}

func TestOpaqueLeafPreparationRejectsInvalidRetainedInputsBeforeSigning(t *testing.T) {
	ca, key := clampTestCA(t, time.Hour)
	prepared, err := NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []LeafPreparation{{}, {Serial: []byte{0}, ValidityAnchor: prepared.ValidityAnchor}, {Serial: []byte{0, 1}, ValidityAnchor: prepared.ValidityAnchor}, {Serial: bytes.Repeat([]byte{1}, 17), ValidityAnchor: prepared.ValidityAnchor}, {Serial: []byte{1}, ValidityAnchor: prepared.ValidityAnchor.Add(time.Nanosecond)}, {Serial: []byte{1}, ValidityAnchor: prepared.ValidityAnchor.Add(2 * time.Hour)}} {
		counted := &countingDigestSigner{DigestSigner: key}
		leaf, err := SignOpaqueLeafFromVerifiedRequestWithPreparation(ca, counted, opaquePreparationRequest(t), time.Minute, LeafProfile{ClampTTLToIssuer: true}, invalid)
		if err == nil || len(leaf.DER) != 0 || counted.calls != 0 {
			t.Fatalf("invalid preparation accepted: err=%v calls=%d", err, counted.calls)
		}
	}
}

func TestOpaqueLeafPreparationCannotReopenExpiredIssuer(t *testing.T) {
	ca, key := clampTestCA(t, -time.Hour)
	prepared, err := NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	prepared.ValidityAnchor = prepared.ValidityAnchor.Add(-2 * time.Hour)
	counted := &countingDigestSigner{DigestSigner: key}
	leaf, err := SignOpaqueLeafFromVerifiedRequestWithPreparation(ca, counted, opaquePreparationRequest(t), time.Minute, LeafProfile{ClampTTLToIssuer: true}, prepared)
	if !IsLeafProfileViolation(err) || len(leaf.DER) != 0 || counted.calls != 0 {
		t.Fatalf("old preparation reopened expired issuer: %v calls=%d", err, counted.calls)
	}
}

// A small receiver journal: the real isolated signer owns the production
// operation record. This independently checks that the constructor hands it
// exactly the same digest across retries, even though metadata keys are fresh.
type opaquePreparationJournal struct {
	DigestSigner
	digest, signature []byte
	opts              SignOptions
	signatures, calls int
}

func (s *opaquePreparationJournal) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	s.calls++
	if s.signature != nil {
		if !bytes.Equal(digest, s.digest) || opts != s.opts {
			return nil, errors.New("operation binding changed")
		}
		return append([]byte(nil), s.signature...), nil
	}
	sig, err := s.DigestSigner.SignDigest(digest, opts)
	if err != nil {
		return nil, err
	}
	s.digest = append([]byte(nil), digest...)
	s.signature = append([]byte(nil), sig...)
	s.opts = opts
	s.signatures++
	return sig, nil
}
