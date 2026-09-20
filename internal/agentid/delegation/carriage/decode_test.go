// SPDX-License-Identifier: BUSL-1.1

package carriage_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agentid/delegation/carriage"
	"trstctl.com/trstctl/internal/crypto"
)

// TestX509_CriticalExtensionRejected proves the non-critical requirement is ENFORCED on
// decode: an AGID extension marked critical is rejected fail-closed (ErrExtensionCritical),
// both from a bare extension and from a real certificate carrying a critical AGID
// extension. Non-critical carriage keeps a legacy relying party able to parse the cert; a
// critical AGID extension is a malformed/hostile carriage.
func TestX509_CriticalExtensionRejected(t *testing.T) {
	bv := carriage.BoundValues{ChainHeadDigest: bytes.Repeat([]byte{0x01}, 32), ComparatorVersion: "v"}

	// A hand-built CRITICAL extension carrying a valid AGID payload.
	payload, err := json.Marshal(bv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	der, err := asn1.Marshal(payload)
	if err != nil {
		t.Fatalf("asn1: %v", err)
	}
	critExt := crypto.CertificateExtension{OID: carriage.AGIDCarriageOIDString, Critical: true, Value: der}
	if _, err := carriage.DecodeExtension(critExt); !errors.Is(err, carriage.ErrExtensionCritical) {
		t.Fatalf("DecodeExtension(critical) err = %v, want ErrExtensionCritical", err)
	}

	// The same, stamped onto a real certificate: DecodeCertificate must also reject it.
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "AGID Critical Test CA", time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "agent.leaf"}, leafKey)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		ExtraExtensions: []crypto.CertificateExtension{critExt},
	})
	if err != nil {
		t.Fatalf("mint leaf: %v", err)
	}
	if _, err := carriage.DecodeCertificate(leafDER); !errors.Is(err, carriage.ErrExtensionCritical) {
		t.Fatalf("DecodeCertificate(critical) err = %v, want ErrExtensionCritical", err)
	}
}

// TestDecode_NoAGIDCarriage proves each decoder fails closed with a distinguishable
// "no AGID carriage" error on a well-formed credential form that simply carries no AGID
// binding (a plain certificate; a JSON document/token without the binding claim).
func TestDecode_NoAGIDCarriage(t *testing.T) {
	// A plain certificate with no AGID extension.
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	defer caKey.Destroy()
	plainCert, err := crypto.SelfSignedCACert(caKey, "plain", time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}
	if _, err := carriage.DecodeCertificate(plainCert); !errors.Is(err, carriage.ErrNoAGIDCarriage) {
		t.Fatalf("DecodeCertificate(plain) err = %v, want ErrNoAGIDCarriage", err)
	}

	// A workload-identity document with no binding claim.
	if _, err := carriage.DecodeWorkloadDoc([]byte(`{"sub":"x","aud":"y"}`)); !errors.Is(err, carriage.ErrNoBindingClaim) {
		t.Fatalf("DecodeWorkloadDoc(no-claim) err = %v, want ErrNoBindingClaim", err)
	}

	// A JWT-shaped token whose claims carry no binding claim.
	tok, err := crypto.SignJWT(caKey, "k", map[string]string{"sub": "x"})
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	if _, err := carriage.DecodeToken([]byte(tok)); !errors.Is(err, carriage.ErrNoBindingClaim) {
		t.Fatalf("DecodeToken(no-claim) err = %v, want ErrNoBindingClaim", err)
	}
}

// TestDecode_MalformedFailsClosed proves malformed carriage payloads fail closed rather
// than yielding a value.
func TestDecode_MalformedFailsClosed(t *testing.T) {
	if _, err := carriage.DecodeCertificate([]byte("garbage")); !errors.Is(err, carriage.ErrMalformedCarriage) {
		t.Fatalf("DecodeCertificate(garbage) err = %v, want ErrMalformedCarriage", err)
	}
	if _, err := carriage.DecodeWorkloadDoc([]byte("not json")); !errors.Is(err, carriage.ErrMalformedCarriage) {
		t.Fatalf("DecodeWorkloadDoc(garbage) err = %v, want ErrMalformedCarriage", err)
	}
	if _, err := carriage.DecodeToken([]byte("only.two")); !errors.Is(err, carriage.ErrMalformedToken) {
		t.Fatalf("DecodeToken(two-seg) err = %v, want ErrMalformedToken", err)
	}
}

// TestDecodeVerifiedToken_BadSignatureRejected proves the verified-token path fails closed
// when the signature does not verify against the JWKS (a wrong key), routing verification
// through internal/crypto (AN-3).
func TestDecodeVerifiedToken_BadSignatureRejected(t *testing.T) {
	signKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("sign key: %v", err)
	}
	defer signKey.Destroy()
	tok, err := carriage.EncodeSignedToken(signKey, "kid-1",
		carriage.BoundValues{ChainHeadDigest: bytes.Repeat([]byte{0x09}, 32), ComparatorVersion: "v"},
		"sub", "aud", "iss")
	if err != nil {
		t.Fatalf("EncodeSignedToken: %v", err)
	}
	// A DIFFERENT key's JWKS must reject the token.
	otherKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	defer otherKey.Destroy()
	otherJWK, err := crypto.PublicJWK(otherKey.Public(), "kid-1")
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	if _, err := carriage.DecodeVerifiedToken(tok, crypto.JWKS{Keys: []crypto.JWK{otherJWK}}); err == nil {
		t.Fatal("DecodeVerifiedToken accepted a token signed by a different key")
	}
}
