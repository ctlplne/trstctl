// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	MLDSA44OID = "2.16.840.1.101.3.4.3.17"
	MLDSA65OID = "2.16.840.1.101.3.4.3.18"
	MLDSA87OID = "2.16.840.1.101.3.4.3.19"
)

// ParsePureMLDSACSR is the licensed parser seam for RFC 9881 PKCS#10
// requests. recognized is false only when the request uses no ML-DSA OID. Once
// either the subject or signature claims ML-DSA, every field is checked
// strictly and a malformed or mixed-algorithm request fails closed.
func ParsePureMLDSACSR(csrDER []byte) (info boundarycrypto.CSRInfo, recognized bool, err error) {
	opaque, err := boundarycrypto.InspectOpaqueCSR(csrDER)
	if err != nil {
		return boundarycrypto.CSRInfo{}, false, err
	}
	alg, pubSize, ok := mldsaAlgorithmForOID(opaque.PublicKeyAlgorithmOID)
	_, _, sigClaimsMLDSA := mldsaAlgorithmForOID(opaque.SignatureAlgorithmOID)
	if !ok && !sigClaimsMLDSA {
		return boundarycrypto.CSRInfo{}, false, nil
	}
	if !ok || opaque.SignatureAlgorithmOID != opaque.PublicKeyAlgorithmOID {
		return boundarycrypto.CSRInfo{}, true, errors.New("pqc: ML-DSA CSR subject and signature algorithms must match")
	}
	if len(opaque.PublicKeyAlgorithmParamsDER) != 0 || len(opaque.SignatureAlgorithmParamsDER) != 0 {
		return boundarycrypto.CSRInfo{}, true, errors.New("pqc: RFC 9881 ML-DSA AlgorithmIdentifier parameters must be absent")
	}
	scheme, ok := schemeFor(alg)
	if !ok {
		return boundarycrypto.CSRInfo{}, true, fmt.Errorf("pqc: unsupported ML-DSA algorithm %s", alg)
	}
	if len(opaque.PublicKeyBytes) != pubSize || len(opaque.Signature) != scheme.SignatureSize() {
		return boundarycrypto.CSRInfo{}, true, fmt.Errorf("pqc: malformed %s CSR public key or signature length", alg)
	}
	if err := Verify(boundarycrypto.PublicKey{Algorithm: alg, DER: opaque.PublicKeyBytes}, opaque.RawTBS, opaque.Signature); err != nil {
		return boundarycrypto.CSRInfo{}, true, fmt.Errorf("pqc: ML-DSA CSR proof of possession: %w", err)
	}
	info = opaque.Info
	info.KeyAlgorithm = string(alg)
	info.KeyBits = len(opaque.PublicKeyBytes) * 8
	return info, true, nil
}

// SignLicensedLeafFromCSRWithProfile dispatches the single PQC attach seam to
// either an RFC 9881 pure ML-DSA subject leaf or the deployable hybrid
// transition leaf. The issuing CA operation remains inside internal/crypto and
// its out-of-process DigestSigner.
func SignLicensedLeafFromCSRWithProfile(caCertDER []byte, caSigner boundarycrypto.DigestSigner, csrDER []byte, ttl time.Duration, prof boundarycrypto.LeafProfile) ([]byte, error) {
	info, pure, err := ParsePureMLDSACSR(csrDER)
	if err != nil {
		return nil, err
	}
	if !pure {
		return SignHybridLeafFromCSRWithProfile(caCertDER, caSigner, csrDER, ttl, prof)
	}
	opaque, err := boundarycrypto.InspectOpaqueCSR(csrDER)
	if err != nil {
		return nil, err
	}
	return boundarycrypto.SignOpaqueLeafFromVerifiedRequestWithProfile(caCertDER, caSigner, boundarycrypto.OpaqueLeafRequest{
		Info: info, RawSubject: opaque.RawSubject,
		SubjectPublicKeyInfoDER: opaque.RawSubjectPublicKeyInfo,
		SignatureOnly:           true,
	}, ttl, prof)
}

// GenerateInteroperableMLDSAKey derives an ML-DSA key from a fresh 32-byte
// FIPS 204 seed and returns both a locked signer and an RFC 9881 seed-form
// PKCS#8 value. The PKCS#8 bytes are intentionally exportable only for the
// local SPIFFE Workload API response; the caller must wipe them after send.
func GenerateInteroperableMLDSAKey(alg boundarycrypto.Algorithm) (*Signer, []byte, error) {
	scheme, ok := schemeFor(alg)
	if !ok || (alg != MLDSA44 && alg != MLDSA65 && alg != MLDSA87) {
		return nil, nil, fmt.Errorf("pqc: interoperable key requires ML-DSA, got %s", alg)
	}
	seed, err := boundarycrypto.RandomBytes(scheme.SeedSize())
	if err != nil {
		return nil, nil, err
	}
	defer secret.Wipe(seed)
	pub, priv := scheme.DeriveKey(seed)
	defer boundarycrypto.WipeBinaryPrivateKey(priv)
	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	defer secret.Wipe(privBytes)
	signer, err := NewSignerFromPrivateKey(alg, privBytes)
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		signer.Destroy()
		return nil, nil, err
	}
	if !bytes.Equal(pubBytes, signer.Public().DER) {
		signer.Destroy()
		return nil, nil, errors.New("pqc: derived ML-DSA public key mismatch")
	}
	seedChoice, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, Bytes: append([]byte(nil), seed...)})
	if err != nil {
		signer.Destroy()
		return nil, nil, err
	}
	defer secret.Wipe(seedChoice)
	pkcs8, err := boundarycrypto.MarshalOpaquePKCS8(mldsaOID(alg), seedChoice)
	if err != nil {
		signer.Destroy()
		return nil, nil, err
	}
	return signer, pkcs8, nil
}

func mldsaOID(alg boundarycrypto.Algorithm) string {
	switch alg {
	case MLDSA44:
		return MLDSA44OID
	case MLDSA65:
		return MLDSA65OID
	case MLDSA87:
		return MLDSA87OID
	default:
		return ""
	}
}

func mldsaAlgorithmForOID(oid string) (boundarycrypto.Algorithm, int, bool) {
	switch oid {
	case MLDSA44OID:
		return MLDSA44, 1312, true
	case MLDSA65OID:
		return MLDSA65, 1952, true
	case MLDSA87OID:
		return MLDSA87, 2592, true
	default:
		return "", 0, false
	}
}
