// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

const (
	// HybridLeafExtensionOID identifies the trstctl hybrid transition extension.
	HybridLeafExtensionOID = "1.3.6.1.4.1.59551.2.2"

	// CompositeMLDSA44ECDSAP256SHA256OID is the composite ML-DSA-44 + ECDSA
	// P-256 algorithm identifier from draft-ietf-lamps-pq-composite-sigs-19.
	// The draft uses the prior-art PKIX AlgorithmIdentifier pattern: an OID
	// names a compile-time algorithm mapping; no runtime engine/provider registry
	// is involved.
	CompositeMLDSA44ECDSAP256SHA256OID = "1.3.6.1.5.5.7.6.40"
)

var (
	oidCompositeMLDSA44ECDSAP256SHA256 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 40}
	oidTrstctlHybridLeaf               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59551, 2, 2}
)

type hybridLeafExtension struct {
	CompositeAlgorithm asn1.ObjectIdentifier
	MLDSAAlgorithm     string
	TraditionalAlg     string
	MLDSAPublicKey     []byte
	TraditionalPubKey  []byte
	CompositePublicKey []byte
	ProofSignature     []byte
}

// HybridLeafInfo is the crypto-free view of the hybrid X.509 extension carried
// by a served hybrid leaf.
type HybridLeafInfo struct {
	CompositeAlgorithmOID string
	MLDSAAlgorithm        boundarycrypto.Algorithm
	TraditionalAlgorithm  boundarycrypto.Algorithm
	MLDSAPublicKey        []byte
	TraditionalPublicKey  []byte
	CompositePublicKey    []byte
	ProofSignature        []byte
}

// HybridLeafCSRExtraExtension builds the non-critical CSR extension a requester
// includes when it wants the served CA to issue a hybrid transition leaf. The
// requester controls both component keys: the traditional key signs the CSR, and
// the ML-DSA key signs the draft-style composite public key
// (ML-DSA public key || ECDSA public key) as proof of possession.
func HybridLeafCSRExtraExtension(traditional boundarycrypto.PublicKey, mldsa boundarycrypto.Signer) (boundarycrypto.CertificateExtension, error) {
	if traditional.Algorithm != boundarycrypto.ECDSAP256 {
		return boundarycrypto.CertificateExtension{}, fmt.Errorf("pqc: hybrid CSR requires ECDSA-P256 traditional key, got %s", traditional.Algorithm)
	}
	if mldsa.Algorithm() != MLDSA44 {
		return boundarycrypto.CertificateExtension{}, fmt.Errorf("pqc: hybrid CSR requires ML-DSA-44 key, got %s", mldsa.Algorithm())
	}
	tradPub, err := ecdsaP256PublicKeyDER(traditional.DER)
	if err != nil {
		return boundarycrypto.CertificateExtension{}, err
	}
	value, err := marshalHybridLeafExtension(mldsa.Public().DER, tradPub, mldsa)
	if err != nil {
		return boundarycrypto.CertificateExtension{}, err
	}
	return boundarycrypto.CertificateExtension{
		OID:      HybridLeafExtensionOID,
		Critical: false,
		Value:    value,
	}, nil
}

// SignHybridLeafFromCSRWithProfile issues a classical ECDSA-P256 leaf that also
// carries the requester's ML-DSA-44 public key in a signed, non-critical
// dual/composite extension copied from the CSR after verification. The extension
// uses the composite draft's public-key serialization rule (ML-DSA public key ||
// traditional public key) and includes an ML-DSA proof over that composite key,
// so a PQ-aware client can verify that the issued certificate binds both
// component keys.
func SignHybridLeafFromCSRWithProfile(caCertDER []byte, caSigner boundarycrypto.DigestSigner, csrDER []byte, ttl time.Duration, prof boundarycrypto.LeafProfile) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("pqc: parse hybrid CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pqc: hybrid CSR signature: %w", err)
	}
	tradPub, err := ecdsaP256PublicKey(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	value, err := verifiedHybridCSRExtension(csr.Extensions, tradPub)
	if err != nil {
		return nil, err
	}
	prof.ExtraExtensions = append(append([]boundarycrypto.CertificateExtension(nil), prof.ExtraExtensions...), boundarycrypto.CertificateExtension{
		OID:      HybridLeafExtensionOID,
		Critical: false,
		Value:    value,
	})
	return boundarycrypto.SignLeafFromCSRWithProfile(caCertDER, caSigner, csrDER, ttl, prof)
}

// InspectHybridCSR verifies the hybrid proof extension and reports whether the
// licensed signer path must handle this CSR. The MPL core receives only the
// boolean decision through the edition seam.
func InspectHybridCSR(csrDER []byte, _ boundarycrypto.CSRInfo) (bool, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return false, fmt.Errorf("pqc: parse hybrid CSR: %w", err)
	}
	tradPub, err := ecdsaP256PublicKey(csr.PublicKey)
	if err != nil {
		return false, nil
	}
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidTrstctlHybridLeaf) {
			continue
		}
		if _, err := verifiedHybridCSRExtension(csr.Extensions, tradPub); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func marshalHybridLeafExtension(mldsaPub, tradPub []byte, mldsa boundarycrypto.Signer) ([]byte, error) {
	compositePub := make([]byte, 0, len(mldsaPub)+len(tradPub))
	compositePub = append(compositePub, mldsaPub...)
	compositePub = append(compositePub, tradPub...)
	proof, err := mldsa.Sign(compositePub, boundarycrypto.SignOptions{})
	if err != nil {
		return nil, fmt.Errorf("pqc: sign hybrid key proof: %w", err)
	}
	value, err := asn1.Marshal(hybridLeafExtension{
		CompositeAlgorithm: oidCompositeMLDSA44ECDSAP256SHA256,
		MLDSAAlgorithm:     string(MLDSA44),
		TraditionalAlg:     string(boundarycrypto.ECDSAP256),
		MLDSAPublicKey:     append([]byte(nil), mldsaPub...),
		TraditionalPubKey:  append([]byte(nil), tradPub...),
		CompositePublicKey: compositePub,
		ProofSignature:     proof,
	})
	if err != nil {
		return nil, fmt.Errorf("pqc: marshal hybrid certificate extension: %w", err)
	}
	return value, nil
}

func verifiedHybridCSRExtension(exts []pkix.Extension, tradPub []byte) ([]byte, error) {
	for _, ext := range exts {
		if !ext.Id.Equal(oidTrstctlHybridLeaf) {
			continue
		}
		if ext.Critical {
			return nil, errors.New("pqc: hybrid CSR extension must be non-critical")
		}
		if err := verifyHybridLeafExtensionValue(ext.Value, tradPub); err != nil {
			return nil, err
		}
		return append([]byte(nil), ext.Value...), nil
	}
	return nil, errors.New("pqc: hybrid CSR extension absent")
}

func verifyHybridLeafExtensionValue(value, tradPub []byte) error {
	var encoded hybridLeafExtension
	rest, err := asn1.Unmarshal(value, &encoded)
	if err != nil {
		return fmt.Errorf("pqc: parse hybrid extension: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("pqc: hybrid extension has trailing data")
	}
	if !encoded.CompositeAlgorithm.Equal(oidCompositeMLDSA44ECDSAP256SHA256) {
		return fmt.Errorf("pqc: unsupported hybrid composite OID %s", encoded.CompositeAlgorithm.String())
	}
	if boundarycrypto.Algorithm(encoded.MLDSAAlgorithm) != MLDSA44 || boundarycrypto.Algorithm(encoded.TraditionalAlg) != boundarycrypto.ECDSAP256 {
		return fmt.Errorf("pqc: unsupported hybrid components %s + %s", encoded.MLDSAAlgorithm, encoded.TraditionalAlg)
	}
	if !bytes.Equal(tradPub, encoded.TraditionalPubKey) {
		return errors.New("pqc: hybrid extension traditional public key does not match CSR/certificate SPKI")
	}
	wantComposite := make([]byte, 0, len(encoded.MLDSAPublicKey)+len(tradPub))
	wantComposite = append(wantComposite, encoded.MLDSAPublicKey...)
	wantComposite = append(wantComposite, tradPub...)
	if !bytes.Equal(wantComposite, encoded.CompositePublicKey) {
		return errors.New("pqc: hybrid composite public key is not ML-DSA || ECDSA")
	}
	return Verify(boundarycrypto.PublicKey{Algorithm: MLDSA44, DER: encoded.MLDSAPublicKey}, encoded.CompositePublicKey, encoded.ProofSignature)
}

// InspectHybridLeaf extracts the hybrid X.509 extension from a leaf certificate.
func InspectHybridLeaf(leafDER []byte) (HybridLeafInfo, error) {
	cert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return HybridLeafInfo{}, fmt.Errorf("pqc: parse hybrid leaf: %w", err)
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidTrstctlHybridLeaf) {
			continue
		}
		var encoded hybridLeafExtension
		rest, err := asn1.Unmarshal(ext.Value, &encoded)
		if err != nil {
			return HybridLeafInfo{}, fmt.Errorf("pqc: parse hybrid extension: %w", err)
		}
		if len(rest) != 0 {
			return HybridLeafInfo{}, errors.New("pqc: hybrid extension has trailing data")
		}
		return HybridLeafInfo{
			CompositeAlgorithmOID: encoded.CompositeAlgorithm.String(),
			MLDSAAlgorithm:        boundarycrypto.Algorithm(encoded.MLDSAAlgorithm),
			TraditionalAlgorithm:  boundarycrypto.Algorithm(encoded.TraditionalAlg),
			MLDSAPublicKey:        append([]byte(nil), encoded.MLDSAPublicKey...),
			TraditionalPublicKey:  append([]byte(nil), encoded.TraditionalPubKey...),
			CompositePublicKey:    append([]byte(nil), encoded.CompositePublicKey...),
			ProofSignature:        append([]byte(nil), encoded.ProofSignature...),
		}, nil
	}
	return HybridLeafInfo{}, errors.New("pqc: hybrid leaf extension absent")
}

// VerifyHybridLeaf checks that the hybrid extension is internally consistent
// with the certificate's classical subject public key and with the ML-DSA proof.
func VerifyHybridLeaf(leafDER []byte) error {
	cert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("pqc: parse hybrid leaf: %w", err)
	}
	info, err := InspectHybridLeaf(leafDER)
	if err != nil {
		return err
	}
	if info.CompositeAlgorithmOID != CompositeMLDSA44ECDSAP256SHA256OID {
		return fmt.Errorf("pqc: unsupported hybrid composite OID %s", info.CompositeAlgorithmOID)
	}
	if info.MLDSAAlgorithm != MLDSA44 || info.TraditionalAlgorithm != boundarycrypto.ECDSAP256 {
		return fmt.Errorf("pqc: unsupported hybrid components %s + %s", info.MLDSAAlgorithm, info.TraditionalAlgorithm)
	}
	tradPub, err := ecdsaP256PublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidTrstctlHybridLeaf) {
			return verifyHybridLeafExtensionValue(ext.Value, tradPub)
		}
	}
	return errors.New("pqc: hybrid leaf extension absent")
}

func ecdsaP256PublicKey(pub any) ([]byte, error) {
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pqc: hybrid leaf requires ECDSA-P256 CSR/public key, got %T", pub)
	}
	if ecdsaPub.Curve == nil || ecdsaPub.Curve.Params().Name != "P-256" {
		return nil, errors.New("pqc: hybrid leaf requires ECDSA-P256 public key")
	}
	ecdhPub, err := ecdsaPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("pqc: invalid ECDSA-P256 public key: %w", err)
	}
	encoded := ecdhPub.Bytes()
	if len(encoded) == 0 {
		return nil, errors.New("pqc: invalid ECDSA-P256 public key")
	}
	return encoded, nil
}

func ecdsaP256PublicKeyDER(der []byte) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("pqc: parse ECDSA-P256 public key: %w", err)
	}
	return ecdsaP256PublicKey(pub)
}
