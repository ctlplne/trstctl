// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// CreateOpaqueCertificateRequest builds a PKCS#10 for a message-signing subject
// algorithm not implemented by crypto/x509. The caller supplies the exact OID
// and a Signer whose Public().DER contains the algorithm's raw public bytes.
// AlgorithmIdentifier parameters are absent, as required for ML-DSA.
//
// The ordinary CSR encoder preserves all requested names, EKUs and extensions.
// Its temporary key is destroyed and never becomes the requested subject key.
// Only the final request body, carrying the real subject key, is signed by the
// supplied signer. The algorithm owner must verify the resulting proof before
// accepting it; this function makes no claim about a caller-supplied OID.
func CreateOpaqueCertificateRequest(tmpl CertificateRequestTemplate, algorithmOID string, signer Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("crypto: opaque CSR requires subject signer")
	}
	oid, err := parseOID(algorithmOID)
	if err != nil {
		return nil, fmt.Errorf("crypto: opaque CSR algorithm: %w", err)
	}
	public := signer.Public().DER
	if len(public) == 0 {
		return nil, errors.New("crypto: opaque CSR subject key is empty")
	}
	metadataKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		return nil, err
	}
	defer metadataKey.Destroy()
	metadata, err := CreateCertificateRequest(tmpl, metadataKey)
	if err != nil {
		return nil, err
	}
	var request opaqueCertificateRequest
	if rest, err := asn1.Unmarshal(metadata, &request); err != nil || len(rest) != 0 {
		return nil, errors.New("crypto: decode opaque CSR metadata")
	}
	request.TBS.Raw = nil
	request.TBS.PublicKey = opaquePublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: append([]byte(nil), public...), BitLength: len(public) * 8},
	}
	tbs, err := asn1.Marshal(request.TBS)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(tbs, SignOptions{})
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, errors.New("crypto: opaque CSR signer returned no signature")
	}
	request.TBS.Raw = tbs
	request.SignatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oid}
	request.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	return asn1.Marshal(request)
}

type opaqueCertificateRequest struct {
	TBS                opaqueCertificateRequestInfo
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type opaqueCertificateRequestInfo struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	PublicKey  opaquePublicKeyInfo
	Attributes []asn1.RawValue `asn1:"tag:0"`
}
