// SPDX-License-Identifier: BUSL-1.1

package deviceattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
)

// CreateEdgeTPMCredential wraps a real TPM2_Certify result in the WebAuthn TPM
// envelope required by the control plane. Both public handles are checked
// against the actual TPM objects before any credential leaves this host.
func CreateEdgeTPMCredential(tenantID, segmentID string, csrDER []byte, edgeHandle, aikHandle trstcrypto.EdgeCAKeyHandle, aikChainPEM, aikAuth []byte, certifier trstcrypto.EdgeTPMCertifier) ([]byte, error) {
	if certifier == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(segmentID) == "" {
		return nil, fmt.Errorf("crypto: edge TPM attestation needs a device, tenant and segment")
	}
	if edgeHandle.Provider != "tpm2" || aikHandle.Provider != "tpm2" || edgeHandle.KeyID == "" || aikHandle.KeyID == "" || edgeHandle.KeyID == aikHandle.KeyID {
		return nil, fmt.Errorf("crypto: edge and attestation handles must be distinct TPM2 signing objects")
	}
	if edgeHandle.Version != 1 || aikHandle.Version != 1 || edgeHandle.Algorithm != trstcrypto.ECDSAP256 || aikHandle.Algorithm != trstcrypto.ECDSAP256 {
		return nil, fmt.Errorf("crypto: edge and attestation TPM handles need the current P-256 format")
	}
	if len(csrDER) == 0 || len(csrDER) > maxDeviceAttestationBytes || len(aikChainPEM) == 0 || len(aikChainPEM) > maxDeviceAttestationBytes {
		return nil, fmt.Errorf("crypto: edge CSR or attestation certificate chain has invalid size")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return nil, fmt.Errorf("crypto: edge CSR is invalid or unsigned")
	}
	csrPublicDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !bytes.Equal(csrPublicDER, edgeHandle.PublicKeyDER) {
		return nil, fmt.Errorf("crypto: edge CSR key differs from its TPM handle")
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("crypto: edge TPM WebAuthn credential requires ECDSA P-256")
	}
	chain, err := parseEdgeAIKChain(aikChainPEM)
	if err != nil {
		return nil, err
	}
	if len(chain) < 2 {
		return nil, fmt.Errorf("crypto: AIK chain must include its configured trust anchor")
	}
	if !bytes.Equal(chain[0].RawSubjectPublicKeyInfo, aikHandle.PublicKeyDER) {
		return nil, fmt.Errorf("crypto: attestation certificate does not match its TPM handle")
	}
	challenge := trstcrypto.EdgeAttestationChallenge(tenantID, segmentID, csrDER)
	clientDataJSON, err := json.Marshal(map[string]any{
		"type": "webauthn.create", "challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin": "https://trstctl.invalid", "crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	// PublicKey.Bytes is the validated, uncompressed P-256 point. Slicing its
	// fixed-width coordinates avoids the deprecated mutable big.Int fields.
	point, err := publicKey.Bytes()
	if err != nil || len(point) != 65 || point[0] != 4 {
		return nil, fmt.Errorf("crypto: invalid P-256 edge public point")
	}
	coseKey, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         int64(webauthncose.P256),
		XCoord:        point[1:33],
		YCoord:        point[33:65],
	})
	if err != nil {
		return nil, err
	}
	credentialID := sha256.Sum256(coseKey)
	authData := make([]byte, 0, 32+1+4+16+2+len(credentialID)+len(coseKey))
	rpIDHash := sha256.Sum256([]byte("trstctl.invalid"))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, byte(0x41)) // user present, attested credential data
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credentialID)))
	authData = append(authData, credentialID[:]...)
	authData = append(authData, coseKey...)
	clientHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte(nil), authData...), clientHash[:]...)
	qualifyingData := sha256.Sum256(signed)
	certified, err := certifier.CertifyEdgeKey(edgeHandle.KeyID, aikHandle.KeyID, qualifyingData[:], aikAuth)
	if err != nil {
		return nil, fmt.Errorf("crypto: TPM2_Certify edge key: %w", err)
	}
	if !bytes.Equal(certified.ObjectPublicKeyDER, csrPublicDER) || !bytes.Equal(certified.SignerPublicKeyDER, aikHandle.PublicKeyDER) {
		return nil, fmt.Errorf("crypto: certified TPM object or signer differs from the reviewed handles")
	}
	if len(certified.PublicArea) == 0 || len(certified.CertInfo) == 0 || len(certified.SignatureDER) == 0 {
		return nil, fmt.Errorf("crypto: TPM2_Certify returned incomplete evidence")
	}
	x5c := make([]any, 0, len(chain))
	for _, certificate := range chain {
		x5c = append(x5c, certificate.Raw)
	}
	attestationObject, err := webauthncbor.Marshal(map[string]any{
		"fmt": "tpm", "authData": authData,
		"attStmt": map[string]any{
			"ver": "2.0", "alg": int64(webauthncose.AlgES256), "x5c": x5c,
			"sig": certified.SignatureDER, "certInfo": certified.CertInfo, "pubArea": certified.PublicArea,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("crypto: encode TPM attestation: %w", err)
	}
	credential, err := json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credentialID[:]),
		"rawId": base64.RawURLEncoding.EncodeToString(credentialID[:]), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		},
	})
	if err != nil {
		return nil, err
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[len(chain)-1].Raw})
	verified, err := ParseAndVerifyTPMDeviceAttestation(credential, challenge, [][]byte{rootPEM}, []int64{int64(webauthncose.AlgES256)}, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("crypto: local TPM attestation verification: %w", err)
	}
	csrKeyDigest := sha256.Sum256(csrPublicDER)
	if !bytes.Equal(verified.PublicKeySHA256, csrKeyDigest[:]) {
		return nil, fmt.Errorf("crypto: TPM attestation did not certify the CSR key")
	}
	return credential, nil
}

func parseEdgeAIKChain(raw []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for len(raw) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			if len(bytes.TrimSpace(raw)) > 0 {
				return nil, fmt.Errorf("crypto: invalid attestation certificate chain PEM")
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(chain) >= 8 {
			return nil, fmt.Errorf("crypto: attestation chain contains a non-certificate or exceeds eight certificates")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse attestation certificate: %w", err)
		}
		chain = append(chain, certificate)
		raw = rest
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("crypto: attestation certificate chain is empty")
	}
	return chain, nil
}
