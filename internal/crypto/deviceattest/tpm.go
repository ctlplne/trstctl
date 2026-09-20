// SPDX-License-Identifier: BUSL-1.1

// Package deviceattest isolates reviewed, high-dependency attestation parsers
// below the crypto boundary without adding them to the sacred signer's lean
// internal/crypto dependency closure.
package deviceattest

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

const maxDeviceAttestationBytes = 1 << 20

// TPMDeviceAttestationResult is the small, backend-neutral result exported
// through the crypto boundary after every binary structure and signature has
// been checked by the reviewed parser.
type TPMDeviceAttestationResult struct {
	PublicKeySHA256              []byte
	AttestationCertificateSHA256 []byte
	Algorithm                    int64
}

// ParseAndVerifyTPMDeviceAttestation verifies one TPM WebAuthn attestation. The
// operator roots are the complete trust decision: this function performs no
// metadata fetch and therefore cannot phone home.
func ParseAndVerifyTPMDeviceAttestation(
	credentialJSON []byte,
	challenge []byte,
	trustedRootsPEM [][]byte,
	allowedAlgorithms []int64,
	now time.Time,
) (TPMDeviceAttestationResult, error) {
	if len(credentialJSON) == 0 || len(credentialJSON) > maxDeviceAttestationBytes {
		return TPMDeviceAttestationResult{}, errors.New("crypto: TPM attestation payload has invalid size")
	}
	if len(challenge) == 0 || len(challenge) > 1024 {
		return TPMDeviceAttestationResult{}, errors.New("crypto: TPM attestation challenge has invalid size")
	}
	if len(trustedRootsPEM) == 0 || len(allowedAlgorithms) == 0 {
		return TPMDeviceAttestationResult{}, errors.New("crypto: TPM attestation trust policy is incomplete")
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(credentialJSON)
	if err != nil {
		return TPMDeviceAttestationResult{}, fmt.Errorf("crypto: parse TPM WebAuthn response: %w", err)
	}
	if parsed.Response.CollectedClientData.Type != protocol.CreateCeremony {
		return TPMDeviceAttestationResult{}, errors.New("crypto: TPM attestation is not a credential creation ceremony")
	}
	expectedChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	if subtle.ConstantTimeCompare(
		[]byte(parsed.Response.CollectedClientData.Challenge),
		[]byte(expectedChallenge),
	) != 1 {
		return TPMDeviceAttestationResult{}, errors.New("crypto: TPM attestation challenge mismatch")
	}
	if parsed.Response.AttestationObject.Format != "tpm" {
		return TPMDeviceAttestationResult{}, fmt.Errorf(
			"crypto: attestation format %q is not TPM",
			parsed.Response.AttestationObject.Format,
		)
	}

	var keyHeader webauthncose.PublicKeyData
	if err := webauthncbor.Unmarshal(
		parsed.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
		&keyHeader,
	); err != nil {
		return TPMDeviceAttestationResult{}, fmt.Errorf("crypto: parse TPM credential algorithm: %w", err)
	}
	if !containsInt64(allowedAlgorithms, keyHeader.Algorithm) {
		return TPMDeviceAttestationResult{}, fmt.Errorf("crypto: TPM credential algorithm %d is not allowed", keyHeader.Algorithm)
	}

	clientHash := sha256.Sum256(parsed.Raw.AttestationResponse.ClientDataJSON)
	if err := parsed.Response.AttestationObject.VerifyAttestation(clientHash[:], nil); err != nil {
		return TPMDeviceAttestationResult{}, fmt.Errorf("crypto: verify TPM attestation statement: %w", err)
	}

	certificates, err := tpmAttestationCertificates(parsed.Response.AttestationObject.AttStatement["x5c"])
	if err != nil {
		return TPMDeviceAttestationResult{}, err
	}
	roots, err := parseTPMAttestationRoots(trustedRootsPEM)
	if err != nil {
		return TPMDeviceAttestationResult{}, err
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := certificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return TPMDeviceAttestationResult{}, fmt.Errorf("crypto: TPM attestation chain is not trusted: %w", err)
	}

	publicKeyDER, err := tpmCredentialPublicKeyDER(
		parsed.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
	)
	if err != nil {
		return TPMDeviceAttestationResult{}, err
	}
	publicKeyDigest := sha256.Sum256(publicKeyDER)
	certificateDigest := sha256.Sum256(certificates[0].Raw)
	return TPMDeviceAttestationResult{
		PublicKeySHA256:              append([]byte(nil), publicKeyDigest[:]...),
		AttestationCertificateSHA256: append([]byte(nil), certificateDigest[:]...),
		Algorithm:                    keyHeader.Algorithm,
	}, nil
}

// CSRPublicKeySHA256 verifies a PKCS#10 request and returns the stable SPKI
// digest used to bind device-attest-01 to finalization.
func CSRPublicKeySHA256(csrDER []byte) ([]byte, error) {
	if len(csrDER) == 0 || len(csrDER) > maxDeviceAttestationBytes {
		return nil, errors.New("crypto: CSR has invalid size")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CSR for key binding: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("crypto: verify CSR for key binding: %w", err)
	}
	digest := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	return append([]byte(nil), digest[:]...), nil
}

func tpmAttestationCertificates(value any) ([]*x509.Certificate, error) {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return nil, errors.New("crypto: TPM attestation x5c chain is missing")
	}
	certificates := make([]*x509.Certificate, 0, len(items))
	for i, item := range items {
		raw, ok := item.([]byte)
		if !ok || len(raw) == 0 {
			return nil, fmt.Errorf("crypto: TPM attestation x5c certificate %d is invalid", i)
		}
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse TPM attestation x5c certificate %d: %w", i, err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func parseTPMAttestationRoots(rootsPEM [][]byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	count := 0
	for i, raw := range rootsPEM {
		if len(raw) > maxDeviceAttestationBytes {
			return nil, fmt.Errorf("crypto: TPM attestation root %d is too large", i)
		}
		rest := raw
		for len(rest) > 0 {
			block, next := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = next
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("crypto: parse TPM attestation root %d: %w", i, err)
			}
			roots.AddCert(certificate)
			count++
		}
	}
	if count == 0 {
		return nil, errors.New("crypto: TPM attestation policy contains no valid root certificate")
	}
	return roots, nil
}

func tpmCredentialPublicKeyDER(coseKey []byte) ([]byte, error) {
	parsed, err := webauthncose.ParsePublicKey(coseKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse TPM credential public key: %w", err)
	}
	switch key := parsed.(type) {
	case webauthncose.EC2PublicKeyData:
		publicKey, err := key.ToECDSA()
		if err != nil {
			return nil, fmt.Errorf("crypto: convert TPM EC credential key: %w", err)
		}
		return x509.MarshalPKIXPublicKey(publicKey)
	case webauthncose.RSAPublicKeyData:
		exponent := new(big.Int).SetBytes(key.Exponent)
		if !exponent.IsInt64() || exponent.Sign() <= 0 || exponent.Int64() > math.MaxInt32 {
			return nil, errors.New("crypto: TPM RSA credential exponent is invalid")
		}
		return x509.MarshalPKIXPublicKey(&rsa.PublicKey{
			N: new(big.Int).SetBytes(key.Modulus),
			E: int(exponent.Int64()),
		})
	default:
		return nil, fmt.Errorf("crypto: TPM credential key type %T is unsupported", parsed)
	}
}

func containsInt64(values []int64, want int64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
