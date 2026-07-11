// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"encoding/pem"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// GenerateUploadableRSAKeypair creates a transient RSA private key plus an X.509
// wrapper for its public key. Cloud APIs such as GCP IAM's service-account key
// upload accept the certificate while the private bytes remain inside trstctl's
// sealed issuance command until handed to the authorized workload. The caller
// owns and must wipe privateKeyPEM.
func GenerateUploadableRSAKeypair(ttl time.Duration) (privateKeyPEM, certificatePEM []byte, err error) {
	if ttl <= 0 {
		return nil, nil, errors.New("crypto: uploadable key TTL must be positive")
	}
	key, err := GenerateLockedKey(RSA2048)
	if err != nil {
		return nil, nil, err
	}
	defer key.Destroy()
	certDER, err := SelfSignedCACert(key, "trstctl dynamic workload key", ttl)
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM, err = key.PrivateKeyPEM()
	if err != nil {
		return nil, nil, err
	}
	certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if certificatePEM == nil {
		return nil, nil, errors.New("crypto: encode uploadable public certificate")
	}
	return privateKeyPEM, certificatePEM, nil
}

// SignUploadableRSAKey proves possession of a private key returned by
// GenerateUploadableRSAKeypair without exposing crypto/rsa or crypto/x509 outside
// the boundary. It is used by interoperability probes and workload adapters.
func SignUploadableRSAKey(privateKeyPEM, message []byte) ([]byte, error) {
	block, rest := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("crypto: invalid uploadable RSA private key PEM")
	}
	defer secret.Wipe(block.Bytes)
	signer, err := NewLockedSignerFromPKCS8(RSA2048, block.Bytes)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()
	digest := SHA256Sum(message)
	defer secret.Wipe(digest)
	return signer.SignDigest(digest, SignOptions{Hash: SHA256, RSAPadding: RSAPKCS1v15})
}
