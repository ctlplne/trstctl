// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// CreateRetainedHostKeyCSR signs a public CSR with a key already installed on
// the host. The caller retains and wipes privateKeyPEM; this function never
// returns private material. expectedSPKISHA256 is the predecessor certificate's
// pinned public-key digest, so a replaced key cannot silently become the key
// for a CA re-protection request.
func CreateRetainedHostKeyCSR(privateKeyPEM []byte, commonName string, dnsNames []string, expectedSPKISHA256 string) ([]byte, error) {
	commonName = strings.TrimSpace(commonName)
	cleaned := make([]string, 0, len(dnsNames))
	for _, name := range dnsNames {
		if name = strings.TrimSpace(name); name != "" {
			cleaned = append(cleaned, name)
		}
	}
	if commonName == "" && len(cleaned) == 0 {
		return nil, ErrNoSubjectNames
	}
	if commonName == "" {
		commonName = cleaned[0]
	}
	want, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(expectedSPKISHA256)), "sha256:"))
	if err != nil || len(want) != 32 {
		return nil, errors.New("crypto: predecessor SPKI SHA-256 is required")
	}
	defer secret.Wipe(want)

	trimmed := bytes.TrimSpace(privateKeyPEM)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, errors.New("crypto: installed private key must be one exact PEM block")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, errors.New("crypto: installed private key must be one unencrypted PEM block")
	}
	defer secret.Wipe(block.Bytes)

	signer, err := lockedRetainedHostSigner(block)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()
	got := SHA256Sum(signer.Public().DER)
	defer secret.Wipe(got)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, errors.New("crypto: installed subject key differs from pinned predecessor SPKI")
	}
	return CreateCertificateRequest(CertificateRequestTemplate{CommonName: commonName, DNSNames: cleaned}, signer)
}

func lockedRetainedHostSigner(block *pem.Block) (*LockedSigner, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return LockedKeyFromPKCS8(block.Bytes)
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse installed EC private key: %w", err)
		}
		defer wipeStdlibKey(key)
		return lockRetainedHostKey(key)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse installed RSA private key: %w", err)
		}
		defer wipeStdlibKey(key)
		return lockRetainedHostKey(key)
	default:
		return nil, fmt.Errorf("crypto: unsupported installed private-key PEM type %q", block.Type)
	}
}

func lockRetainedHostKey(key any) (*LockedSigner, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: encode installed private key for locked use: %w", err)
	}
	defer secret.Wipe(der)
	return LockedKeyFromPKCS8(der)
}
