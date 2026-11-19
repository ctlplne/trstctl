// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	MaxPublicChainBytes          = 256 * 1024
	MaxPublicCertificatePEMBytes = 1 << 20
)

// ParsePublicPEMChain parses an exact public-only, leaf-first PEM envelope. It checks
// the retained leaf identity and preserves certificate order. It does not grant
// trust to its last certificate or establish current time/hostname validity;
// the receiving TLS client must use independently authorized trust anchors.
func ParsePublicPEMChain(raw, expectedLeafDER []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxPublicChainBytes || len(expectedLeafDER) == 0 {
		return nil, errors.New("certinfo: bounded public chain and exact leaf required")
	}
	return canonicalPublicPEM(raw, expectedLeafDER, MaxPublicChainBytes, 8)
}

// NormalizePublicCertificatePEM returns a bounded envelope of exact X.509
// CERTIFICATE blocks, in input order, encoded from their parsed DER.
func NormalizePublicCertificatePEM(raw []byte) ([]byte, error) {
	if len(raw) > MaxPublicCertificatePEMBytes {
		return nil, errors.New("certinfo: public certificate bundle exceeds 1 MiB")
	}
	return canonicalPublicPEM(raw, nil, MaxPublicCertificatePEMBytes, 0)
}

func canonicalPublicPEM(raw, expectedLeafDER []byte, maxBytes, maxCertificates int) ([]byte, error) {
	rest := bytes.TrimSpace(raw)
	var result []byte
	for count := 0; len(rest) != 0; count++ {
		if maxCertificates > 0 && count >= maxCertificates {
			return nil, errors.New("certinfo: too many certificates in public chain")
		}
		der, next, err := consumePublicCertificate(rest)
		if err != nil {
			return nil, err
		}
		if count == 0 && expectedLeafDER != nil && !bytes.Equal(der, expectedLeafDER) {
			return nil, errors.New("certinfo: public chain belongs to another leaf")
		}
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		if len(result) > maxBytes {
			return nil, errors.New("certinfo: canonical public certificate envelope exceeds its size limit")
		}
		rest = bytes.TrimSpace(next)
	}
	if len(result) == 0 {
		return nil, errors.New("certinfo: public certificate envelope must contain at least one certificate")
	}
	return result, nil
}

// consumePublicCertificate restricts pem.Decode to one complete block. PEM
// decoding of the entire remaining stream can skip data before a valid block.
func consumePublicCertificate(rest []byte) (der, next []byte, err error) {
	beginMarker := []byte("-----BEGIN CERTIFICATE-----")
	endMarker := []byte("-----END CERTIFICATE-----")
	if !bytes.HasPrefix(rest, beginMarker) {
		return nil, nil, errors.New("certinfo: public certificate envelope must contain only CERTIFICATE blocks")
	}
	end := bytes.Index(rest, endMarker)
	if end < 0 {
		return nil, nil, errors.New("certinfo: incomplete public certificate PEM")
	}
	end += len(endMarker)
	section := rest[:end]
	if bytes.Count(section, beginMarker) != 1 {
		return nil, nil, errors.New("certinfo: nested or skipped public certificate PEM")
	}
	block, trailing := pem.Decode(section)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, nil, errors.New("certinfo: malformed public certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, errors.New("certinfo: public certificate does not parse")
	}
	return cert.Raw, rest[end:], nil
}
