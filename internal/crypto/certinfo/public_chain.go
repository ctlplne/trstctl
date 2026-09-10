// SPDX-License-Identifier: MPL-2.0

package certinfo

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const MaxPublicChainBytes = 256 * 1024

// ParsePublicPEMChain parses an exact public-only, leaf-first PEM envelope. It checks
// the retained leaf identity and preserves certificate order. It does not grant
// trust to its last certificate or establish current time/hostname validity;
// the receiving TLS client must use independently authorized trust anchors.
func ParsePublicPEMChain(raw, expectedLeafDER []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxPublicChainBytes || len(expectedLeafDER) == 0 {
		return nil, errors.New("certinfo: bounded public chain and exact leaf required")
	}
	rest := bytes.TrimSpace(raw)
	var result []byte
	for count := 0; len(rest) != 0; count++ {
		if count >= 8 || !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("certinfo: public chain has extra or non-certificate data")
		}
		endMarker := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(rest, endMarker)
		if end < 0 {
			return nil, errors.New("certinfo: incomplete public certificate PEM")
		}
		end += len(endMarker)
		section := rest[:end]
		if bytes.Count(section, []byte("-----BEGIN CERTIFICATE-----")) != 1 {
			return nil, errors.New("certinfo: nested or skipped public certificate PEM")
		}
		block, trailing := pem.Decode(section)
		if len(bytes.TrimSpace(trailing)) != 0 {
			return nil, errors.New("certinfo: extra public certificate data")
		}
		next := rest[end:]
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("certinfo: malformed public certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("certinfo: invalid certificate in public chain")
		}
		if count == 0 && !bytes.Equal(cert.Raw, expectedLeafDER) {
			return nil, errors.New("certinfo: public chain belongs to another leaf")
		}
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		rest = bytes.TrimSpace(next)
	}
	if len(result) == 0 || len(result) > MaxPublicChainBytes {
		return nil, errors.New("certinfo: invalid public chain length")
	}
	return result, nil
}
