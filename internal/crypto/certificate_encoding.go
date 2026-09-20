// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/pem"
	"errors"
)

// EncodeCertificatePEM wraps certificate DER without leaking encoding/pem to
// callers that must stay behind the AN-3 crypto boundary.
func EncodeCertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// NormalizeCertificateDER accepts one certificate encoded as PEM or DER and
// returns its DER bytes. PEM decoding stays inside the AN-3 boundary and is
// deliberately strict: a bundle, a private-key block, or trailing material is
// not an unambiguous trust root.
func NormalizeCertificateDER(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("crypto: certificate is empty")
	}
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		// DER is binary. A signature may legitimately end in a byte that ASCII
		// classifies as whitespace, so trimming it would corrupt real roots.
		return append([]byte(nil), raw...), nil
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
		return nil, errors.New("crypto: PEM trust root must contain one CERTIFICATE block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("crypto: PEM trust root contains trailing or multiple blocks")
	}
	return append([]byte(nil), block.Bytes...), nil
}
