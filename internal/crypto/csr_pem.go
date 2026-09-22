// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/pem"
	"errors"
)

// ParsePublicCSRPEM accepts one bounded, public PKCS#10 envelope and verifies its
// signature. It rejects skipped, nested or additional PEM blocks before decoding;
// pem.Decode alone searches past malformed input for a later usable block.
func ParsePublicCSRPEM(raw []byte) ([]byte, CSRInfo, error) {
	return ParsePublicCSRPEMWithInspector(raw, InspectCSR)
}

// ParsePublicCSRPEMWithInspector applies the same bounded, exact PEM envelope
// contract before calling a trusted algorithm-aware proof verifier. The verifier
// must check possession of every requested key; extracting fields is insufficient.
// A nil verifier fails closed and no partial result escapes a verification error.
func ParsePublicCSRPEMWithInspector(raw []byte, inspect func([]byte) (CSRInfo, error)) ([]byte, CSRInfo, error) {
	if inspect == nil {
		return nil, CSRInfo{}, errors.New("crypto: public CSR proof verifier is required")
	}
	if len(raw) == 0 || len(raw) > 64*1024 {
		return nil, CSRInfo{}, errors.New("crypto: public CSR must fit 64 KiB")
	}
	input := bytes.TrimSpace(raw)
	if (!bytes.HasPrefix(input, []byte("-----BEGIN CERTIFICATE REQUEST-----")) &&
		!bytes.HasPrefix(input, []byte("-----BEGIN NEW CERTIFICATE REQUEST-----"))) ||
		bytes.Count(input, []byte("-----BEGIN ")) != 1 ||
		bytes.Count(input, []byte("-----END ")) != 1 {
		return nil, CSRInfo{}, errors.New("crypto: expected exactly one public CSR PEM block")
	}
	block, rest := pem.Decode(input)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") ||
		len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, CSRInfo{}, errors.New("crypto: malformed or additional public CSR data")
	}
	info, err := inspect(block.Bytes)
	if err != nil {
		return nil, CSRInfo{}, err
	}
	return block.Bytes, info, nil
}
