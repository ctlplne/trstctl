// SPDX-License-Identifier: MPL-2.0

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
	info, err := InspectCSR(block.Bytes)
	if err != nil {
		return nil, CSRInfo{}, err
	}
	return block.Bytes, info, nil
}
