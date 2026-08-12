// SPDX-License-Identifier: MPL-2.0

package crypto

import "encoding/pem"

// EncodeCertificatePEM wraps certificate DER without leaking encoding/pem to
// callers that must stay behind the AN-3 crypto boundary.
func EncodeCertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
