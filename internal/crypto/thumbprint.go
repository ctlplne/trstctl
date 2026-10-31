// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/sha1" // #nosec G505 -- a certificate's SHA-1 thumbprint is the identifier some CA APIs address it by; it proves nothing (CWE-328)
	"encoding/hex"
	"strings"
)

// CertificateSHA1Thumbprint is the upper-case hex SHA-1 of a certificate's DER,
// the identifier some CA APIs address a certificate by (A164). It names a
// certificate; it is never used to decide whether one is genuine.
func CertificateSHA1Thumbprint(der []byte) string {
	sum := sha1.Sum(der) // #nosec G401 -- an identifier a CA API requires, not integrity (CWE-328)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
