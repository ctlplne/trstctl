// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/sha1" // #nosec G505 -- MariaDB mysql_native_password specifies double SHA-1 for its account verifier (CWE-328)
	"encoding/hex"
	"errors"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// MySQLNativePasswordVerifier returns MariaDB's mysql_native_password account
// verifier, *HEX(SHA1(SHA1(password))). This legacy verifier is needed only
// for MariaDB, which has no server-generated CREATE USER password result.
// It is never used for MySQL 8.4's caching_sha2_password accounts. The caller
// wipes the returned bytes after the redacted CREATE USER path (CR-596).
func MySQLNativePasswordVerifier(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("crypto: MariaDB verifier needs a password")
	}
	first := sha1.Sum(password) // #nosec G401 -- MariaDB mysql_native_password's specified account verifier, not a general hash (CWE-328)
	defer secret.Wipe(first[:])
	second := sha1.Sum(first[:]) // #nosec G401 -- same MariaDB protocol verifier (CWE-328)
	defer secret.Wipe(second[:])
	out := make([]byte, 1+hex.EncodedLen(len(second)))
	out[0] = '*'
	hex.Encode(out[1:], second[:])
	for i := 1; i < len(out); i++ {
		if out[i] >= 'a' && out[i] <= 'f' {
			out[i] -= 'a' - 'A'
		}
	}
	return out, nil
}
