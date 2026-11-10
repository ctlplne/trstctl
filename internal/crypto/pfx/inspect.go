// SPDX-License-Identifier: BUSL-1.1

package pfx

import (
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ErrIncorrectPassword reports that a password does not open the file.
var ErrIncorrectPassword = pkcs12.ErrIncorrectPassword

// ChainDER opens a PKCS#12 file with password for inventory (X2) and returns
// its certificates as DER, the key's certificate first, and whether it holds a
// private key. It reads certificates only (X2-L3): the file's MAC checks the
// password, the encrypted contents that hold certificates are decrypted, and a
// key bag is noted but never decrypted, parsed or copied, so no key material
// is in memory at any point. A file with only certificates returns them with
// hasKey false.
func ChainDER(pfxData []byte, password string) (chain [][]byte, hasKey bool, err error) {
	return certificatesOnly(pfxData, password)
}
