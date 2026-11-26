// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"crypto/rsa"
	"errors"
)

// ValidateUntrustedPublicKey is the leaf-level guard shared by CSR and CMS
// verifiers. It lives here so certinfo can use it without importing its parent.
func ValidateUntrustedPublicKey(public any) error {
	rsaKey, ok := public.(*rsa.PublicKey)
	if !ok {
		return nil
	}
	if rsaKey == nil || rsaKey.N == nil || rsaKey.N.Sign() <= 0 {
		return errors.New("crypto: invalid RSA public key")
	}
	if rsaKey.N.BitLen() > 8192 {
		return errors.New("crypto: untrusted RSA public key exceeds 8192 bits")
	}
	if rsaKey.E < 3 || rsaKey.E > 65537 || rsaKey.E%2 == 0 {
		return errors.New("crypto: untrusted RSA public exponent is outside 3..65537 odd")
	}
	return nil
}
