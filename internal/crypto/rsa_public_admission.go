// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// ValidateUntrustedPublicKey bounds the cost of verifying a signature with a
// key supplied by the requester. It must run before CheckSignature, CMS Verify,
// or a direct RSA verification. The limit is above supported enrollment keys
// while excluding huge moduli and exponents that can pin protocol workers.
func ValidateUntrustedPublicKey(public any) error {
	return certinfo.ValidateUntrustedPublicKey(public)
}
