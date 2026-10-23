// SPDX-License-Identifier: BUSL-1.1

package signing

import "trstctl.com/trstctl/internal/crypto"

// ceremonyCheck runs on every key the signer generates, mints or imports
// before its handle is published (eMudhra, Part 4): it refuses a key the
// weak-key checks flag. A freshly generated software key practically never
// fails; the check is there for a broken random source, a key factory that
// hands back a key it did not make well, or an imported key that was weak
// before it arrived. Possession is proven where a certificate is made,
// against the exact public key going into it (crypto.ProvePossession), and by
// the custody probe for HSM and KMS keys (proveManagedKeyCustody).
func ceremonyCheck(key crypto.DigestSigner) error {
	return crypto.RefuseWeakKey(key.Public())
}
