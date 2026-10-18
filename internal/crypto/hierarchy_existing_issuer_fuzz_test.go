// SPDX-License-Identifier: BUSL-1.1

package crypto

import "testing"

// FuzzVerifyExistingCAIssuerChain keeps hostile public CA bytes on the same
// validation path used before a tenant-bound signer key is prepared.
func FuzzVerifyExistingCAIssuerChain(f *testing.F) {
	f.Fuzz(func(t *testing.T, issuerDER []byte) {
		_, _ = VerifyExistingCAIssuerChain([][]byte{issuerDER})
		_, _ = VerifyExistingCAIssuerChain([][]byte{issuerDER, issuerDER})
	})
}
