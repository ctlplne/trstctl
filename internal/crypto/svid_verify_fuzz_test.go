// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"testing"
	"time"
)

// FuzzVerifyX509SVID keeps the bytes a Workload API socket hands a workload —
// a chain, a bundle and a private key — on the checked path: hostile input
// returns an error, never a panic.
func FuzzVerifyX509SVID(f *testing.F) {
	at := time.Unix(1_800_000_000, 0)
	f.Fuzz(func(t *testing.T, chainDER, bundleDER, keyPKCS8 []byte) {
		_, _ = VerifyX509SVID(chainDER, bundleDER, keyPKCS8, at)
		_, _ = VerifyX509SVID(chainDER, chainDER, keyPKCS8, at)
	})
}
