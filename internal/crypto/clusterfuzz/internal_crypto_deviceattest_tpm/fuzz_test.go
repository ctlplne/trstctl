// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/deviceattest"
)

func FuzzParseAndVerifyTPMDeviceAttestation(f *testing.F) {
	f.Add([]byte(`{}`), []byte("challenge"), []byte("not a certificate"))
	f.Add([]byte(`{"type":"public-key","response":{}}`), make([]byte, 32), []byte("-----BEGIN CERTIFICATE-----"))
	f.Fuzz(func(t *testing.T, credentialJSON, challenge, rootPEM []byte) {
		if len(credentialJSON) > 1<<20 || len(challenge) > 1024 || len(rootPEM) > 1<<20 {
			t.Skip()
		}
		_, _ = deviceattest.ParseAndVerifyTPMDeviceAttestation(
			credentialJSON,
			challenge,
			[][]byte{rootPEM},
			[]int64{-7, -257},
			time.Unix(1_785_240_000, 0).UTC(),
		)
	})
}
