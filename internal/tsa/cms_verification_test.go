// SPDX-License-Identifier: BUSL-1.1

package tsa

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestVerifyAuthenticatesPresentCMSToken(t *testing.T) {
	issuedAt := time.Now().UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	a, root := newTSA(t, func() time.Time { return issuedAt })
	imprint := imprintOf("portable audit evidence")
	token, err := a.timestamp(t.Context(), imprint, big.NewInt(739))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("genuine-fractional-time-and-nonce", func(t *testing.T) {
		if token.Info.GenTime.Nanosecond() != 123456789 {
			t.Fatal("fixture lost its fractional signed manifest time")
		}
		if err := Verify(token, imprint, root); err != nil {
			t.Fatalf("genuine token must verify: %v", err)
		}
	})
	t.Run("legacy-manifest-only", func(t *testing.T) {
		legacy := token
		legacy.DER = nil
		if err := Verify(legacy, imprint, root); err != nil {
			t.Fatalf("authenticated legacy manifest must verify: %v", err)
		}
	})

	malformed := append([]byte("not-a-CMS-token:"), token.TSACertDER...)
	malformed = append(malformed, imprint...)
	badSignature := bytes.Clone(token.DER)
	badSignature[len(badSignature)-1] ^= 1
	trailing := append(bytes.Clone(token.DER), 0)
	cases := []struct {
		name string
		der  []byte
	}{
		{"malformed-with-certificate-and-imprint", malformed},
		{"invalid-CMS-signature", badSignature},
		{"trailing-container-data", trailing},
	}
	// Each replacement is genuinely signed by the same TSA, with the same
	// imprint. Only one authenticated field differs from the original manifest.
	for _, field := range []string{"serial", "policy", "time"} {
		params := crypto.TSTInfoParams{
			PolicyOID: token.Info.Policy, HashedMessage: imprint,
			SerialNumber: token.Info.SerialNumber, GenTime: issuedAt,
			Nonce: big.NewInt(739),
		}
		switch field {
		case "serial":
			params.SerialNumber++
		case "policy":
			params.PolicyOID = "1.3.6.1.4.1.59551.2.999"
		case "time":
			params.GenTime = issuedAt.Add(time.Second)
		}
		info, err := crypto.EncodeTSTInfo(params)
		if err != nil {
			t.Fatal(err)
		}
		der, err := crypto.BuildTimeStampToken(info, token.TSACertDER, a.cfg.TSASigner)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			name string
			der  []byte
		}{"different-signed-" + field, der})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Contains(tc.der, token.TSACertDER) || !bytes.Contains(tc.der, imprint) {
				t.Fatal("fixture must retain both byte strings accepted by the old containment check")
			}
			changed := token
			changed.DER = tc.der
			if err := Verify(changed, imprint, root); err == nil {
				t.Fatal("verification accepted present CMS that does not authenticate the original timestamp evidence")
			}
		})
	}
}
