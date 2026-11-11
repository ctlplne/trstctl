// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"encoding/base32"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// TestTOTPVerifyCodeAcceptsTheCurrentStepAndOneEitherSideA239L5: a
// replacement seed is proven by a code from it. The current step's code is
// accepted, and so is one step either side (an authenticator's clock skew);
// two steps away, a code from another seed, or a code of another length is
// refused.
func TestTOTPVerifyCodeAcceptsTheCurrentStepAndOneEitherSideA239L5(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	now := time.Unix(1_800_000_015, 0)
	b, err := NewTOTPBackend(TOTPConfig{SeedBase32: []byte(seed), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	other, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	step := now.Unix() / 30
	code := func(k []byte, s int64) []byte {
		t.Helper()
		c, err := crypto.HOTP(k, uint64(s), 6, "SHA1") // #nosec G115 -- a positive clock step in a test (CWE-190)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for name, tc := range map[string]struct {
		code []byte
		want bool
	}{
		"the current step":       {code(key, step), true},
		"one step before":        {code(key, step-1), true},
		"one step after":         {code(key, step+1), true},
		"two steps before":       {code(key, step-2), false},
		"two steps after":        {code(key, step+2), false},
		"another seed's code":    {code(other, step), false},
		"a code of another size": {append(code(key, step), '0'), false},
	} {
		got, err := b.VerifyCode(tc.code)
		if err != nil || got != tc.want {
			t.Errorf("%s: VerifyCode = %v, %v; want %v", name, got, err, tc.want)
		}
	}
}
