// SPDX-License-Identifier: BUSL-1.1

package crypto

import "testing"

// A239: HOTP matches RFC 6238 Appendix B's TOTP vectors for SHA1, SHA256 and
// SHA512 (8 digits, 30-second steps), and refuses what it can't compute.
func TestHOTPMatchesRFC6238VectorsA239(t *testing.T) {
	seeds := map[string][]byte{
		"SHA1":   []byte("12345678901234567890"),
		"SHA256": []byte("12345678901234567890123456789012"),
		"SHA512": []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}
	for _, v := range []struct {
		unix      uint64
		algorithm string
		want      string
	}{
		{59, "SHA1", "94287082"}, {59, "SHA256", "46119246"}, {59, "SHA512", "90693936"},
		{1111111109, "SHA1", "07081804"}, {1111111109, "SHA256", "68084774"}, {1111111109, "SHA512", "25091201"},
		{1234567890, "SHA1", "89005924"}, {2000000000, "SHA256", "90698825"}, {20000000000, "SHA512", "47863826"},
	} {
		got, err := HOTP(seeds[v.algorithm], v.unix/30, 8, v.algorithm)
		if err != nil || string(got) != v.want {
			t.Fatalf("%s at %d: %q %v, want %s", v.algorithm, v.unix, got, err, v.want)
		}
	}
	if got, _ := HOTP(seeds["SHA1"], 59/30, 6, ""); string(got) != "287082" {
		t.Fatalf("six digits: %q", got)
	}
	for name, call := range map[string]func() ([]byte, error){
		"md5":      func() ([]byte, error) { return HOTP(seeds["SHA1"], 1, 6, "MD5") },
		"5 digits": func() ([]byte, error) { return HOTP(seeds["SHA1"], 1, 5, "SHA1") },
		"9 digits": func() ([]byte, error) { return HOTP(seeds["SHA1"], 1, 9, "SHA1") },
		"no key":   func() ([]byte, error) { return HOTP(nil, 1, 6, "SHA1") },
	} {
		if _, err := call(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
