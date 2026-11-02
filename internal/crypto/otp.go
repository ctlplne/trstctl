// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP's default HMAC hash, used as an HMAC, not a collision-resistant digest (CWE-327)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// HOTP returns the RFC 4226 one-time password for counter: an HMAC over the
// big-endian counter with the named hash ("SHA1", the default, "SHA256" or
// "SHA512"), dynamically truncated to digits decimal digits (6 to 8),
// zero-padded. RFC 6238's TOTP is HOTP with counter = Unix time / period. The
// code is returned as bytes the caller wipes.
func HOTP(key []byte, counter uint64, digits int, algorithm string) ([]byte, error) {
	var newHash func() hash.Hash
	switch algorithm {
	case "", "SHA1":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA512":
		newHash = sha512.New
	default:
		return nil, fmt.Errorf("crypto: one-time-password algorithm %q is not SHA1, SHA256 or SHA512", algorithm)
	}
	if digits < 6 || digits > 8 {
		return nil, errors.New("crypto: a one-time password has 6 to 8 digits")
	}
	if len(key) == 0 {
		return nil, errors.New("crypto: a one-time-password key is required")
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(newHash, key)
	mac.Write(message[:])
	sum := mac.Sum(nil)
	defer wipeBytes(sum)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	code := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		code[i] = byte('0' + value%10)
		value /= 10
	}
	return code, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
