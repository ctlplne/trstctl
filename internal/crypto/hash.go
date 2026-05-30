package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns the lowercase hex-encoded SHA-256 digest of data. It lives
// in the crypto boundary so build and release tooling (for example, publishing
// artifact checksums) can compute digests without importing crypto/* directly
// (AN-3).
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HMACSHA256 returns the HMAC-SHA256 of data under key. It lives in the crypto
// boundary (AN-3) so request signers that need a keyed MAC — for example AWS
// SigV4 in the ACM deployment connector — can derive signatures without
// importing crypto/* directly.
func HMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
