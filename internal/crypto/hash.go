package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// SHA256Hex returns the lowercase hex-encoded SHA-256 digest of data. It lives
// in the crypto boundary so build and release tooling (for example, publishing
// artifact checksums) can compute digests without importing crypto/* directly
// (AN-3).
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Sum returns the raw 32-byte SHA-256 digest of data. The TLS-ALPN-01
// acmeIdentifier extension (RFC 8737) carries this digest of the key
// authorization; routing it through the boundary keeps crypto/* out of the ACME
// validators (AN-3).
func SHA256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// SHA256ReaderHex streams r through SHA-256 and returns the lowercase hex digest
// plus the byte count. It keeps file/artifact digesting inside the crypto
// boundary (AN-3) without requiring callers to buffer large backups in memory.
func SHA256ReaderHex(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", n, fmt.Errorf("sha256 stream: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// SHA256Base64URL returns the unpadded base64url-encoded SHA-256 digest of data.
// The DNS-01 challenge TXT record (RFC 8555 §8.4) is this digest of the key
// authorization.
func SHA256Base64URL(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
