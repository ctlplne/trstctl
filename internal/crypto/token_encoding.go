package crypto

import (
	"encoding/base64"
	"encoding/hex"
)

// AppendHex appends the lowercase hex encoding of src to dst and returns the
// extended byte slice without materializing an immutable Go string.
func AppendHex(dst, src []byte) []byte {
	return hex.AppendEncode(dst, src)
}

// AppendBase64RawURL appends the unpadded URL-safe base64 encoding of src to dst
// and returns the extended byte slice without materializing an immutable Go string.
func AppendBase64RawURL(dst, src []byte) []byte {
	return base64.RawURLEncoding.AppendEncode(dst, src)
}
