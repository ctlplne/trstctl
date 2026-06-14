package crypto

import "crypto/subtle"

// ConstantTimeEqual reports whether a and b are equal, comparing in constant time. It lets
// callers compare MACs, tokens, and other secret-derived values without importing
// crypto/subtle directly (AN-3).
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
