// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/sha1" // #nosec G505 -- RFC 4122 UUIDv5 uses SHA-1 only for a public identity label, never integrity (CWE-328).
	"fmt"
)

// UUIDv5OID derives a public, deterministic identifier in the RFC 4122 OID
// namespace. SHA-1 is fixed by UUID version 5 here; the result is an identity
// label, never a signature, MAC, password hash, or integrity check. Keeping
// this tiny derivation behind the crypto boundary avoids linking a general
// UUID package's SQL adapter into the isolated signer.
func UUIDv5OID(name []byte) string {
	namespace := [...]byte{0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1,
		0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	seed := make([]byte, 0, len(namespace)+len(name))
	seed = append(seed, namespace[:]...)
	seed = append(seed, name...)
	digest := sha1.Sum(seed) // #nosec G401 -- RFC 4122 UUIDv5 public identifier, not a security digest.
	digest[6] = (digest[6] & 0x0f) | 0x50
	digest[8] = (digest[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8],
		digest[8:10], digest[10:16])
}
