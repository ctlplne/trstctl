//trstctl:keymaterial
package sealedcreds

// sealedcreds stands in for the credential-handling packages newly brought under
// the AN-8 marker in R3.1 (the seal/secret-vault code). Once a package carries
// //trstctl:keymaterial, a string-typed credential is a build failure: secret
// material must live in []byte so it can be locked, dump-protected, and zeroed.

// DataKey is fine: the key bytes live in []byte.
type DataKey struct {
	Bytes []byte
}

// Credential is NOT fine: a secret stored as string cannot be wiped.
type Credential struct {
	Sealed []byte
	Secret string // want "must not use string for key material"
}

// Seal taking a string secret is flagged.
func Seal(plaintext string) {} // want "must not use string for key material"

// Open returning a string secret is flagged.
func Open() (secret string) { // want "must not use string for key material"
	return ""
}
