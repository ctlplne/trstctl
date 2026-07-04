// SPDX-License-Identifier: MPL-2.0

package signing

type heldKey struct {
	handle        string
	privateKeyDER []byte
	privateKeyPEM string // want "signing key custody must not use string-backed key material"
}

func importPrivateKeyPEM(privateKeyPEM string) {} // want "signing key custody must not use string-backed key material"

func exportPrivateKeyPEM() (privateKeyPEM string) { // want "signing key custody must not use string-backed key material"
	return ""
}

func signerByHandle(handle string) []byte {
	return []byte(handle)
}
