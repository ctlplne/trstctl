// SPDX-License-Identifier: BUSL-1.1

//trstctl:keymaterial
package cleankeys

// A key-handling package that keeps all key material in []byte is clean.

type PrivateKey struct {
	Bytes []byte
}

func Sign(priv []byte) error { return nil }
