// SPDX-License-Identifier: BUSL-1.1

//go:build !cgo

package discovery

import "context"

// platformPKCS11Reader in a build with no cgo, and therefore no way to dlopen a
// vendor PKCS#11 module.
//
// It fails rather than returning nothing, and the shipped census reports that
// this build does not collect PKCS#11 at all — so the capability is never
// advertised by a binary that cannot deliver it. An empty result would tell an
// operator their HSM and smart-card estate is clean, which is the false comfort
// epic C1 exists to remove.
func platformPKCS11Reader() pkcs11Reader { return unsupportedPKCS11Reader{} }

// pkcs11Shipped reports that this build cannot collect PKCS#11.
func pkcs11Shipped() bool { return false }

type unsupportedPKCS11Reader struct{}

func (unsupportedPKCS11Reader) readTokens(context.Context, PKCS11Config) (map[string][]byte, error) {
	return nil, ErrPKCS11Unsupported
}
