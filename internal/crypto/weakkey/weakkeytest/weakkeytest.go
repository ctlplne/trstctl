// SPDX-License-Identifier: BUSL-1.1

// Package weakkeytest builds deliberately weak keys for tests outside the
// crypto boundary, which may not import crypto/* themselves (AN-3). Every key
// here is public knowledge by construction: use one only to prove that a weak
// key is refused or flagged.
package weakkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
)

// SmallScalarPKCS8 returns the PKCS #8 DER of an elliptic-curve private key
// whose private scalar is k, on "P-256", "P-384" or "P-521". The eight
// eMudhra intermediates had P-384 keys with k between 4 and 237.
func SmallScalarPKCS8(curveName string, k uint64) ([]byte, error) {
	var curve elliptic.Curve
	switch curveName {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("weakkeytest: unknown curve %q", curveName)
	}
	if k == 0 {
		return nil, errors.New("weakkeytest: the scalar must be positive")
	}
	raw := make([]byte, (curve.Params().BitSize+7)/8)
	for i := len(raw) - 1; i >= 0 && k > 0; i-- {
		raw[i] = byte(k)
		k >>= 8
	}
	key, err := ecdsa.ParseRawPrivateKey(curve, raw)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(key)
}
