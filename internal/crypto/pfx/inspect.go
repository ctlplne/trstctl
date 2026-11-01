// SPDX-License-Identifier: BUSL-1.1

package pfx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math/big"
	"runtime"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ErrIncorrectPassword reports that a password does not open the file.
var ErrIncorrectPassword = pkcs12.ErrIncorrectPassword

// ChainDER opens a PKCS#12 file with password for inventory (X2) and returns
// its certificates as DER, the key's certificate first, and whether it holds a
// private key. PKCS#12 keeps certificates and key under one password, so the
// library decodes the key on the way to the certificates; it is wiped before
// this returns and never leaves the package. A file with only certificates
// returns them with hasKey false.
func ChainDER(pfxData []byte, password string) (chain [][]byte, hasKey bool, err error) {
	key, leaf, cas, err := pkcs12.DecodeChain(pfxData, password)
	if err == nil {
		defer wipeKey(key)
		chain = append(chain, leaf.Raw)
		for _, ca := range cas {
			chain = append(chain, ca.Raw)
		}
		return chain, true, nil
	}
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return nil, false, ErrIncorrectPassword
	}
	certs, terr := pkcs12.DecodeTrustStore(pfxData, password)
	if terr != nil {
		return nil, false, err
	}
	for _, c := range certs {
		chain = append(chain, c.Raw)
	}
	return chain, false, nil
}

// wipeKey zeroes the decoded private key's secret values (AN-8).
func wipeKey(key any) {
	zero := func(n *big.Int) {
		if n != nil {
			n.SetInt64(0)
		}
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k == nil {
			return
		}
		zero(k.D)
		for _, p := range k.Primes {
			zero(p)
		}
		zero(k.Precomputed.Dp)
		zero(k.Precomputed.Dq)
		zero(k.Precomputed.Qinv)
	case *ecdsa.PrivateKey:
		if k != nil {
			//nolint:staticcheck // AN-8: zero the legacy ECDSA scalar when present.
			zero(k.D)
		}
	case ed25519.PrivateKey:
		for i := range k {
			k[i] = 0
		}
	}
	runtime.KeepAlive(key)
}
