// SPDX-License-Identifier: BUSL-1.1

package weakkeytest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- Debian's blocklist format is defined over SHA-1; not a security use (CWE-328)
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// SharedPrimeRSASPKIs returns the DER SubjectPublicKeyInfo of two RSA keys of
// about bits each whose moduli share one prime, so batch GCD factors both.
func SharedPrimeRSASPKIs(bits int) ([]byte, []byte, error) {
	if bits < 1024 {
		return nil, nil, errors.New("weakkeytest: use at least 1024 bits")
	}
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, err
	}
	var out [2][]byte
	for i := range out {
		q, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return nil, nil, err
		}
		if out[i], err = x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537}); err != nil {
			return nil, nil, err
		}
	}
	return out[0], out[1], nil
}

// DebianBlocklistLine returns the line Debian's openssl-blacklist format
// carries for an RSA SubjectPublicKeyInfo: the last 20 hex digits of
// SHA-1("Modulus=" + uppercase hex modulus + "\n").
func DebianBlocklistLine(spki []byte) (string, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return "", err
	}
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("weakkeytest: not an RSA key")
	}
	sum := sha1.Sum([]byte("Modulus=" + strings.ToUpper(k.N.Text(16)) + "\n")) // #nosec G401 -- Debian blocklist entry format, not a security use of SHA-1 (CWE-328)
	return hex.EncodeToString(sum[:])[20:], nil
}
