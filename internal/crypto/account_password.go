// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"errors"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// RandomAccountPassword is the shared Windows/SQL account policy used by the
// local-account engine: uniform rejection sampling with all three classes.
func RandomAccountPassword(n int) ([]byte, error) {
	if n < 3 || n > 4096 {
		return nil, errors.New("crypto: account password size is outside its bounded policy")
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	const limit = 256 - 256%len(alphabet) // bytes at or above this are redrawn
	for attempt := 0; attempt < 32; attempt++ {
		out := make([]byte, 0, n)
		for len(out) < n {
			raw, err := RandomBytes(n)
			if err != nil {
				secret.Wipe(out)
				return nil, err
			}
			for _, b := range raw {
				if int(b) < limit && len(out) < n {
					out = append(out, alphabet[int(b)%len(alphabet)])
				}
			}
			secret.Wipe(raw)
		}
		var upper, lower, digit bool
		for _, c := range out {
			upper = upper || (c >= 'A' && c <= 'Z')
			lower = lower || (c >= 'a' && c <= 'z')
			digit = digit || (c >= '0' && c <= '9')
		}
		if upper && lower && digit {
			return out, nil
		}
		secret.Wipe(out)
	}
	return nil, errors.New("crypto: could not draw an account password")
}

// ValidAccountPassword checks the same upper/lower/digit alphabet without
// converting private bytes to a string. The caller chooses its minimum length.
func ValidAccountPassword(value []byte, minimum int) bool {
	if len(value) < minimum || len(value) > 4096 {
		return false
	}
	var upper, lower, digit bool
	for _, c := range value {
		u := c >= 'A' && c <= 'Z'
		l := c >= 'a' && c <= 'z'
		d := c >= '0' && c <= '9'
		if !u && !l && !d {
			return false
		}
		upper = upper || u
		lower = lower || l
		digit = digit || d
	}
	return upper && lower && digit
}
