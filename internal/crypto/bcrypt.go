// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// HashBcrypt returns password's bcrypt hash ($2a$, cost from 4 to 31) for a
// server that accepts a hash it then checks logins against, so the password
// itself never appears in the statement that sets it (Cassandra's HASHED
// PASSWORD, A239). A password longer than bcrypt's 72 bytes is refused, never
// truncated.
func HashBcrypt(password []byte, cost int) ([]byte, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, errors.New("crypto: bcrypt cost must be from 4 to 31")
	}
	if len(password) == 0 {
		return nil, errors.New("crypto: bcrypt needs a password")
	}
	return bcrypt.GenerateFromPassword(password, cost)
}

// VerifyBcrypt reports whether password matches hash.
func VerifyBcrypt(hash, password []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, password) == nil
}
