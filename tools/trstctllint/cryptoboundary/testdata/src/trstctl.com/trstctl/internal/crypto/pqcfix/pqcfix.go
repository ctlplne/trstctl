// Package pqcfix is a subpackage of the internal/crypto boundary, so it may
// import third-party cryptography (and stdlib crypto/*) freely — the boundary is
// exactly where such imports belong (AN-3).
package pqcfix

import _ "golang.org/x/crypto/acme"
