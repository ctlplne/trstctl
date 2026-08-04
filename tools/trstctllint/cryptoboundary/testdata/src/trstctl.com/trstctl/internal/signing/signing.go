// SPDX-License-Identifier: MPL-2.0

// Package signing is a fixture standing in for the core signer package that
// ee/pqc attaches to. It holds no crypto of its own — the seam is an interface.
package signing

// KeyFactory is the compile-time DI seam ee/pqc implements.
type KeyFactory interface {
	Name() string
}
