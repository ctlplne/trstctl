// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package pqc is a fixture for the proprietary PQC boundary, which sits on the
// opposite side of the two AN-3 halves from internal/crypto.
//
// It may hold crypto (that is the whole point of it being a boundary), and it
// may import core — internal/pqc reaches the runtime only by implementing the core
// signer's factory interface at the attach seam, and AN-9 states plainly that
// ee/ may import core. NEITHER import below is a violation.
//
// This fixture exists because the inward AN-3 rule was first written against
// the combined boundary predicate, which flagged exactly these imports and
// would have forced the signer's types to be duplicated into ee/ to satisfy a
// rule that was never about internal/pqc. If a future tightening reintroduces that,
// this fixture fails before the repo-wide run does.
package pqc

import (
	"crypto/sha512"

	_ "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/signing"
)

type factory struct{}

func (factory) Name() string { return "ml-dsa" }

// New returns the attach-seam implementation, typed by core.
func New() signing.KeyFactory { return factory{} }

// Digest keeps the crypto import load-bearing.
func Digest(b []byte) [64]byte { return sha512.Sum512(b) }
