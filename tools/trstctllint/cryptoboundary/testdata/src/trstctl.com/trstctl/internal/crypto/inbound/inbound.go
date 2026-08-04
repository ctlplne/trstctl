// Package inbound is a fixture: a package INSIDE the crypto boundary that
// reaches out to the platform. That is the inward half of AN-3 and it was
// unenforced — the boundary could have grown to include anything.
package inbound

import (
	"crypto/sha256" // fine: inside the boundary

	_ "trstctl.com/trstctl/internal/store" // want `AN-3: .* may not import .*internal/store.* from outside it`

	// ee/pqc is a crypto boundary too, but core importing it is AN-9's other
	// direction — core may never import ee/. "Both are boundaries" must not
	// read as "so they may import each other".
	_ "trstctl.com/trstctl/ee/pqc" // want `AN-3: .* may not import .*ee/pqc.* from outside it`
)

// Sum keeps the fixture non-empty.
func Sum(b []byte) [32]byte { return sha256.Sum256(b) }
