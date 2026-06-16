package cryptoboundary_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/cryptoboundary"
)

// TestCryptoBoundary exercises AN-3: crypto/* may be imported only inside
// internal/crypto (and its subpackages). The fixtures live under testdata/src
// at paths that mirror the real module layout so the boundary check is tested
// against realistic package paths.
func TestCryptoBoundary(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), cryptoboundary.Analyzer,
		"trstctl.com/trstctl/internal/crypto",          // the boundary: allowed
		"trstctl.com/trstctl/internal/crypto/software", // subpackage of the boundary: allowed
		"trstctl.com/trstctl/internal/store",           // violation: imports crypto/*
		"cleanpkg",                                     // clean: no crypto import at all
		// CRYPTO-002: third-party crypto (x/crypto, circl) is forbidden outside the
		// boundary in production code, but a differential/conformance _test.go may
		// drive a reference client. The fixture has a production file that imports
		// x/crypto (flagged) and a _test.go that imports it (NOT flagged).
		"thirdpartycrypto",
		// The boundary itself may import third-party crypto freely.
		"trstctl.com/trstctl/internal/crypto/pqcfix",
	)
}
