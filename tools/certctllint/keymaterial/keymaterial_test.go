package keymaterial_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"certctl.io/certctl/tools/certctllint/keymaterial"
)

// TestKeyMaterial exercises AN-8: a package that opts in with the
// //certctl:keymaterial marker must not use string for fields, parameters, or
// results (key material belongs in []byte). Packages without the marker are
// ignored (the rule tightens as the key-handling packages land).
func TestKeyMaterial(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), keymaterial.Analyzer,
		"keyhandling", // marker present, uses string: flagged
		"cleankeys",   // marker present, []byte only: clean
		"plainpkg",    // no marker: ignored
		"sealedcreds", // newly-covered credential package (R3.1): string secret flagged
	)
}
