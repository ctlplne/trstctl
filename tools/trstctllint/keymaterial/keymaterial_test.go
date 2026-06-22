package keymaterial_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/keymaterial"
)

// TestKeyMaterial exercises AN-8. A package is in scope either by carrying the
// //trstctl:keymaterial marker, or by being a default-on secret primitive
// (internal/crypto/secret, internal/crypto/seal) whose enforcement cannot be
// turned off by removing the marker. In scope, any string-BACKED field, param,
// or result is flagged — including named string types, slices/arrays of string,
// maps with a string value, and pointers to any of those (ARCH-001). Out of
// scope (no marker, not default-on), ordinary string usage is ignored.
func TestKeyMaterial(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), keymaterial.Analyzer,
		"keyhandling", // marker present; string + named/slice/map/array/ptr evasions all flagged
		"cleankeys",   // marker present, []byte only: clean
		"plainpkg",    // no marker, not default-on: ignored
		"sealedcreds", // newly-covered credential package (R3.1): string secret flagged
		"trstctl.com/trstctl/internal/api",
		"trstctl.com/trstctl/internal/authmethod",
		"trstctl.com/trstctl/internal/connector/badkeycopy",
		"trstctl.com/trstctl/internal/kms/badcreds",
		// CRYPTO-003: every provider-credential surface named in the fix_spec is
		// fail-closed, not just kms/connector. These pin the dns, notify, and CA
		// scopes so a future narrowing of providerCredentialScope is caught.
		"trstctl.com/trstctl/internal/dns/badcreds",
		"trstctl.com/trstctl/internal/notify/badcreds",
		"trstctl.com/trstctl/internal/ca/badcreds",
		"trstctl.com/trstctl/internal/signing",
		// Default-on secret primitive WITHOUT the marker: ARCH-004 fail-closed
		// proof — a forgotten marker does not disable the rule here.
		"trstctl.com/trstctl/internal/crypto/secret",
	)
}
