// SPDX-License-Identifier: BUSL-1.1

package cryptoagility_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/cryptoagility"
)

// TestCryptoAgilityGuard locks the PQC-00 design guardrail: crypto agility in
// trstctl is compile-time Go interfaces plus dependency injection behind
// internal/crypto, not a runtime plugin/engine/provider registry.
func TestCryptoAgilityGuard(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), cryptoagility.Analyzer,
		"trstctl.com/trstctl/internal/crypto/clean",
		"trstctl.com/trstctl/internal/crypto/badplugin",
		"trstctl.com/trstctl/internal/crypto/badpolicy",
		"trstctl.com/trstctl/internal/signing/badpolicy",
		"trstctl.com/trstctl/internal/crypto/badregistry",
		"trstctl.com/trstctl/internal/crypto/badregister",
		"trstctl.com/trstctl/internal/signing/protoclean",
		"trstctl.com/trstctl/internal/policy",
	)
}
