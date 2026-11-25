// SPDX-License-Identifier: BUSL-1.1

package tlsdistrust_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/tlsdistrust"
)

func TestDirectTLSClientsAreRejected(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), tlsdistrust.Analyzer,
		"trstctl.com/trstctl/internal/crypto/badclient",
		"trstctl.com/trstctl/internal/crypto/tlsprobe",
		"trstctl.com/trstctl/internal/crypto/trust")
}
