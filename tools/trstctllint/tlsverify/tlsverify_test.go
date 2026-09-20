// SPDX-License-Identifier: BUSL-1.1

package tlsverify_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/tlsverify"
)

// TestTLSVerify exercises SEC-CWE-295 in both directions: a production file
// outside the prober that sets InsecureSkipVerify (composite literal or
// assignment) is flagged; the tlsprobe package itself and _test.go files are
// not; and a config that leaves verification on is never flagged.
func TestTLSVerify(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), tlsverify.Analyzer,
		"trstctl.com/trstctl/internal/crypto/tlsprobe", // the sanctioned prober: allowed
		"trstctl.com/trstctl/internal/crypto/mtls",     // LoopbackProbeClient allowed, everything else flagged
		"badpkg",   // production violations: flagged
		"cleanpkg", // verification left on: never flagged
	)
}
