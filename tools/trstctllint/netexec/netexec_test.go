// SPDX-License-Identifier: MPL-2.0

package netexec_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/netexec"
)

func TestNetExecGuard(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), netexec.Analyzer,
		"trstctl.com/trstctl/internal/netexecbad",
		"trstctl.com/trstctl/internal/spireupstream",
		"trstctl.com/trstctl/internal/ca/shellca",
	)
}

// TestNetExecGuardAcceptsTheSanctionedPath is the other half of the SEC-005
// ambient-HTTP rule: a caller that takes its client from netsec must be clean,
// and netsec itself — the package that implements the sanctioned constructor —
// must stay clean too, or the rule would be circular. analysistest fails on any
// unexpected diagnostic, so "no want comments" is the assertion.
func TestNetExecGuardAcceptsTheSanctionedPath(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), netexec.Analyzer,
		"trstctl.com/trstctl/internal/netexecgood",
		"trstctl.com/trstctl/internal/netsec",
	)
}
