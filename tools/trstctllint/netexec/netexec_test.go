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
