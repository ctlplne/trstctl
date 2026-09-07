// SPDX-License-Identifier: MPL-2.0

package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"trstctl.com/trstctl/tools/trstctllint/cryptoagility"
	"trstctl.com/trstctl/tools/trstctllint/cryptoboundary"
	"trstctl.com/trstctl/tools/trstctllint/eventsource"
	"trstctl.com/trstctl/tools/trstctllint/idempotency"
	"trstctl.com/trstctl/tools/trstctllint/keymaterial"
	"trstctl.com/trstctl/tools/trstctllint/licenseboundary"
	"trstctl.com/trstctl/tools/trstctllint/netexec"
	"trstctl.com/trstctl/tools/trstctllint/tenantfilter"
	"trstctl.com/trstctl/tools/trstctllint/tlsverify"
	"trstctl.com/trstctl/tools/trstctllint/upsertarbiter"
)

func main() {
	multichecker.Main(
		cryptoboundary.Analyzer,  // AN-3
		tenantfilter.Analyzer,    // AN-1
		keymaterial.Analyzer,     // AN-8
		idempotency.Analyzer,     // AN-5
		eventsource.Analyzer,     // AN-2
		cryptoagility.Analyzer,   // PQC-00
		netexec.Analyzer,         // SEC-005
		licenseboundary.Analyzer, // PACKAGING-007
		tlsverify.Analyzer,       // SEC-CWE-295
		upsertarbiter.Analyzer,   // OPP-C01
	)
}
