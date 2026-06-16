package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"trstctl.com/trstctl/tools/trstctllint/cryptoboundary"
	"trstctl.com/trstctl/tools/trstctllint/eventsource"
	"trstctl.com/trstctl/tools/trstctllint/idempotency"
	"trstctl.com/trstctl/tools/trstctllint/keymaterial"
	"trstctl.com/trstctl/tools/trstctllint/tenantfilter"
)

func main() {
	multichecker.Main(
		cryptoboundary.Analyzer, // AN-3
		tenantfilter.Analyzer,   // AN-1
		keymaterial.Analyzer,    // AN-8
		idempotency.Analyzer,    // AN-5
		eventsource.Analyzer,    // AN-2
	)
}
