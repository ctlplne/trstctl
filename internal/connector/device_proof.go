// SPDX-License-Identifier: BUSL-1.1

package connector

import "sort"

// Which appliance families are proven against an emulated device (epic E1).
//
// The existing Conformance() suite runs every connector against MemoryOps: it
// proves a connector respects its capability grant, is deterministic on replay,
// and does not reach outside what it declared. Those are real properties and
// they are the same for all connectors, which is exactly why they cannot answer
// the question this census answers.
//
// MemoryOps says yes to any request. So a connector that POSTs to the wrong
// path, sends a malformed body, omits authentication, or ignores a device's
// error response passes conformance without complaint. What conformance proves
// is that the connector behaves; what it cannot prove is that the DEVICE would
// have accepted it.
//
// That gap matters most for the appliance families, because their whole
// implementation IS an API conversation. A relay advertised as able to deploy to
// an F5 and unable to actually do so is the defect this workstream exists to
// find, and "it compiles and passes conformance" is precisely the evidence that
// would hide it.
//
// So: a family appears here only when this repository carries a faithful
// in-process double of its management API and a test that drives the REAL
// connector against it. The guard test in device_proof_census_test.go fails if a
// family claims proof it does not have — the C1a discipline, applied to
// connectors instead of agent job kinds.

// deviceProvenFamilies are the connector families with an emulator-backed deploy
// proof in this repository.
var deviceProvenFamilies = []string{
	"a10",
	"cisco",
	"f5",
	"fortigate",
	"kemp",
	"netscaler",
	"paloalto",
}

// DeviceProven reports whether this family's deploy is proven against a faithful
// double of its device API.
//
// False is not an accusation. A host connector writes files and reloads a
// service — there is no device API to emulate, so the question does not apply
// and the honest answer is that this proof is not the one that covers it.
func DeviceProven(name string) bool {
	for _, n := range deviceProvenFamilies {
		if n == name {
			return true
		}
	}
	return false
}

// DeviceProvenConnectors reports the proven families, sorted.
func DeviceProvenConnectors() []string {
	out := append([]string(nil), deviceProvenFamilies...)
	sort.Strings(out)
	return out
}
