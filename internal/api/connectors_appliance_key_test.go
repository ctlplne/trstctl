// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// A122: the catalog says which families can have their appliance generate the
// key, from the same census the target validator and the relay read, so the
// console offers the choice exactly where a target may declare it.
func TestConnectorCatalogNamesTheFamiliesWhoseAppliancesGenerateKeys(t *testing.T) {
	offered := map[string]bool{}
	for _, item := range (&API{}).connectorCatalogWithSandbox() {
		if item.ApplianceKeyGeneration != connector.ApplianceKeyFamily(item.Name) {
			t.Errorf("%s: catalog appliance_key_generation=%v, census %v", item.Name, item.ApplianceKeyGeneration, connector.ApplianceKeyFamily(item.Name))
		}
		offered[item.Name] = item.ApplianceKeyGeneration
	}
	for _, family := range connector.ApplianceKeyFamilies() {
		if !offered[family] {
			t.Errorf("appliance-key family %q is not offered in the connector catalog", family)
		}
	}
	if offered["kemp"] || offered["fortigate"] || offered["nginx"] {
		t.Errorf("the catalog offers appliance key generation to a family that cannot: %v", offered)
	}
}
