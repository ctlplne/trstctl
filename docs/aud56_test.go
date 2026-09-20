// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestAUD56PublishesCompletePricingAndEnvironmentEntitlement(t *testing.T) {
	pricing := readAUD56Doc(t, "pricing.md")
	for _, want := range []string{
		"$15,000", "$30,000", "$12,000", "$72,000",
		"1 production", "3 non-production", "no production SLA",
		"no per-connector", "no per-protocol", "60-day", "5%", "30-day grace",
		"read-only", "MPL core keeps running",
	} {
		if !strings.Contains(strings.ToLower(pricing), strings.ToLower(want)) {
			t.Errorf("pricing.md does not publish %q", want)
		}
	}

	editions := readAUD56Doc(t, "editions.md")
	for _, want := range []string{
		"environment_entitlement", "production_deployment_id",
		"non_production_deployment_ids", "TRSTCTL_LICENSE_DEPLOYMENT_ID",
		"TRSTCTL_LICENSE_ENVIRONMENT", "production_units_consumed",
	} {
		if !strings.Contains(editions, want) {
			t.Errorf("editions.md does not document %q", want)
		}
	}

	configuration := readAUD56Doc(t, "configuration.md")
	for _, want := range []string{"TRSTCTL_LICENSE_FILE", "TRSTCTL_LICENSE_DEPLOYMENT_ID", "TRSTCTL_LICENSE_ENVIRONMENT", "non_production"} {
		if !strings.Contains(configuration, want) {
			t.Errorf("configuration.md does not document %q", want)
		}
	}

	limitations := readAUD56Doc(t, "limitations.md")
	for _, want := range []string{"non-production entitlement", "operator-declared", "version 1", "production-only"} {
		if !strings.Contains(strings.ToLower(limitations), strings.ToLower(want)) {
			t.Errorf("limitations.md does not state %q", want)
		}
	}
}

func readAUD56Doc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name) // #nosec G304 -- name comes from the fixed documentation manifest in this test (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
