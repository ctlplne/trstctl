// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestAUD56PublishesEnvironmentEntitlementWithoutPrices(t *testing.T) {
	editions := readAUD56Doc(t, "editions.md")
	// No prices are published anywhere (2026-09-20): the commercial posture says
	// so, and the entitlement, grace and read-only behavior stay documented.
	// Prose wraps, so phrases are matched with whitespace collapsed.
	flatEditions := strings.ToLower(strings.Join(strings.Fields(editions), " "))
	for _, want := range []string{
		"not published yet",
		"1 production", "3 non-production", "no production sla",
		"no per-connector", "no per-protocol", "30-day grace",
		"read-only", "core keeps running",
	} {
		if !strings.Contains(flatEditions, want) {
			t.Errorf("editions.md does not state %q", want)
		}
	}
	if price := regexp.MustCompile(`\$[0-9]|USD ?[0-9]`).FindString(editions); price != "" {
		t.Errorf("editions.md publishes a price (%q); there is no published pricing", price)
	}
	if _, err := os.Stat("pricing.md"); err == nil {
		t.Error("docs/pricing.md exists; there is no published pricing")
	}

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
