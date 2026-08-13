// SPDX-License-Identifier: MPL-2.0

package docs_test

import (
	"os"
	"strings"
	"testing"
)

func TestAUD64GraphDependencyDocumentationNamesProductionAuthority(t *testing.T) {
	limitations, err := os.ReadFile("limitations.md")
	if err != nil {
		t.Fatal(err)
	}
	feature, err := os.ReadFile("features/graph-query-ai.md")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(limitations) + "\n" + string(feature)
	for _, required := range []string{
		"service_dependency",
		"agent.mtls.ReportInventory",
		"workload -> resource",
		"INCOMING",
		"workload -> credential",
		"does not infer network traffic",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("AUD-64 docs omit %q", required)
		}
	}
}
