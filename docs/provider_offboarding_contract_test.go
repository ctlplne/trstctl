// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

// A false preview or approval promise can cause an operator to execute a real
// customer deletion while expecting a harmless inspection. Keep the destructive
// boundary and its separate permissions explicit in the operator journey.
func TestProviderOffboardingContractExplainsDestructiveExecution(t *testing.T) {
	journey := strings.Join(strings.Fields(read(t, "journeys/operate-as-a-provider.md")), " ")
	if strings.Contains(journey, "preview-only until a break-glass grant is used") {
		t.Error("Provider journey falsely promises a preview and emergency-access gate before deletion")
	}
	start := strings.Index(journey, "### Offboard a customer")
	if start < 0 {
		t.Fatal("Provider journey needs an offboarding step before its interruption-recovery instructions")
	}
	step := journey[start:]
	if end := strings.Index(step[4:], "### "); end >= 0 {
		step = step[:end+4]
	}
	for _, want := range []string{
		"PostgreSQL read state", "not a dry run", "cannot be undone with Resume",
		"does not revoke certificates at upstream CAs", "MFA", "`offboard`",
		"Emergency-access approvals do not authorize deletion",
		"Idempotency-Key", "Deletion verified", "Tenant offboarding boundary",
	} {
		if !strings.Contains(step, want) {
			t.Errorf("offboarding instructions must explain %q before execution", want)
		}
	}
}
