// SPDX-License-Identifier: MPL-2.0

package projections

import "testing"

func TestCMPDiagnosticsAcceptOnlyTheRegisteredProtocolAndCapacityCause(t *testing.T) {
	t.Parallel()
	valid := EnrollmentDiagnosticObserved{
		DiagnosticID: "11111111-1111-4111-8111-111111111111",
		Protocol:     "cmp",
		Step:         "issue",
		Cause:        "capacity_full",
		Summary:      "The bounded enrollment worker pool was full.",
		Remediation:  "Wait for current work to drain, then retry the same transaction.",
	}
	if err := validateEnrollmentDiagnosticObserved(valid); err != nil {
		t.Fatalf("valid CMP capacity diagnostic was rejected: %v", err)
	}

	invalidProtocol := valid
	invalidProtocol.Protocol = "cmp-text-guessed"
	if err := validateEnrollmentDiagnosticObserved(invalidProtocol); err == nil {
		t.Fatal("an unregistered CMP-like protocol label was accepted")
	}
	invalidCause := valid
	invalidCause.Cause = "queue-probably-full"
	if err := validateEnrollmentDiagnosticObserved(invalidCause); err == nil {
		t.Fatal("an unregistered free-text CMP cause was accepted")
	}
}
