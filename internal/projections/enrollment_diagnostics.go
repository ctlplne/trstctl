// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"fmt"
	"strings"
)

func validateEnrollmentDiagnosticObserved(diagnostic EnrollmentDiagnosticObserved) error {
	if strings.TrimSpace(diagnostic.DiagnosticID) == "" {
		return fmt.Errorf("projections: enrollment diagnostic id is required")
	}
	if !diagnosticOneOf(diagnostic.Protocol, "acme", "est", "scep", "adcs") {
		return fmt.Errorf("projections: enrollment diagnostic protocol %q is not known", diagnostic.Protocol)
	}
	if !diagnosticOneOf(diagnostic.Step, "account", "order", "challenge", "validation", "authorize", "issue", "chain_build", "revocation", "unknown") {
		return fmt.Errorf("projections: enrollment diagnostic step %q is not known", diagnostic.Step)
	}
	if !diagnosticOneOf(diagnostic.Cause,
		"challenge_not_visible", "challenge_wrong_value", "template_acl_denied",
		"eab_unauthorized", "client_cert_rejected", "responder_unreachable",
		"chain_incomplete", "name_not_permitted", "rate_limited", "unknown") {
		return fmt.Errorf("projections: enrollment diagnostic cause %q is not known", diagnostic.Cause)
	}
	if strings.TrimSpace(diagnostic.Summary) == "" {
		return fmt.Errorf("projections: enrollment diagnostic summary is required")
	}
	if diagnostic.Cause == "unknown" && strings.TrimSpace(diagnostic.Remediation) != "" {
		return fmt.Errorf("projections: unknown enrollment diagnostic cannot invent remediation")
	}
	if diagnostic.VerificationKind != "" && diagnostic.VerificationKind != "endpoint.verify" {
		return fmt.Errorf("projections: enrollment diagnostic verification kind %q is not known", diagnostic.VerificationKind)
	}
	if diagnostic.VerificationKind != "" && strings.TrimSpace(diagnostic.VerificationAddress) == "" {
		return fmt.Errorf("projections: enrollment diagnostic verification address is required")
	}
	return nil
}

func diagnosticOneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
