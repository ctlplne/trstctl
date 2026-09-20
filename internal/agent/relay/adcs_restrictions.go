// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"strings"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

// parseCAAgentRestrictions interprets only the stable certutil outcome needed
// by posture. Raw command output can name infrastructure and never crosses the
// relay boundary. Missing EnrollmentAgentRights means the CA is unrestricted;
// a successful read means the control exists. Every other result is unknown.
func parseCAAgentRestrictions(output []byte, commandSucceeded bool) adcs.EnrollmentAgentRestrictions {
	normalized := strings.ToLower(string(output))
	if commandSucceeded {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceEnabled, Source: "windows_certutil"}
	}
	if strings.Contains(normalized, "0x80070002") || strings.Contains(normalized, "error_file_not_found") ||
		strings.Contains(normalized, "the system cannot find the file specified") {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceDisabled, Source: "windows_certutil"}
	}
	return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "windows_certutil_unavailable"}
}
