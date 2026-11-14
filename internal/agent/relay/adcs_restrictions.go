// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"net"
	"strings"

	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/netsec"
)

// certutilRPCPort is the RPC endpoint mapper port certutil's -config read
// reaches a CA through first.
const certutilRPCPort = "135"

// caRestrictionsEgress checks the CA a directory named against this agent's
// egress policy before an external tool reaches it (A229-L1): certutil
// connects on its own, outside the Go dialer's guard, so the CA host's
// resolved addresses are checked here first, as every other job connection
// is checked when it is dialed. A refusal leaves the evidence unobserved
// ("egress_refused"); it is never assumed either way.
func caRestrictionsEgress(ctx context.Context, service adcs.EnrollmentService) (adcs.EnrollmentAgentRestrictions, bool) {
	host := strings.TrimSpace(service.DNSName)
	if host == "" {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "ca_identity_unobserved"}, false
	}
	if err := externalToolEgress(ctx, host, certutilRPCPort); err != nil {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "egress_refused"}, false
	}
	return adcs.EnrollmentAgentRestrictions{}, true
}

// externalToolEgress checks a host an external tool will reach on its own
// (certutil) against this agent's egress policy, as a dial is checked: every
// address it resolves to must be allowed. A name the agent cannot resolve
// itself (a NetBIOS name Windows resolves for certutil) passes only when no
// allowlist is configured, since nothing then limits where jobs may go
// beyond the always-refused addresses; with an allowlist it is refused,
// because it cannot be shown to be on the list.
func externalToolEgress(ctx context.Context, host, port string) error {
	err := egress().CheckHostPort(ctx, net.JoinHostPort(host, port))
	if err == nil || errors.Is(err, netsec.ErrRelayEgressBlocked) || egress().Allowlisted() {
		return err
	}
	return nil
}

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
