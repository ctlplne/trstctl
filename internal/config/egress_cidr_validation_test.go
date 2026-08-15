// SPDX-License-Identifier: MPL-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

// TestEveryEgressCIDRSurfaceRejectsHostBits is the regression guard for
// AUD-201 follow-up J1/V23. netip.ParsePrefix accepts 10.1.2.3/8 and Contains
// matches the masked form — so such entries USED TO WORK — while the dial-time
// guard silently skipped any entry failing validation. The loud parse-time
// rejection had reached exactly ONE of ~9 boundaries: on upgrade, a
// previously functional entry passed config validation everywhere except one
// API surface and was then ignored at dial time with no log, so private
// egress (connectors, Rekor, PagerDuty, managed keys, secret integrations,
// external CAs) failed as SSRF-blocked with nothing explaining why. Every
// surface now routes through netsec.ParseEgressAllowPrefix and refuses the
// entry at CONFIG LOAD, naming the value.
func TestEveryEgressCIDRSurfaceRejectsHostBits(t *testing.T) {
	const hostBits = "10.1.2.3/8"
	requireHostBitsError := func(t *testing.T, surface string, errs []error) {
		t.Helper()
		joined := errors.Join(errs...)
		if joined == nil {
			t.Fatalf("%s accepted the host-bits entry %q; it would be silently ignored at dial time", surface, hostBits)
		}
		if !strings.Contains(joined.Error(), "10.1.2.3/8") {
			t.Fatalf("%s refusal does not name the offending value: %v", surface, joined)
		}
	}

	t.Run("connectors.allow_private_cidrs", func(t *testing.T) {
		requireHostBitsError(t, "connectors", validateConnectors(Connectors{AllowPrivateCIDRs: []string{hostBits}}))
	})
	t.Run("code_signing rekor", func(t *testing.T) {
		requireHostBitsError(t, "code_signing.rekor", validateCodeSigningRekor(CodeSigningRekor{
			Endpoint: "https://rekor.internal", AllowPrivateCIDRs: []string{hostBits},
		}))
	})
	t.Run("notifications incident", func(t *testing.T) {
		requireHostBitsError(t, "notifications", validateIncidentNotification(
			"pagerduty", "https://events.pagerduty.internal", "5s", []string{hostBits}, false, true, ""))
	})
	t.Run("managed_keys", func(t *testing.T) {
		requireHostBitsError(t, "managed_keys", validateManagedKeyPrivateCIDRs("managed_keys.aws", []string{hostBits}))
	})
	t.Run("secret_integrations", func(t *testing.T) {
		requireHostBitsError(t, "secret_integrations", validatePrivateEgress("secret_integrations.vault", true, []string{hostBits}))
	})
	t.Run("external_ca", func(t *testing.T) {
		_, err := ExternalCANetworkConfig{PrivateEgressCIDRs: []string{hostBits}}.PrivatePrefixes()
		if err == nil {
			t.Fatalf("external_ca accepted the host-bits entry %q", hostBits)
		}
		if !strings.Contains(err.Error(), "10.1.2.3/8") {
			t.Fatalf("external_ca refusal does not name the offending value: %v", err)
		}
	})
	t.Run("itsm servicenow", func(t *testing.T) {
		cfg := Default()
		cfg.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{
			InstanceURL: "https://example.service-now.com", TokenRef: "env:X",
			AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{hostBits},
		}}
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("itsm.servicenow accepted the host-bits entry %q", hostBits)
		}
		if !strings.Contains(err.Error(), "10.1.2.3/8") {
			t.Fatalf("itsm.servicenow refusal does not name the offending value: %v", err)
		}
	})
}
