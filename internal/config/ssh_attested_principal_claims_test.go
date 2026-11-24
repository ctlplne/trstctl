// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"slices"
	"testing"
)

func TestCR193AttestedSSHClaimMappingRequiresExactOperatorKeys(t *testing.T) {
	if errs := validateSSHAttestedPrincipalClaims([]string{"k8s_sat:sa", "gcp_iit:instance_id"}); len(errs) != 0 {
		t.Fatalf("valid operator claim keys refused: %v", errs)
	}
	for _, name := range []string{"pod", "k8s_sat:", ":pod", "k8s_sat:pod:extra", "k8s_sat:*", "github_oidc:repository_id", "github_oidc:repository_owner_id"} {
		if errs := validateSSHAttestedPrincipalClaims([]string{name}); len(errs) == 0 {
			t.Errorf("unsafe claim key %q accepted", name)
		}
	}
	if errs := validateSSHAttestedPrincipalClaims([]string{"k8s_sat:sa", "k8s_sat:sa"}); len(errs) == 0 {
		t.Error("duplicate claim key accepted")
	}
	var protocols Protocols
	applyProtocolsEnv(func(key string) string {
		if key == "TRSTCTL_PROTOCOLS_SSH_ATTESTED_PRINCIPAL_CLAIMS" {
			return "k8s_sat:sa, gcp_iit:instance_id"
		}
		return ""
	}, &protocols)
	if !slices.Equal(protocols.SSHAttestedPrincipalClaims, []string{"k8s_sat:sa", "gcp_iit:instance_id"}) {
		t.Errorf("attested claim keys from environment = %q", protocols.SSHAttestedPrincipalClaims)
	}
}
