// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"slices"
	"strings"
	"testing"
)

func TestCR192SSHHostPrincipalConfigurationRejectsPatterns(t *testing.T) {
	for _, literal := range []string{"edge-1.internal", "10.0.0.4", "2001:db8::1", "xn--bcher-kva.example"} {
		if !ValidSSHHostPrincipal(literal) {
			t.Errorf("literal host %q refused", literal)
		}
	}
	for _, pattern := range []string{"*", "*.example.com", "edge?", "edge[12]", "!edge", "edge,other", `edge\other`, "edge name", "éxample.com", "", strings.Repeat("a", 257)} {
		if ValidSSHHostPrincipal(pattern) || len(validateSSHHostPrincipals([]string{pattern})) == 0 {
			t.Errorf("OpenSSH pattern or invalid host %q accepted", pattern)
		}
	}
	if len(validateSSHHostPrincipals([]string{"edge-1.internal", "edge-1.internal"})) == 0 {
		t.Error("duplicate host approval accepted")
	}
	var protocols Protocols
	applyProtocolsEnv(func(key string) string {
		if key == "TRSTCTL_PROTOCOLS_SSH_HOST_PRINCIPALS" {
			return "edge-1.internal, edge-2.internal"
		}
		return ""
	}, &protocols)
	if !slices.Equal(protocols.SSHHostPrincipals, []string{"edge-1.internal", "edge-2.internal"}) {
		t.Errorf("host principal environment list = %q", protocols.SSHHostPrincipals)
	}
}
