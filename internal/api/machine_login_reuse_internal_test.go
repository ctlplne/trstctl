// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
)

// M4-L1: the machine-login preview says whether a credential logs in once.
// OIDC and JWT logins pass the replay guard, so their tokens are single-use;
// every other method's credential logs in again until it expires.
func TestMachineLoginPreviewSaysWhetherTheCredentialIsSingleUse(t *testing.T) {
	for typ, want := range map[string]bool{
		"oidc": true, "jwt": true, "token": false, "kubernetes": false, "gcp": false, "azure": false, "aws-iam": false,
	} {
		single, reuse := machineLoginCredentialReuse(machineAuthMethodInfo{Name: typ, Type: typ})
		if single != want || reuse == "" {
			t.Fatalf("%s single_use = %v (%q), want %v", typ, single, reuse, want)
		}
		if prefix := map[bool]string{true: "Single-use", false: "Reusable"}[want]; !strings.HasPrefix(reuse, prefix) {
			t.Fatalf("%s reuse sentence %q does not start with %q", typ, reuse, prefix)
		}
	}
}
