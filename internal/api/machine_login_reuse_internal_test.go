// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
)

// M4-L1: the machine-login preview says whether a credential logs in once.
// OIDC, JWT, Kubernetes, GCP, Azure and AWS IAM logins pass the replay guard,
// so their credentials are single-use; a machine token remains reusable.
func TestMachineLoginPreviewSaysWhetherTheCredentialIsSingleUse(t *testing.T) {
	for typ, want := range map[string]bool{
		"oidc": true, "jwt": true, "token": false, "kubernetes": true, "gcp": true, "azure": true, "aws-iam": true,
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

// A238-L8: a Kubernetes, GCP or Azure method whose operator set
// allow_token_reuse is reusable, and the preview names the setting.
func TestMachineLoginPreviewNamesAllowedTokenReuse(t *testing.T) {
	for _, typ := range []string{"kubernetes", "gcp", "azure"} {
		single, reuse := machineLoginCredentialReuse(machineAuthMethodInfo{Name: typ, Type: typ, AllowTokenReuse: true})
		if single || !strings.HasPrefix(reuse, "Reusable") || !strings.Contains(reuse, "allow_token_reuse") {
			t.Fatalf("%s with allow_token_reuse: single_use = %v (%q); want reusable naming allow_token_reuse", typ, single, reuse)
		}
	}
}
