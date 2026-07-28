// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestSecurityExceptionRegisterKeepsAcceptedDebtVisible(t *testing.T) {
	t.Parallel()

	register, err := os.ReadFile("security-exceptions.md")
	if err != nil {
		t.Fatalf("read security exception register: %v", err)
	}
	text := string(register)
	for _, required := range []string{
		"GHSA-qwww-vcr4-c8h2",
		"GHSA-mh99-v99m-4gvg",
		"GHSA-52cp-r559-cp3m",
		"GHSA-3jxr-9vmj-r5cp",
		"SEC-5b43d4b3",
		"S-7268c77e",
		"S-a72284e3",
		"Accepted:",
		"Review by:",
		"Package and version:",
		"Why no compatible patch exists:",
		"Why the vulnerable path is unreachable:",
		"What we are waiting for:",
		"Gate remains reporting:",
		"audit-harness/harness.sh reopen <card>",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("security exception register does not contain %q", required)
		}
	}

	sca, err := os.ReadFile("../scripts/ci/npm-audit-dependency-surfaces.sh")
	if err != nil {
		t.Fatalf("read npm SCA gate: %v", err)
	}
	script := string(sca)
	for _, required := range []string{
		`audit_lock "web"`,
		`"build-and-production" --include=dev`,
		`audit_lock "typescript-sdk-generator"`,
		`"dev-generator" --include=dev`,
		"--audit-level=high",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("npm SCA gate no longer contains %q", required)
		}
	}

	if nav, err := os.ReadFile("../mkdocs.yml"); err != nil {
		t.Fatalf("read MkDocs navigation: %v", err)
	} else if !strings.Contains(string(nav), "security-exceptions.md") {
		t.Error("MkDocs navigation does not expose the security exception register")
	}
}
