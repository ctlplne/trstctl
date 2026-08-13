// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"encoding/json"
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
		"SEC-5b43d4b3",
		"S-7268c77e",
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

func TestSDKGeneratorAdvisoriesStayRemediated(t *testing.T) {
	t.Parallel()

	register, err := os.ReadFile("security-exceptions.md")
	if err != nil {
		t.Fatalf("read security exception register: %v", err)
	}
	for _, stale := range []string{
		"S-a72284e3",
		"GHSA-52cp-r559-cp3m",
		"GHSA-3jxr-9vmj-r5cp",
		"js-yaml@4.2.0",
		"brace-expansion@2.1.1",
	} {
		if strings.Contains(string(register), stale) {
			t.Errorf("security exception register retains remediated SDK-generator debt %q", stale)
		}
	}

	type lockedPackage struct {
		Version string `json:"version"`
	}
	var lock struct {
		Packages map[string]lockedPackage `json:"packages"`
	}
	contents, err := os.ReadFile("../clients/sdk/typescript/package-lock.json")
	if err != nil {
		t.Fatalf("read TypeScript SDK generator lockfile: %v", err)
	}
	if err := json.Unmarshal(contents, &lock); err != nil {
		t.Fatalf("decode TypeScript SDK generator lockfile: %v", err)
	}
	for path, want := range map[string]string{
		"node_modules/@redocly/openapi-core": "1.34.19",
		"node_modules/js-yaml":               "4.3.1",
		"node_modules/brace-expansion":       "2.1.4",
	} {
		if got := lock.Packages[path].Version; got != want {
			t.Errorf("%s version = %q, want remediated %q", path, got, want)
		}
	}
}

func TestReactRouterExceptionNamesPublishedButIncompatiblePatch(t *testing.T) {
	t.Parallel()

	register, err := os.ReadFile("security-exceptions.md")
	if err != nil {
		t.Fatalf("read security exception register: %v", err)
	}
	text := string(register)
	normalized := strings.Join(strings.Fields(text), " ")
	for _, required := range []string{
		"react-router@8.3.0`, is published",
		"React and React DOM `>=19.2.7`",
		"Node `>=22.22.0`",
		"react-router-dom`, `7.18.2`",
		"react-router@7.18.2",
		"lockfile currently installs both packages at",
		"compatible `react-router-dom` release",
		"Publication of the standalone router alone is not that event",
	} {
		if !strings.Contains(normalized, required) {
			t.Errorf("React Router exception does not contain current compatibility fact %q", required)
		}
	}
	if strings.Contains(normalized, "8.3.0` as the first patched release, but that version is not published") {
		t.Error("React Router exception still calls the published 8.3.0 patch unavailable")
	}
}
