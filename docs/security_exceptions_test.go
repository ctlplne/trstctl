// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSecurityExceptionRegisterRecordsClosedDebtAndKeepsGatesVisible(t *testing.T) {
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
		"Closed:",
		"Resolved version",
		"Why it is closed:",
		"Verification:",
		"audit-harness/harness.sh reopen <card>",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("security exception register does not contain %q", required)
		}
	}

	openSection := strings.SplitN(text, "## Closed exceptions", 2)[0]
	for _, closedAdvisory := range []string{"GHSA-qwww-vcr4-c8h2", "GHSA-mh99-v99m-4gvg"} {
		if strings.Contains(openSection, "### "+closedAdvisory) {
			t.Errorf("remediated advisory %q is still listed as an open exception", closedAdvisory)
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
		"node_modules/@redocly/openapi-core": "1.34.20",
		"node_modules/js-yaml":               "4.3.2",
		"node_modules/brace-expansion":       "2.1.4",
	} {
		if got := lock.Packages[path].Version; got != want {
			t.Errorf("%s version = %q, want remediated %q", path, got, want)
		}
	}
}

func TestReactRouterExceptionRecordsCompatiblePatchedPair(t *testing.T) {
	t.Parallel()

	register, err := os.ReadFile("security-exceptions.md")
	if err != nil {
		t.Fatalf("read security exception register: %v", err)
	}
	text := string(register)
	normalized := strings.Join(strings.Fields(text), " ")
	for _, required := range []string{
		"GHSA-qwww-vcr4-c8h2 — React Router RSC action handling",
		"Closed:** 2026-08-20",
		"react-router@7.18.2` through `react-router-dom@7.18.2",
		"names `7.18.2` as the patched 7.x release",
		"direct package floor and lockfile both resolve `react-router-dom` and its `react-router` dependency to `7.18.2`",
		"does not add an ignore or suppress a future router finding",
	} {
		if !strings.Contains(normalized, required) {
			t.Errorf("closed React Router exception does not contain remediation fact %q", required)
		}
	}
	for _, stale := range []string{
		"Why no compatible patch exists:",
		"Why the vulnerable path is unreachable:",
		"Publication of the standalone router alone is not that event",
	} {
		if strings.Contains(normalized, stale) {
			t.Errorf("closed React Router exception retains obsolete acceptance rationale %q", stale)
		}
	}

	type lockedPackage struct {
		Version string `json:"version"`
	}
	var lock struct {
		Packages map[string]lockedPackage `json:"packages"`
	}
	contents, err := os.ReadFile("../web/package-lock.json")
	if err != nil {
		t.Fatalf("read web lockfile: %v", err)
	}
	if err := json.Unmarshal(contents, &lock); err != nil {
		t.Fatalf("decode web lockfile: %v", err)
	}
	for path, want := range map[string]string{
		"node_modules/react-router":     "7.18.2",
		"node_modules/react-router-dom": "7.18.2",
	} {
		if got := lock.Packages[path].Version; got != want {
			t.Errorf("%s version = %q, want remediated %q", path, got, want)
		}
	}
}
