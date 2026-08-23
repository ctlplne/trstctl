// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"regexp"
	"strings"
	"testing"
)

func TestInstallGuideDoesNotInventAProductionContainerOrSignerHelper(t *testing.T) {
	install := read(t, "install.md")
	chartReadme := read(t, "../deploy/helm/trstctl/README.md")

	if strings.Contains(install, "docker run --rm -p 8443:8443") {
		t.Fatal("install.md must not present a disposable one-container command as a production control plane")
	}
	for _, document := range []struct {
		name string
		body string
	}{
		{name: "install.md", body: install},
		{name: "Helm README", body: chartReadme},
	} {
		if strings.Contains(document.body, "/usr/local/bin/trstctl-sign-approve") {
			t.Errorf("%s names trstctl-sign-approve even though the official image does not ship that executable", document.name)
		}
	}
	for _, want := range []string{
		"not a complete production deployment",
		"official trstctl image does not include",
		"operator-provided signer authorization client",
	} {
		if !strings.Contains(install+"\n"+chartReadme, want) {
			t.Errorf("production install truth is missing %q", want)
		}
	}
}

func TestQuietConfidenceSecurityClaimsStayBounded(t *testing.T) {
	readme := read(t, "../README.md")
	for _, overclaim := range []string{"tamper-proof", "hard-isolated"} {
		if strings.Contains(strings.ToLower(readme), overclaim) {
			t.Errorf("README still uses unbounded security claim %q", overclaim)
		}
	}
	for _, want := range []string{"tamper-evident", "row-level security", "downloads the pinned PostgreSQL runtime"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README is missing bounded customer-facing truth %q", want)
		}
	}
}

func TestFencedShellExamplesDoNotHintAtTLSBypass(t *testing.T) {
	install := read(t, "install.md")
	blocks := regexp.MustCompile("(?s)```(?:bash|sh|shell)\\s*(.*?)```").FindAllStringSubmatch(install, -1)
	unsafe := regexp.MustCompile(`(?m)(?:^|\s)(?:-[A-Za-z]*k[A-Za-z]*|--insecure|\(-k\))(?:\s|$)`)
	for _, block := range blocks {
		if unsafe.MatchString(block[1]) {
			t.Errorf("install.md fenced shell example hints at disabling TLS verification:\n%s", strings.TrimSpace(block[1]))
		}
	}
}
