// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"regexp"
	"strings"
	"testing"
)

func TestWindowsAgentReleasePublishesDurableAssets(t *testing.T) {
	release := read(t, "../.github/workflows/release.yml")
	job := workflowJob(t, release, "agent-windows")
	for _, want := range []string{
		"contents: write",
		"id-token: write",
		"osslsigncode verify -in \"$art\"",
		"sha256sum -c SHA256SUMS",
		"gh release upload \"$GITHUB_REF_NAME\"",
		"dist/trstctl-agent.exe",
		"dist/trstctl-agent.msi",
		"dist/SHA256SUMS",
		"gh release view \"$GITHUB_REF_NAME\" --json assets",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("agent-windows release job must contain %q for durable signed Windows release assets", want)
		}
	}
	if strings.Contains(job, "uses: actions/upload-artifact") {
		t.Error("agent-windows must publish durable GitHub Release assets, not temporary workflow artifacts")
	}

	install := read(t, "install.md")
	for _, want := range []string{"GitHub Release assets", "trstctl-agent.exe", "trstctl-agent.msi", "SHA256SUMS"} {
		if !strings.Contains(install, want) {
			t.Errorf("install.md must document Windows agent release asset %q", want)
		}
	}
}

func workflowJob(t *testing.T, workflow, job string) string {
	t.Helper()
	start := strings.Index(workflow, "\n  "+job+":")
	if start < 0 {
		t.Fatalf("workflow is missing job %s", job)
	}
	body := workflow[start+1:]
	if next := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:`).FindAllStringIndex(body, 2); len(next) == 2 {
		body = body[:next[1][0]]
	}
	return body
}
