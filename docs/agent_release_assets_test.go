// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

func TestUnixHostAgentReleaseHasDownloadableVerifiedAssets(t *testing.T) {
	release := read(t, "../.github/workflows/release.yml")
	job := workflowJob(t, release, "agent-unix")
	for _, want := range []string{
		"needs: [test, required-checks, release-evidence]",
		"scripts/release/agent-assets.sh",
		"trstctl-agent_${version}_linux_amd64.tar.gz",
		"trstctl-agent_${version}_darwin_arm64.tar.gz",
		"sha256sum -c",
		"gh release upload \"$GITHUB_REF_NAME\" dist/agent/*",
		"gh release view \"$GITHUB_REF_NAME\" --json assets",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("Unix agent release job is missing %q", want)
		}
	}
	provenance := workflowJob(t, release, "agent-unix-provenance")
	for _, want := range []string{"needs: [agent-unix]", "id-token: write", "trstctl-agent-unix.intoto.jsonl"} {
		if !strings.Contains(provenance, want) {
			t.Errorf("Unix agent provenance job is missing %q", want)
		}
	}
	install := read(t, "install.md")
	for _, want := range []string{
		"trstctl-agent_${version}_${platform}.tar.gz",
		"trstctl-agent_${version}_SHA256SUMS",
		"curl --fail --location",
		"shasum -a 256 -c",
		"trstctl-agent --version",
	} {
		if !strings.Contains(install, want) {
			t.Errorf("install.md is missing a downloadable Unix host-agent step %q", want)
		}
	}
}
