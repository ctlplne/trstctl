// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

// TestExactCandidateCLIHasAReleaseAndInstallContract is the DP-008 packaging
// control. ELI5: the server, the download, and the text printed by --version
// must all point to the same commit before a token ever enters the process.
func TestExactCandidateCLIHasAReleaseAndInstallContract(t *testing.T) {
	script := read(t, "../scripts/release/cli-assets.sh")
	for _, marker := range []string{
		"git rev-parse HEAD",
		"trstctl-cli_${VERSION}_${platform}",
		"trstctl-cli_${VERSION}_manifest.json",
		"trstctl-cli_${VERSION}_SHA256SUMS",
		"-buildvcs=false",
		"internal/buildinfo.commit=${COMMIT}",
	} {
		if !strings.Contains(script, marker) {
			t.Errorf("DP-008: CLI asset builder is missing %q", marker)
		}
	}

	workflow := read(t, "../.github/workflows/release.yml")
	for _, marker := range []string{
		"cli-client:",
		"scripts/release/cli-assets.sh",
		"trstctl-cli-release",
		"trstctl-cli.intoto.jsonl",
		"slsa / cli client provenance",
	} {
		if !strings.Contains(workflow, marker) {
			t.Errorf("DP-008: release workflow is missing %q", marker)
		}
	}

	install := read(t, "install.md")
	flatInstall := strings.Join(strings.Fields(install), " ")
	for _, marker := range []string{
		"## Install the exact API client",
		"trstctl-cli --version",
		"sha256sum -c",
		"TRSTCTL_CA_FILE",
		"TRSTCTL_TOKEN",
		"full 40-character source commit",
	} {
		if !strings.Contains(flatInstall, strings.Join(strings.Fields(marker), " ")) {
			t.Errorf("DP-008: install guide is missing %q", marker)
		}
	}
}
