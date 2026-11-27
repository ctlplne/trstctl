// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReleaseIdentityGuidanceUsesScopedPatterns(t *testing.T) {
	for _, root := range []string{".", "../deploy", "../scripts"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			switch filepath.Ext(path) {
			case ".md", ".sh", ".yml", ".yaml":
			default:
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			content, err := fs.ReadFile(os.DirFS(root), rel)
			if err != nil {
				return err
			}
			if strings.Contains(string(content), "/.*/trstctl") || strings.Contains(string(content), "@.*") {
				t.Errorf("%s contains an unscoped release identity pattern", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPublishedArtifactGuidancePinsRepositoryAndTag(t *testing.T) {
	pattern := regexp.MustCompile(`--certificate-identity-regexp '([^']+)'`)
	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "install.md", want: 1},
		{path: "../deploy/docker/README.md", want: 1},
	} {
		t.Run(tc.path, func(t *testing.T) {
			content, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			matches := pattern.FindAllStringSubmatch(string(content), -1)
			if len(matches) != tc.want {
				t.Fatalf("identity patterns = %d, want %d", len(matches), tc.want)
			}
			for _, match := range matches {
				assertReleaseIdentityPattern(t, match[1])
			}
		})
	}
	policy, err := os.ReadFile("../deploy/kubernetes/sigstore-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^\s*subjectRegExp:\s*(\S+)\s*$`).FindStringSubmatch(string(policy))
	if len(line) != 2 {
		t.Fatal("admission policy release identity is missing")
	}
	assertReleaseIdentityPattern(t, line[1])
}

func assertReleaseIdentityPattern(t *testing.T, expression string) {
	t.Helper()
	identity, err := regexp.Compile(expression)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		uri  string
		want bool
	}{
		{uri: "https://github.com/ctlplne/trstctl/.github/workflows/release.yml@refs/tags/v1.2.3", want: true},
		{uri: "https://github.com/another-owner/trstctl/.github/workflows/release.yml@refs/tags/v1.2.3"},
		{uri: "https://github.com/ctlplne/trstctl/.github/workflows/release.yml@refs/heads/main"},
		{uri: "https://githubXcom/ctlplne/trstctl/.github/workflows/release.yml@refs/tags/v1.2.3"},
		{uri: "https://github.com/ctlplne/trstctl/xgithub/workflows/release.yml@refs/tags/v1.2.3"},
	} {
		if got := identity.MatchString(tc.uri); got != tc.want {
			t.Errorf("release identity expression %q matched %q: got %v, want %v", expression, tc.uri, got, tc.want)
		}
	}
}

func TestChartVerificationRequiresDigestAndExactReleaseTag(t *testing.T) {
	root := t.TempDir()
	capture := filepath.Join(root, "capture")
	verify := func(cmd *exec.Cmd, wantSuccess bool) {
		t.Helper()
		if err := os.Remove(capture); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		cmd.Env = append(os.Environ(), "CAPTURE="+capture,
			"BASH_FUNC_cosign%%=() { printf '%s\\n' \"$@\" > \"$CAPTURE\"; }")
		output, err := cmd.CombinedOutput()
		if (err == nil) != wantSuccess {
			t.Fatalf("chart verification success=%v, want %v: %v: %s", err == nil, wantSuccess, err, output)
		}
		if !wantSuccess {
			if _, err := os.Stat(capture); !os.IsNotExist(err) {
				t.Fatalf("unaccepted chart input reached cosign: %v", err)
			}
			return
		}
		args, err := fs.ReadFile(os.DirFS(root), "capture")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(args), "\n--certificate-identity\nhttps://github.com/ctlplne/trstctl/.github/workflows/release.yml@refs/tags/v1.2.3\n") {
			t.Fatalf("exact release identity was not checked: %s", args)
		}
	}
	const ref = "ghcr.io/ctlplne/trstctl/charts/trstctl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verify(exec.Command("bash", "../scripts/verify-chart.sh", ref, "v1.2.3"), true)
	verify(exec.Command("bash", "../scripts/verify-chart.sh", "ghcr.io/ctlplne/trstctl/charts/trstctl:v1.2.3", "v1.2.3"), false)
	verify(exec.Command("bash", "../scripts/verify-chart.sh", ref, "main"), false)
}

func TestImageVerificationPinsRepositoryAndTag(t *testing.T) {
	root := t.TempDir()
	capture := filepath.Join(root, "capture")
	cmd := exec.Command("bash", "../scripts/verify-image.sh", "ghcr.io/ctlplne/trstctl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	cmd.Env = append(os.Environ(), "CAPTURE="+capture,
		"BASH_FUNC_cosign%%=() { printf '%s\\n' \"$@\" >> \"$CAPTURE\"; }")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("image verification: %v: %s", err, output)
	}
	args, err := fs.ReadFile(os.DirFS(root), "capture")
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`(?m)^--certificate-identity-regexp\n([^\n]+)$`).FindAllStringSubmatch(string(args), -1)
	if len(matches) != 2 {
		t.Fatalf("signature and attestation identity checks = %d, want 2", len(matches))
	}
	for _, match := range matches {
		assertReleaseIdentityPattern(t, match[1])
	}
}
