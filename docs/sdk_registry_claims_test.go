// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A250: no SDK package is published to a public registry, so no page may say
// one is or offer a command that installs from one. An install command in a
// code block must name a local registry: npm with --registry, pip with
// --index-url, and `go get` of the SDK with GOPROXY set.
func TestNoDocClaimsAPublicSDKRegistryA250(t *testing.T) {
	var files []string
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "third_party", ".git", "dist", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join("..", "web", "src", "pages", "Integrate.tsx"))
	if len(files) < 50 {
		t.Fatalf("found only %d pages; the walk is broken", len(files))
	}
	for _, path := range files {
		raw, err := os.ReadFile(path) // #nosec G304 -- a page in this checkout (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		for _, problem := range registryClaims(path, string(raw)) {
			t.Error(problem)
		}
	}
	// The matcher fails on what it is for and passes a local-registry page.
	for _, bad := range []string{
		"```bash\nnpm install @trstctl/sdk\n```", "```sh\npip install trstctl-sdk==0.1.0\n```",
		"```bash\ngo get trstctl.com/sdk/go@v0.1.0\n```", "The SDK is available on PyPI.", "See https://pypi.org/project/trstctl-sdk/.",
	} {
		if len(registryClaims("x.md", bad)) == 0 {
			t.Errorf("the guard passed %q", bad)
		}
	}
	good := "```bash\nnpm install --registry http://127.0.0.1:8790/npm/ @trstctl/sdk@0.1.0\n" +
		"python3 -m pip install --index-url http://127.0.0.1:8790/pypi/simple/ trstctl-sdk==0.1.0\n" +
		"GOPROXY=http://127.0.0.1:8790/go GONOPROXY=none \\\n  go get trstctl.com/sdk/go@v0.1.0\n```\n" +
		"`go get trstctl.com/sdk/go` does not resolve without a registry, and `npm install` takes a directory too."
	if problems := registryClaims("x.md", good); len(problems) != 0 {
		t.Errorf("the guard refused a local-registry page: %v", problems)
	}
}

var (
	publicRegistryClaim = regexp.MustCompile(`(?i)(pypi\.org/project/trstctl|npmjs\.com/package/@trstctl|pkg\.go\.dev/trstctl\.com|` +
		`central\.sonatype\.com/artifact/com\.trstctl|search\.maven\.org/artifact/com\.trstctl|` +
		`(available|published) (on|to|from|in) (npm|pypi|maven central|the npm registry|pkg\.go\.dev))`)
	npmInstall = regexp.MustCompile(`npm (install|i|add)\b[^\n]*@trstctl/sdk`)
	pipInstall = regexp.MustCompile(`pip3? install\b[^\n]*\btrstctl-sdk\b`)
	goGet      = regexp.MustCompile(`^\s*(\$ )?go get trstctl\.com/sdk/go`)
)

// registryClaims lists where text says an SDK is on a public registry or
// gives a command that installs one from it.
func registryClaims(path, text string) []string {
	var out []string
	if m := publicRegistryClaim.FindString(text); m != "" {
		out = append(out, path+" says an SDK is on a public registry ("+m+"); the packages are installed from a local registry")
	}
	for _, cmd := range commandLines(path, text) {
		cmd = strings.TrimSpace(cmd)
		switch {
		case npmInstall.MatchString(cmd) && !strings.Contains(cmd, "--registry"):
			out = append(out, path+" installs @trstctl/sdk without a local --registry: "+cmd)
		case pipInstall.MatchString(cmd) && !strings.Contains(cmd, "--index-url"):
			out = append(out, path+" installs trstctl-sdk without a local --index-url: "+cmd)
		case goGet.MatchString(cmd) && !strings.Contains(cmd, "GOPROXY="):
			out = append(out, path+" gets the Go SDK without a local GOPROXY: "+cmd)
		}
	}
	return out
}

func commandLines(path, text string) []string {
	lines := strings.Split(strings.ReplaceAll(text, "\\\n", " "), "\n")
	if !strings.HasSuffix(path, ".md") {
		return lines
	}
	var out []string
	inBlock := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inBlock = !inBlock
			continue
		}
		if inBlock {
			out = append(out, line)
		}
	}
	return out
}
