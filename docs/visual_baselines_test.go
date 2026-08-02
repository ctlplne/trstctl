// SPDX-License-Identifier: MPL-2.0

package docs

// ---- CODE-109: committed Playwright baselines must be consumable by real CI ----
//
// A screenshot baseline is only a guard if some configured job can compare against
// it. Playwright resolves `toHaveScreenshot("home-dark.png")` to
// `home-dark-<project>-<platform>.png`, where <platform> is the Node process.platform
// of the machine that recorded it. A baseline recorded on macOS (`-darwin.png`) is
// therefore invisible to a Linux runner: that runner looks for `-linux.png`, does not
// find it, and WRITES a new baseline instead of failing. Committing baselines no job
// can read is dead weight that reads like coverage.
//
// This guard pins the honest state. Every tracked Playwright baseline must carry a
// platform suffix that some ci.yml job actually invoking Playwright would produce.
// When no baselines are tracked at all — the deliberate "visual regression is
// local-only" posture — the guard instead requires the tree to SAY so (web/DESIGN.md)
// and to keep locally generated snapshots untracked (.gitignore), so the absence is a
// recorded decision rather than an oversight. It also holds the two comments that
// used to describe the committed-baseline world to the current one.
//
// Helper `read` is defined in docs/docs_test.go and reused here.

import (
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// playwrightPlatformForRunner maps a GitHub Actions runner-image prefix to the Node
// process.platform token Playwright appends to a snapshot file name.
var playwrightPlatformForRunner = map[string]string{
	"ubuntu":  "linux",
	"macos":   "darwin",
	"windows": "win32",
}

// baselineSuffixRE captures the `-<project>-<platform>` tail Playwright appends to
// every screenshot name.
var baselineSuffixRE = regexp.MustCompile(`-([a-z0-9]+)-([a-z0-9]+)\.png$`)

type ciStep struct {
	Run string `yaml:"run"`
}

type ciJob struct {
	Name   string   `yaml:"name"`
	RunsOn any      `yaml:"runs-on"`
	Steps  []ciStep `yaml:"steps"`
}

type ciWorkflow struct {
	Jobs map[string]ciJob `yaml:"jobs"`
}

// TestCommittedVisualBaselinesMatchAConfiguredRunner locks CODE-109.
func TestCommittedVisualBaselinesMatchAConfiguredRunner(t *testing.T) {
	var wf ciWorkflow
	if err := yaml.Unmarshal([]byte(read(t, "../.github/workflows/ci.yml")), &wf); err != nil {
		t.Fatalf("CODE-109: parse .github/workflows/ci.yml: %v", err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("CODE-109: parsed no jobs out of ci.yml; the workflow shape changed, so revisit this guard")
	}

	// Platforms a CI job that actually invokes Playwright could record or compare.
	runnable := map[string]string{} // platform token -> job id that would produce it
	for id, job := range wf.Jobs {
		invokesPlaywright := false
		for _, s := range job.Steps {
			if strings.Contains(s.Run, "playwright") || strings.Contains(s.Run, "npm run e2e") {
				invokesPlaywright = true
				break
			}
		}
		if !invokesPlaywright {
			continue
		}
		var labels []string
		switch v := job.RunsOn.(type) {
		case string:
			labels = []string{v}
		case []any:
			for _, e := range v {
				labels = append(labels, fmt.Sprint(e))
			}
		}
		for _, label := range labels {
			for prefix, platform := range playwrightPlatformForRunner {
				if strings.HasPrefix(label, prefix) {
					runnable[platform] = id
				}
			}
		}
	}
	platforms := make([]string, 0, len(runnable))
	for p := range runnable {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)

	// Tracked baselines come from git, not the filesystem: an untracked local
	// `--update-snapshots` run must not be able to satisfy or break this guard.
	cmd := exec.Command("git", "ls-files", "-z", "web/e2e")
	cmd.Dir = ".."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("CODE-109: list tracked files under web/e2e: %v", err)
	}
	var baselines []string
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" || !strings.HasSuffix(rel, ".png") || !strings.Contains(rel, "-snapshots/") {
			continue
		}
		baselines = append(baselines, rel)
	}

	for _, rel := range baselines {
		m := baselineSuffixRE.FindStringSubmatch(path.Base(rel))
		if m == nil {
			t.Errorf("CODE-109: %s is a committed Playwright baseline with no -<project>-<platform>.png suffix; Playwright would never resolve it", rel)
			continue
		}
		if _, ok := runnable[m[2]]; !ok {
			t.Errorf("CODE-109: %s is recorded for platform %q, but no ci.yml job that invokes Playwright runs on a %s runner (Playwright-capable platforms: %v); no job could ever compare against it", rel, m[2], m[2], platforms)
		}
	}

	if len(baselines) == 0 {
		// The deliberate local-only posture. It has to be written down, and a local
		// --update-snapshots run must not be able to quietly re-commit dead files.
		if design := read(t, "../web/DESIGN.md"); !strings.Contains(design, "local-only") {
			t.Error("CODE-109: no Playwright baselines are tracked, so web/DESIGN.md must state that visual regression is local-only")
		}
		if ignore := read(t, "../.gitignore"); !strings.Contains(ignore, "/web/e2e/*-snapshots/") {
			t.Error("CODE-109: no Playwright baselines are tracked, so .gitignore must carry `/web/e2e/*-snapshots/`, or a local --update-snapshots run re-commits baselines no job can read")
		}
	}

	// The comments that described the committed-baseline world must not survive it.
	for _, stale := range []struct{ file, phrase string }{
		{"../.github/workflows/ci.yml", "until the visual baselines are generated and committed"},
		{"../web/src/lib/utils.test.ts", "once baselines exist"},
		{"../web/DESIGN.md", "Visual baselines are committed"},
		{"../web/playwright.config.ts", "Visual baselines are written on first run"},
	} {
		if strings.Contains(read(t, stale.file), stale.phrase) {
			t.Errorf("CODE-109: %s still says %q; that describes a committed-baseline world this repo no longer has", strings.TrimPrefix(stale.file, "../"), stale.phrase)
		}
	}
}
