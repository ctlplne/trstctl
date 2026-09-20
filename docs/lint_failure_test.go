// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the actual Make recipes with failed tools. A later failure must not
// hide that a prerequisite was ignored, so the fixture records every Go call.
func TestMakeLintStopsOnToolFailure(t *testing.T) {
	for _, fault := range []string{"git", "xargs", "gofmt-first-file", "mktemp", "analyzer-build"} {
		t.Run(fault, func(t *testing.T) {
			root, bin, env := lintFailureFixture(t)
			env = withEnvOverrides(env, "LINT_FAULT="+fault)
			writeExecutable(t, filepath.Join(bin, "golangci-lint"), "#!/bin/sh\necho 'reached later linter' >&2\nexit 23\n")
			out, err := runLintFixture(t, root, env, "lint")
			if err == nil || !strings.Contains(string(out), "injected "+fault) {
				t.Fatalf("missing injected failure: %v\n%s", err, out)
			}
			calls, err := openLintRoot(t, root).ReadFile("go-calls")
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			forbidden := "vet"
			switch fault {
			case "mktemp":
				forbidden = "build"
			case "analyzer-build":
				forbidden = "-vettool="
			}
			if strings.Contains(string(calls), forbidden) || strings.Contains(string(out), "reached later linter") {
				t.Fatalf("lint continued after failed %s; calls=%s\n%s", fault, calls, out)
			}
		})
	}
	t.Run("python-deadline-retains-output", testEELintPythonDeadline)
}

func testEELintPythonDeadline(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	code := `import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("ee_lint", "../scripts/ci/ee-lint-ratchet.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.run_scanner([sys.executable, "-c", "import time; print('partial scanner report', flush=True); time.sleep(60)"], timeout=2)
except subprocess.TimeoutExpired:
    sys.exit(0)
sys.exit(1)
`
	cmd := exec.Command(python, "-B", "-c", code) // #nosec G204 -- fixed timeout regression over an owned Python child (CWE-78)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "partial scanner report") {
		t.Fatalf("timeout lost partial diagnostics: %v\n%s", err, out)
	}
}

func TestEELintRejectsIncompleteScans(t *testing.T) {
	linters := `"Linters":[{"Name":"errcheck","Enabled":true},{"Name":"govet","Enabled":true},{"Name":"ineffassign","Enabled":true},{"Name":"staticcheck","Enabled":true},{"Name":"unused","Enabled":true},{"Name":"gosec","Enabled":true}]`
	clean := `{"Issues":[],"Report":{` + linters + `}}`
	issue := `{"Issues":[{"FromLinter":"gosec","Text":"unsafe fixture","Pos":{"Filename":"ee/pkg/a.go","Line":1,"Column":1}}],"Report":{` + linters + `}}`
	type scanCase struct {
		name, baseline, report, code string
		pass                         bool
	}
	cases := []scanCase{
		{"clean", "0\n", clean, "0", true},
		{"existing-findings", "1\n", issue, "1", true},
		{"new-finding", "0\n", issue, "1", false},
		{"timeout", "0\n", "", "4", false},
		{"tool-error", "0\n", "", "3", false},
		{"malformed", "0\n", "broken JSON", "0", false},
		{"empty", "0\n", "", "0", false},
		{"missing-issues", "0\n", `{"Report":{}}`, "0", false},
		{"report-error", "0\n", `{"Issues":[],"Report":{"Error":"load failed",` + linters + `}}`, "0", false},
		{"report-warning", "0\n", `{"Issues":[],"Report":{"Warnings":[{"Text":"analysis incomplete"}],` + linters + `}}`, "0", false},
		{"false-error", "0\n", `{"Issues":[],"Report":{"Error":false,` + linters + `}}`, "0", false},
		{"object-error", "0\n", `{"Issues":[],"Report":{"Error":{},` + linters + `}}`, "0", false},
		{"null-error", "0\n", `{"Issues":[],"Report":{"Error":null,` + linters + `}}`, "0", false},
		{"object-warnings", "0\n", `{"Issues":[],"Report":{"Warnings":{},` + linters + `}}`, "0", false},
		{"numeric-warnings", "0\n", `{"Issues":[],"Report":{"Warnings":0,` + linters + `}}`, "0", false},
		{"null-warnings", "0\n", `{"Issues":[],"Report":{"Warnings":null,` + linters + `}}`, "0", false},
		{"empty-native-metadata", "0\n", `{"Issues":[],"Report":{"Error":"","Warnings":[],` + linters + `}}`, "0", true},
		{"no-linter", "0\n", `{"Issues":[],"Report":{}}`, "0", false},
		{"inconsistent-exit", "0\n", clean, "1", false},
		{"findings-with-success-exit", "1\n", issue, "0", false},
		{"fatal-after-findings", "1\n", issue, "3", false},
		{"duplicate-fields", "0\n", strings.Replace(clean, `"Issues":[]`, `"Issues":[],"Issues":[]`, 1), "0", false},
		{"non-finite", "0\n", strings.Replace(clean, `"Report":{`, `"extra":NaN,"Report":{`, 1), "0", false},
		{"missing-baseline", "", clean, "0", false},
		{"invalid-baseline", "not-a-count\n", clean, "0", false},
		{"oversized-baseline", "0" + strings.Repeat(" ", 1023) + "invalid", clean, "0", false},
		{"clean-does-not-rewrite-baseline", "1\n", clean, "0", true},
	}
	for _, name := range []string{"errcheck", "govet", "ineffassign", "staticcheck", "unused", "gosec"} {
		needle := `{"Name":"` + name + `","Enabled":true}`
		cases = append(cases, scanCase{"disabled-" + name, "0\n", strings.Replace(clean, needle, `{"Name":"`+name+`","Enabled":false}`, 1), "0", false})
		cases = append(cases, scanCase{"missing-" + name, "0\n", strings.Replace(clean, needle, `{"Name":"unrelated","Enabled":true}`, 1), "0", false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, bin, env := lintFailureFixture(t)
			baseline := filepath.Join(root, ".ee-lint-baseline")
			if tc.baseline != "" {
				if err := os.WriteFile(baseline, []byte(tc.baseline), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeExecutable(t, filepath.Join(bin, "golangci-lint"), "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$LINT_ARGS\"\nprintf '%s' \"$LINT_REPORT\"\necho 'fixture scanner diagnostic' >&2\nexit \"$LINT_CODE\"\n")
			env = withEnvOverrides(env, "LINT_REPORT="+tc.report, "LINT_CODE="+tc.code)
			out, err := runLintFixture(t, root, env, "ee-lint-ratchet")
			if (err == nil) != tc.pass {
				t.Errorf("pass=%v, want %v: %v\n%s", err == nil, tc.pass, err, out)
			}
			if tc.baseline != "" && tc.name != "invalid-baseline" && tc.name != "oversized-baseline" {
				if !strings.Contains(string(out), "fixture scanner diagnostic") || !strings.Contains(string(out), tc.report) {
					t.Errorf("scanner diagnostics/report were discarded:\n%s", out)
				}
				args, readErr := openLintRoot(t, root).ReadFile("scanner-args")
				if readErr != nil {
					t.Fatal(readErr)
				}
				for _, want := range []string{"run", "--timeout", "25m", "--issues-exit-code=1", "--max-issues-per-linter=0", "--max-same-issues=0", "--uniq-by-line=false", "--output.json.path=stdout", "--output.text.path=/dev/null", "--show-stats=false", "./ee/..."} {
					if !strings.Contains("\n"+string(args), "\n"+want+"\n") {
						t.Errorf("missing scanner argument %q: %s", want, args)
					}
				}
			}
			after, readErr := openLintRoot(t, root).ReadFile(".ee-lint-baseline")
			if string(after) != tc.baseline || (tc.baseline == "" && !os.IsNotExist(readErr)) {
				t.Errorf("lint changed baseline after scan: %q, %v", after, readErr)
			}
		})
	}
}

func openLintRoot(t *testing.T, path string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}

func lintFailureFixture(t *testing.T) (string, string, []string) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	source := openLintRoot(t, "..")
	destination := openLintRoot(t, root)
	for _, name := range []string{"Makefile", "scripts/ci/ee-lint-ratchet.py"} {
		data, err := source.ReadFile(name)
		if os.IsNotExist(err) && name != "Makefile" {
			continue // The pre-repair recipe does not have the structured adapter.
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := destination.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := destination.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("package fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"bash", "python3"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("required fixture tool %s: %v", tool, err)
		}
		if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable(t, filepath.Join(bin, "git"), `#!/bin/sh
if [ "$1" = ls-files ]; then
  if [ "$LINT_FAULT" = git ]; then echo 'injected git' >&2; exit 2; fi
  printf 'a.go\000b.go\000'
fi
`)
	writeExecutable(t, filepath.Join(bin, "xargs"), `#!/bin/sh
if [ "$LINT_FAULT" = xargs ]; then echo 'injected xargs' >&2; exit 2; fi
exec /usr/bin/xargs "$@"
`)
	writeExecutable(t, filepath.Join(bin, "gofmt"), `#!/bin/sh
for arg do last="$arg"; done
if [ "$LINT_FAULT" = gofmt-first-file ] && [ "$last" = a.go ]; then echo 'injected gofmt-first-file' >&2; exit 2; fi
exit 0
`)
	writeExecutable(t, filepath.Join(bin, "mktemp"), `#!/bin/sh
if [ "$LINT_FAULT" = mktemp ]; then echo 'injected mktemp' >&2; exit 2; fi
exec /usr/bin/mktemp "$@"
`)
	writeExecutable(t, filepath.Join(bin, "go"), `#!/bin/sh
if [ "$1" = env ]; then exit 0; fi
printf '%s\n' "$*" >> "$LINT_CALLS"
if [ "$1" = build ] && [ "$LINT_FAULT" = analyzer-build ]; then echo 'injected analyzer-build' >&2; exit 2; fi
exit 0
`)
	env := withEnvOverrides(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "TMPDIR="+root, "LINT_CALLS="+filepath.Join(root, "go-calls"), "LINT_ARGS="+filepath.Join(root, "scanner-args"), "LINT_FAULT=")
	return root, bin, env
}

func runLintFixture(t *testing.T, root string, env []string, target string) ([]byte, error) {
	t.Helper()
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(makePath, "-j1", target, "VERSION=fixture", "COMMIT=fixture", "DATE=fixture", "GO_TOOL_BIN="+filepath.Join(root, "bin")) // #nosec G204 -- fixed local Make target in an owned test fixture (CWE-78)
	cmd.Dir, cmd.Env = root, env
	return cmd.CombinedOutput()
}
