// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeLintFailsClosedWithoutOptionalTools(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Fatalf("look up make: %v", err)
	}
	fakeBin := t.TempDir()
	installLintGateStubs(t, fakeBin)
	env := withEnvOverrides(os.Environ(),
		"PATH="+fakeBin,
		"TMPDIR="+t.TempDir(),
	)

	cmd := exec.Command(makePath, "-f", "../Makefile", "lint") // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("make lint passed even though golangci-lint/actionlint were hidden:\n%s", out)
	}
	got := string(out)
	if !strings.Contains(got, "FAIL: golangci-lint is not installed") {
		t.Fatalf("make lint failed for the wrong reason; want missing golangci-lint hard failure:\n%s", got)
	}
	if strings.Contains(got, "WARNING: golangci-lint NOT installed") {
		t.Fatalf("make lint used the partial-warning path instead of failing closed:\n%s", got)
	}

	cmd = exec.Command(makePath, "-f", "../Makefile", "lint-partial") // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Env = env
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make lint-partial should be the explicit partial lint escape hatch: %v\n%s", err, out)
	}
	got = string(out)
	for _, want := range []string{
		"WARNING: golangci-lint NOT installed",
		"WARNING: actionlint NOT installed",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("make lint-partial output missing %q:\n%s", want, got)
		}
	}
}

func installLintGateStubs(t *testing.T, dir string) {
	t.Helper()
	realBash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("look up bash: %v", err)
	}
	writeExecutable(t, filepath.Join(dir, "bash"), `#!/bin/sh
case "$1" in
scripts/ci/check-actions-pinned_selftest.sh|scripts/ci/check-actions-pinned.sh)
	exit 0
	;;
esac
exec `+realBash+` "$@"
`)
	writeExecutable(t, filepath.Join(dir, "find"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(dir, "gofmt"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(dir, "go"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(dir, "mktemp"), `#!/bin/sh
template="${1:-${TMPDIR:-/tmp}/tmp.XXXXXX}"
case "$template" in
*/*) dir="${template%/*}" ;;
*) dir="." ;;
esac
path="$dir/trstctllint.test.$$"
: > "$path"
printf '%s\n' "$path"
`)
	writeExecutable(t, filepath.Join(dir, "rm"), "#!/bin/sh\nexec /bin/rm \"$@\"\n")
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write %s: %v", path, err)
	}
}

func withEnvOverrides(env []string, overrides ...string) []string {
	out := append([]string{}, env...)
	for _, override := range overrides {
		key := override
		if i := strings.IndexByte(key, '='); i >= 0 {
			key = key[:i]
		}
		replaced := false
		for i, kv := range out {
			if strings.HasPrefix(kv, key+"=") {
				out[i] = override
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, override)
		}
	}
	return out
}
