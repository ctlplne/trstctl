package docs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMakeVulnDoesNotDependOnToolBinInPath is the TEST-003 regression: the local
// vulnerability gate may install govulncheck into GOPATH/bin or GOBIN, but it must
// invoke that resolved path directly instead of assuming the tool bin directory is
// already on PATH. The test dry-runs make, so it never downloads or scans.
func TestMakeVulnDoesNotDependOnToolBinInPath(t *testing.T) {
	gopath := goEnv(t, "GOPATH")
	gobin := goEnv(t, "GOBIN")
	toolBin := gobin
	if toolBin == "" {
		toolBin = filepath.Join(gopath, "bin")
	}
	toolBin = filepath.Clean(toolBin)

	cmd := exec.Command("make", "-n", "-f", "../Makefile", "vuln")
	cmd.Env = withPathWithout(os.Environ(), toolBin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n vuln failed: %v\n%s", err, out)
	}
	plan := string(out)
	want := filepath.Join(toolBin, "govulncheck") + " ./..."
	if !strings.Contains(plan, want) {
		t.Fatalf("make vuln dry-run did not invoke resolved govulncheck path %q:\n%s", want, plan)
	}
	if strings.Contains(plan, "\ngovulncheck ./...") || strings.Contains(plan, "\tgovulncheck ./...") {
		t.Fatalf("make vuln still contains a bare govulncheck invocation:\n%s", plan)
	}
}

func goEnv(t *testing.T, key string) string {
	t.Helper()
	out, err := exec.Command("go", "env", key).Output()
	if err != nil {
		t.Fatalf("go env %s: %v", key, err)
	}
	return strings.TrimSpace(string(out))
}

func withPathWithout(env []string, remove string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, "PATH=") {
			out = append(out, kv)
			continue
		}
		parts := strings.Split(strings.TrimPrefix(kv, "PATH="), string(os.PathListSeparator))
		kept := parts[:0]
		for _, part := range parts {
			if filepath.Clean(part) != remove {
				kept = append(kept, part)
			}
		}
		out = append(out, "PATH="+strings.Join(kept, string(os.PathListSeparator)))
	}
	return out
}
