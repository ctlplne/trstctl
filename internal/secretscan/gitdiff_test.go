package secretscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareGitDiffTargetUsesStagedBlobNotWorkingTree(t *testing.T) {
	repo := initSecretScanGitRepo(t)
	writeRepoFile(t, repo, "app.env", "API_KEY=staged-value\n")
	gitSecretScan(t, repo, "add", "app.env")
	writeRepoFile(t, repo, "app.env", "API_KEY=unstaged-value\n")

	target, err := PrepareGitDiffTarget(context.Background(), GitDiffConfig{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Cleanup()
	if target.Mode != "staged" || len(target.Files) != 1 || target.Files[0] != "app.env" {
		t.Fatalf("target = mode %q files %v, want staged app.env", target.Mode, target.Files)
	}
	data, err := os.ReadFile(filepath.Join(target.Path, "app.env"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); !strings.Contains(got, "staged-value") || strings.Contains(got, "unstaged-value") {
		t.Fatalf("materialized staged blob = %q", got)
	}
}

func TestPrepareGitDiffTargetUsesHeadSideForCIDiff(t *testing.T) {
	repo := initSecretScanGitRepo(t)
	writeRepoFile(t, repo, "README.md", "base\n")
	gitSecretScan(t, repo, "add", "README.md")
	gitSecretScan(t, repo, "commit", "-m", "base")
	base := strings.TrimSpace(gitSecretScanOutput(t, repo, "rev-parse", "HEAD"))

	writeRepoFile(t, repo, "ci.env", "CI_TOKEN=head-value\n")
	gitSecretScan(t, repo, "add", "ci.env")
	gitSecretScan(t, repo, "commit", "-m", "head")
	head := strings.TrimSpace(gitSecretScanOutput(t, repo, "rev-parse", "HEAD"))

	target, err := PrepareGitDiffTarget(context.Background(), GitDiffConfig{Repo: repo, Base: base, Head: head})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Cleanup()
	if target.Mode != "ci_diff" || len(target.Files) != 1 || target.Files[0] != "ci.env" {
		t.Fatalf("target = mode %q files %v, want ci_diff ci.env", target.Mode, target.Files)
	}
	data, err := os.ReadFile(filepath.Join(target.Path, "ci.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "head-value") {
		t.Fatalf("CI diff blob = %q, want head-side content", data)
	}
}

func initSecretScanGitRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitSecretScan(t, repo, "init")
	gitSecretScan(t, repo, "config", "user.email", "test@example.com")
	gitSecretScan(t, repo, "config", "user.name", "trstctl test")
	return repo
}

func writeRepoFile(t *testing.T, repo, name, body string) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gitSecretScan(t *testing.T, repo string, args ...string) {
	t.Helper()
	_ = gitSecretScanOutput(t, repo, args...)
}

func gitSecretScanOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
