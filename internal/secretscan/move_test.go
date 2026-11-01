// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A directory scan's fingerprint names the path gitleaks reported; once the
// file is relative, so is the fingerprint, so a clone in a new temporary
// directory keeps the finding's identity (P6).
func TestRelativizeFindingsKeepsFingerprintsIndependentOfTheCheckoutP6(t *testing.T) {
	findings := []Finding{
		{RuleID: "slack-bot-token", File: "/tmp/clone-1/app.env", Line: 2, Fingerprint: "/tmp/clone-1/app.env:slack-bot-token:2"},
		{RuleID: "slack-bot-token", File: "app.env", Line: 2, Fingerprint: "0123abc:app.env:slack-bot-token:2"},
	}
	relativizeFindings(findings, "/tmp/clone-1")
	if findings[0].File != "app.env" || findings[0].Fingerprint != "app.env:slack-bot-token:2" {
		t.Fatalf("directory finding = %+v", findings[0])
	}
	if findings[1].Fingerprint != "0123abc:app.env:slack-bot-token:2" {
		t.Fatalf("history finding fingerprint changed: %+v", findings[1])
	}
}

func p6Gitleaks(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{os.Getenv("TRSTCTL_GITLEAKS_BIN"), filepath.Join("..", "..", "tools", "bin", "gitleaks")} {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() { // #nosec G703 -- locates the pinned gitleaks binary in known tool dirs (CWE-22)
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	t.Skip("needs the pinned gitleaks (tools/gitleaks/install.sh or TRSTCTL_GITLEAKS_BIN)")
	return ""
}

func p6Repo(t *testing.T, files map[string]string) (string, func(...string) string) {
	t.Helper()
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	git("config", "user.email", "p6@example.test")
	git("config", "user.name", "p6")
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return repo, git
}

var p6Token = strings.Join([]string{"xoxb", "123456789012", "123456789012", "abcdefghijklmnopqrstuvwx"}, "-")

// The CLI's locate re-finds exactly the value a redacted finding names, and
// every history commit that still holds it; a line that holds no value is
// refused rather than guessed.
func TestLocateSecretForMoveFindsTheValueAndItsHistoryP6(t *testing.T) {
	bin := p6Gitleaks(t)
	repo, git := p6Repo(t, map[string]string{"app.env": "APP=payments\nSLACK_TOKEN=" + p6Token + "\n"})
	git("add", "app.env")
	git("commit", "-q", "-m", "config")
	first := git("rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("unrelated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "notes.txt")
	git("commit", "-q", "-m", "notes")

	runner := NewGitleaksRunner(bin)
	runner.AllowedRoots = []string{repo}
	value, residue, err := runner.LocateSecretForMove(t.Context(), repo, SecretLocation{RuleID: "slack-bot-token", File: "app.env", Line: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, []byte(p6Token)) {
		t.Fatalf("located a different value (%d bytes)", len(value))
	}
	if len(residue) != 1 || residue[0].Commit != first || residue[0].File != "app.env" || residue[0].Line != 2 || residue[0].RuleID != "slack-bot-token" {
		t.Fatalf("residue = %+v, want the commit that added the token", residue)
	}
	if _, _, err := runner.LocateSecretForMove(t.Context(), repo, SecretLocation{RuleID: "slack-bot-token", File: "app.env", Line: 1}); !errors.Is(err, ErrSecretNotLocated) {
		t.Fatalf("a line with no value: %v", err)
	}
	if _, _, err := runner.LocateSecretForMove(t.Context(), t.TempDir(), SecretLocation{RuleID: "slack-bot-token", File: "app.env", Line: 2}); !errors.Is(err, ErrInvalidScanTarget) {
		t.Fatalf("a checkout outside the allowed roots: %v", err)
	}
}

// A clone trstctl made in its own temporary directory is scanned with that
// directory as the only root, even when the configured roots do not cover it.
func TestScanCloneScansOnlyTheCloneP6(t *testing.T) {
	bin := p6Gitleaks(t)
	clone, _ := p6Repo(t, map[string]string{"app.env": "SLACK_TOKEN=" + p6Token + "\n"})
	runner := NewGitleaksRunner(bin)
	runner.AllowedRoots = []string{t.TempDir()} // the operator's roots do not cover the clone
	if _, err := runner.Scan(t.Context(), clone); !errors.Is(err, ErrInvalidScanTarget) {
		t.Fatalf("a plain scan outside the roots: %v", err)
	}
	report, err := runner.ScanClone(t.Context(), clone)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].File != "app.env" || report.Findings[0].Fingerprint != "app.env:slack-bot-token:1" {
		t.Fatalf("clone scan = %+v", report.Findings)
	}
}
