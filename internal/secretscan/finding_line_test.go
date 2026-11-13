// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"os"
	"path/filepath"
	"testing"
)

// A172-L1: a finding's line, and the lines after it a multi-line credential
// may run on to, are read from the scanned tree and nowhere else.
func TestReadFindingLineReadsTheLineAndWhatFollowsA172L1(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ci"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "one\nGITLAB_TOKEN = \"x\"\nthree\nfour"
	if err := os.WriteFile(filepath.Join(root, "ci", "deploy.env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	line, err := ReadFindingLine(root, "ci/deploy.env", 2, 1)
	if err != nil || string(line.Text) != "GITLAB_TOKEN = \"x\"\nthree" || line.LineEnd != len("GITLAB_TOKEN = \"x\"") {
		t.Fatalf("line = %q end %d err=%v", line.Text, line.LineEnd, err)
	}
	if line, err := ReadFindingLine(root, filepath.Join(root, "ci", "deploy.env"), 4, 10); err != nil || string(line.Text) != "four" || line.LineEnd != 4 {
		t.Fatalf("last line by absolute path = %q end %d err=%v", line.Text, line.LineEnd, err)
	}
	if line, err := ReadFindingLine(root, "ci/deploy.env", 1, 0); err != nil || string(line.Text) != "one" || line.LineEnd != 3 {
		t.Fatalf("first line alone = %q end %d err=%v", line.Text, line.LineEnd, err)
	}
	for name, read := range map[string]func() error{
		"past the end":     func() error { _, err := ReadFindingLine(root, "ci/deploy.env", 9, 0); return err },
		"outside the tree": func() error { _, err := ReadFindingLine(root, "../deploy.env", 1, 0); return err },
		"no such file":     func() error { _, err := ReadFindingLine(root, "ci/missing.env", 1, 0); return err },
		"no line":          func() error { _, err := ReadFindingLine(root, "ci/deploy.env", 0, 0); return err },
		"no tree":          func() error { _, err := ReadFindingLine(" ", "ci/deploy.env", 1, 0); return err },
	} {
		if err := read(); err == nil {
			t.Fatalf("%s: read a line", name)
		}
	}
}

// Gitleaks' columns survive parsing; its secret never does.
func TestParseGitleaksKeepsTheMatchColumnsA172L1(t *testing.T) {
	findings, err := ParseGitleaks([]byte(`[{"RuleID":"gitlab-pat","File":"ci/deploy.env","StartLine":2,"EndLine":2,"StartColumn":18,"EndColumn":43,
		"Fingerprint":"c0ffee:ci/deploy.env:gitlab-pat:2","Secret":"REDACTED","Match":"REDACTED"},
		{"RuleID":"private-key","File":"k.pem","StartLine":4,"EndLine":9,"StartColumn":1,"EndColumn":30,"Fingerprint":"k"}]`))
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %+v err=%v", findings, err)
	}
	if f := findings[0]; f.Line != 2 || f.EndLine != 2 || f.Column != 18 || f.EndColumn != 43 || f.RuleID != "gitlab-pat" {
		t.Fatalf("single-line finding = %+v", f)
	}
	if f := findings[1]; f.Line != 4 || f.EndLine != 9 || f.Column != 1 || f.EndColumn != 30 {
		t.Fatalf("multi-line finding = %+v", f)
	}
}
