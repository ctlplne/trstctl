// SPDX-License-Identifier: BUSL-1.1

package drift_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/drift"
	"trstctl.com/trstctl/internal/safefile"
)

func TestCR415WatchedFileReadIsBounded(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "oversized-certificate-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Truncate(2 << 20); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = drift.Detect([]drift.Watched{{Path: path, Class: "certificate", Fingerprint: drift.Fingerprint([]byte("declared"))}})
	if !errors.Is(err, safefile.ErrFileLimit) {
		t.Fatalf("watched oversized file: %v, want bounded read refusal", err)
	}
}

func TestCR415AgentDriftStillFollowsOperatorConfiguredSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "actual", "leaf.pem")
	if err := os.Mkdir(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("drifted"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "live.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	findings, err := drift.Detect([]drift.Watched{{Path: link, Class: "certificate", Fingerprint: drift.Fingerprint([]byte("declared"))}})
	if err != nil || len(findings) != 1 || findings[0].Type != drift.Replaced {
		t.Fatalf("agent symlink = %+v, %v; want replaced finding", findings, err)
	}
}

func TestCR415AgentRelocationStillFindsRegularFileThroughSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "actual", "leaf.pem")
	if err := os.Mkdir(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("declared")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "relocated.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(parent, "missing.pem")
	findings, err := drift.Detect([]drift.Watched{{Path: missing, Class: "certificate", Fingerprint: drift.Fingerprint(content)}})
	if err != nil || len(findings) != 1 || findings[0].Type != drift.Relocated || findings[0].FoundAt != link {
		t.Fatalf("relocation symlink = %+v, %v; want relocated at %s", findings, err, link)
	}
}
