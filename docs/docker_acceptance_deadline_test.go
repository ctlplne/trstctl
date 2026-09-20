// SPDX-License-Identifier: BUSL-1.1

package docs_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDockerBackedAcceptanceHarnessesHaveCommandDeadlines prevents a wedged
// local engine from consuming an entire package timeout and hiding later test
// results. These three acceptance harnesses all run Docker directly.
func TestDockerBackedAcceptanceHarnessesHaveCommandDeadlines(t *testing.T) {
	root := filepath.Clean("..")
	for _, rel := range []string{
		"internal/kms/pkcs11/softhsm_container_test.go",
		"internal/kms/tpm/swtpm_container_test.go",
		"internal/server/pam_served_test.go",
	} {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- test reads a fixed repository path (CWE-22)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if !strings.Contains(text, "exec.CommandContext(") || !strings.Contains(text, "context.WithTimeout(") {
			t.Errorf("%s must bound Docker commands with a context deadline", rel)
		}
		if strings.Contains(text, `exec.Command("docker"`) {
			t.Errorf("%s still contains an unbounded direct Docker command", rel)
		}
	}
}
