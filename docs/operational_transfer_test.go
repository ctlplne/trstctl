package docs

import (
	"os"
	"strings"
	"testing"
)

func TestOperationalTransferDocsArePresent(t *testing.T) {
	architecture := readTransferDoc(t, "design/architecture-invariants.md")
	for _, want := range []string{
		"Architecture invariants",
		"go/analysis",
		"multi-tenant storage",
		"event-sourced state",
		"single crypto boundary",
		"separate signing service",
		"idempotent mutations",
		"outbox external calls",
		"bulkheads and backpressure",
		"memory-safe key material",
		"How to extend the guard",
	} {
		if !strings.Contains(architecture, want) {
			t.Errorf("architecture handoff doc should contain %q", want)
		}
	}

	dr := readTransferDoc(t, "runbooks/disaster-recovery-drill.md")
	for _, want := range []string{
		"trstctl --full-backup-dir",
		"trstctl --full-restore-dir",
		"scripts/dr/full-backup.sh",
		"scripts/dr/full-restore.sh",
		"manifest.json",
		"postgres-state.jsonl",
		"event log",
		"smoke test",
	} {
		if !strings.Contains(dr, want) {
			t.Errorf("DR drill runbook should contain %q", want)
		}
	}

	nav := readTransferDoc(t, "../mkdocs.yml")
	for _, want := range []string{
		"Architecture invariants: design/architecture-invariants.md",
		"Disaster recovery drill: runbooks/disaster-recovery-drill.md",
		"Fleet rollout: runbooks/fleet-rollout.md",
		"Fleet rollback: runbooks/fleet-rollback.md",
		"Signer recovery: runbooks/signer-recovery.md",
		"Upgrade rollback: runbooks/upgrade-rollback.md",
	} {
		if !strings.Contains(nav, want) {
			t.Errorf("mkdocs nav should include %q", want)
		}
	}
}

func readTransferDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
