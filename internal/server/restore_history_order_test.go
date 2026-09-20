// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"os"
	"strings"
	"testing"
)

func TestRestoreResumesExactHistoryBeforeSchedulerSanitation(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile("backup.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func restoreEventLog(")
	end := strings.Index(body[start:], "// RunFullRestore")
	if start < 0 || end < 0 {
		t.Fatal("restoreEventLog source boundaries changed")
	}
	body = body[start : start+end]
	open := strings.Index(body, "openHistoryAwareEventLog(")
	floor := strings.Index(body, "EnforceLegacySchedulerWriteFloor()")
	restore := strings.Index(body, "backup.RestoreLogWithKey(")
	pending := strings.Index(body, "RequireNoPendingBackupRestore(")
	sanitize := strings.Index(body, "ensureLegacySchedulerHistorySanitized(")
	if open < 0 || floor < 0 || restore < 0 || pending < 0 || sanitize < 0 {
		t.Fatalf("restore history phases missing: open=%d floor=%d restore=%d pending=%d sanitize=%d", open, floor, restore, pending, sanitize)
	}
	if strings.Contains(body[:restore], "openSanitizedHistoryAwareEventLog(") {
		t.Fatal("restore sanitizes an artifact-bound partial prefix before exact resume")
	}
	if open >= floor || floor >= restore || restore >= pending || pending >= sanitize {
		t.Fatalf("restore order = open:%d floor:%d exact:%d pending:%d sanitize:%d", open, floor, restore, pending, sanitize)
	}
}

func TestNormalHistoryConstructorRejectsPendingRestoreBeforeSanitation(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile("history_rewrite.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func openSanitizedHistoryAwareEventLog(")
	end := strings.Index(body[start:], "// historyRewriteOrchestratorOptions")
	if start < 0 || end < 0 {
		t.Fatal("normal history constructor source boundaries changed")
	}
	body = body[start : start+end]
	pending := strings.Index(body, "RequireNoPendingBackupRestore(")
	sanitize := strings.Index(body, "ensureLegacySchedulerHistorySanitized(")
	if pending < 0 || sanitize < 0 || pending >= sanitize {
		t.Fatalf("normal constructor order = pending:%d sanitation:%d", pending, sanitize)
	}
}
