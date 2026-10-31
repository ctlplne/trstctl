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
	// The configured wrapper must select raw history and retain the exact
	// authenticated restore authority. The normal constructor below still owns
	// the pending-restore-before-sanitation guard for every ordinary open.
	open := strings.Index(body, "openConfiguredEventSource(ctx, cfg, st, auditKey, false, []string{path}, events.WithBackupRestoreAuthorizer(restoreAuthorizer))")
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
	wrapper, err := os.ReadFile("event_protection_source.go")
	if err != nil {
		t.Fatal(err)
	}
	constructor := string(wrapper)
	options := strings.Index(constructor, "options := append(protection.openOptions(), extra...)")
	branch := strings.Index(constructor, "if sanitized {")
	normal := strings.Index(constructor, "openSanitizedHistoryAwareEventLogWithRecovery(")
	raw := strings.Index(constructor, "} else {\n\t\tlog, err = openHistoryAwareEventLog(")
	if options < 0 || branch <= options || normal <= branch || raw <= normal ||
		strings.Count(constructor, "openSanitizedHistoryAwareEventLogWithRecovery(") != 1 ||
		strings.Count(constructor, "openHistoryAwareEventLog(") != 1 {
		t.Fatal("configured source must attach protection before opening, and false must select only unsanitized history")
	}
	verify := strings.Index(constructor, "protection.reader.VerifyCurrentCustody(ctx)")
	if verify <= normal || verify >= raw || strings.Count(constructor, "VerifyCurrentCustody(") != 1 {
		t.Fatal("current custody verification must follow normal sanitized open; raw restore must resume exact history first")
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
	recovery := strings.Index(body, "recoverSource(ctx, log)")
	if pending < 0 || recovery < 0 || sanitize < 0 || pending >= recovery || recovery >= sanitize {
		t.Fatalf("normal constructor order = pending:%d recovery:%d sanitation:%d", pending, recovery, sanitize)
	}
}
