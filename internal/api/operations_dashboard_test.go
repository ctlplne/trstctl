// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"
	"time"
)

// A246: each dashboard state follows from the numbers behind it.
func TestOperationsDashboardStatesFollowTheirNumbersA246(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339) }
	for name, tc := range map[string]struct {
		dr   DRPosture
		want string
	}{
		"not configured":      {DRPosture{}, dashUnknown},
		"unreadable":          {DRPosture{BackupConfigured: true}, dashCritical},
		"did not verify":      {DRPosture{BackupConfigured: true, LastVerifiedAt: at(0), LastBackupAt: at(time.Hour)}, dashCritical},
		"taken an hour ago":   {DRPosture{BackupConfigured: true, Verified: true, LastVerifiedAt: at(0), LastBackupAt: at(time.Hour)}, dashOK},
		"no time recorded":    {DRPosture{BackupConfigured: true, Verified: true, LastVerifiedAt: at(0)}, dashWarning},
		"an optional failure": {DRPosture{BackupConfigured: true, Verified: true, LastVerifiedAt: at(0), LastBackupAt: at(time.Hour), Failures: []DRArtifactFailure{{Name: "logs"}}}, dashWarning},
		// Verification re-hashes on every read, so a just-verified old backup
		// is still old.
		"two days old": {DRPosture{BackupConfigured: true, Verified: true, LastVerifiedAt: at(0), LastBackupAt: at(48 * time.Hour)}, dashWarning},
		"a week old":   {DRPosture{BackupConfigured: true, Verified: true, LastVerifiedAt: at(0), LastBackupAt: at(7 * 24 * time.Hour)}, dashCritical},
	} {
		if got := classifyBackup(tc.dr, now); got.State != tc.want {
			t.Errorf("backup %s: %q, want %q", name, got.State, tc.want)
		}
	}
	if got := classifyRestore(DRPosture{}); got.State != dashWarning {
		t.Errorf("never drilled reads %q", got.State)
	}
	if got := classifyRestore(DRPosture{LastDrill: &DRDrill{Outcome: "failed"}}); got.State != dashCritical {
		t.Errorf("a failed drill reads %q", got.State)
	}
	oldest := func(ago time.Duration) *time.Time { t := now.Add(-ago); return &t }
	for name, tc := range map[string]struct {
		pending, stranded, failed int
		oldest                    *time.Time
		want                      string
	}{
		"empty":           {0, 0, 0, nil, dashOK},
		"fresh":           {3, 0, 0, oldest(time.Minute), dashOK},
		"waiting":         {3, 0, 0, oldest(20 * time.Minute), dashWarning},
		"stuck":           {3, 0, 0, oldest(2 * time.Hour), dashCritical},
		"a lease ran out": {0, 1, 0, nil, dashCritical},
		"failed for good": {0, 0, 2, nil, dashWarning},
	} {
		got := classifyQueues(tc.pending, 0, tc.stranded, tc.failed, tc.oldest, now)
		if got.State != tc.want {
			t.Errorf("queues %s: %q, want %q", name, got.State, tc.want)
		}
	}
	if got := classifyFreshness(OperationsHealth{EventHead: 5000, ProjectionApplied: 3000}); got.State != dashWarning || got.LagEvents != 2000 {
		t.Errorf("a lagging read model: %+v", got)
	}
	if got := classifyFreshness(OperationsHealth{EventHead: 10, ProjectionApplied: 10, ProjectionFailed: 11}); got.State != dashCritical {
		t.Errorf("a stopped read model: %+v", got)
	}
}
