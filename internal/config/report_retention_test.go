// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
	"time"
)

// A206: the report retention is off unless set. A window needs a report
// archive to remove from and is at least an hour, so a typo cannot remove
// reports minutes after they are written; TRSTCTL_AUDIT_REPORT_RETENTION
// reaches it.
func TestAuditReportRetentionIsOptInBoundedAndNeedsAnArchive(t *testing.T) {
	cfg := Default()
	if d, err := cfg.Audit.ReportRetentionDuration(); err != nil || d != 0 {
		t.Fatalf("default report retention = %v %v, want off", d, err)
	}
	cfg.Audit.ReportRetention = "2160h"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "audit.report_retention needs a report archive") {
		t.Fatalf("a retention with no archive = %v", err)
	}
	cfg.Audit.ArchiveDir = "/var/lib/trstctl/archive"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a retention with an archive directory = %v", err)
	}
	if d, err := cfg.Audit.ReportRetentionDuration(); err != nil || d != 90*24*time.Hour {
		t.Fatalf("parsed retention = %v %v", d, err)
	}
	cfg.Audit.ArchiveDir = ""
	cfg.Audit.ArchiveObjectStore = true
	cfg.ObjectStore = validObjectStore()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a retention with the archive object store = %v", err)
	}
	for _, bad := range []string{"ninety days", "-1h", "30m"} {
		cfg.Audit.ReportRetention = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "audit.report_retention") {
			t.Fatalf("retention %q = %v", bad, err)
		}
	}
	env := map[string]string{"TRSTCTL_AUDIT_REPORT_RETENTION": "720h"}
	var overlaid Config
	overlaid.applyEnv(func(k string) string { return env[k] })
	if overlaid.Audit.ReportRetention != "720h" {
		t.Fatalf("TRSTCTL_AUDIT_REPORT_RETENTION reached %q", overlaid.Audit.ReportRetention)
	}
}
