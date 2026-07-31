// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

func TestTenantOffboardingPrivacyBoundaryDocumented(t *testing.T) {
	limitations := read(t, "limitations.md")
	for _, want := range []string{
		"Tenant offboarding boundary",
		"PostgreSQL read state",
		"`tenant.offboarded`",
		"append-only event log",
		"audit archive",
		"`TRSTCTL_AUDIT_RETENTION`",
		"`TRSTCTL_AUDIT_ARCHIVE_DIR`",
		"Privacy Retention",
		"`POST /api/v1/privacy/archive-erasure-attestations`",
		"`GET /api/v1/privacy/archive-erasure-attestations`",
	} {
		if !strings.Contains(limitations, want) {
			t.Errorf("limitations.md must document tenant offboarding/privacy boundary; missing %q", want)
		}
	}

	configuration := read(t, "configuration.md")
	for _, want := range []string{"TRSTCTL_AUDIT_RETENTION", "TRSTCTL_AUDIT_ARCHIVE_DIR", "TRSTCTL_PRIVACY_RETENTION_ENABLED", "privacy/archive-erasure-attestations"} {
		if !strings.Contains(configuration, want) {
			t.Errorf("configuration.md missing retention setting %q", want)
		}
	}

	compliance := read(t, "compliance.md")
	for _, want := range []string{"Audit retention and archive lifecycle", "archive", "served audit view", "WORM", "archive-erasure attestations"} {
		if !strings.Contains(compliance, want) {
			t.Errorf("compliance.md missing audit retention anchor %q", want)
		}
	}

	offboard := read(t, "../internal/store/offboard.go")
	for _, want := range []string{"Object-store audit-archive residue", "docs/limitations.md"} {
		if !strings.Contains(offboard, want) {
			t.Errorf("offboard.go must keep the documented privacy boundary pointer; missing %q", want)
		}
	}
}
