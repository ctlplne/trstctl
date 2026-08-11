// SPDX-License-Identifier: MPL-2.0

package store

import (
	"os"
	"strings"
	"testing"
)

func TestPrivacyAuthorityMigrationIsVersionedAndFailClosed(t *testing.T) {
	raw, err := os.ReadFile("migrations/0158_privacy_authority_stamps.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"application_secret_mutation_fences",
		"approved_target_event_fences",
		"application_secret_mutation_receipts",
		"code_signing_operations",
		"privacy_rewrite_version",
		"privacy_subject_ref",
		"privacy_erasure_operation_id",
		"privacy_erasure_event_id",
		"privacy_disposition",
		"semantic_version",
		"approval_authority_version",
		"approval_resource_kind",
		"approval_resource_id",
		"approval_action",
		"approval_target_version",
		"NOT VALID",
		"VALIDATE CONSTRAINT",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("0158 migration omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"UPDATE code_signing_operations SET approval_authority_version = 1",
		"UPDATE code_signing_operations\nSET approval_resource",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("0158 migration fabricates historical code-signing authority via %q", forbidden)
		}
	}
}
