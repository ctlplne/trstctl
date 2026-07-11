// SPDX-License-Identifier: MPL-2.0

package store

import "testing"

func TestDeploymentTargetsAreExcludedFromEventRebuildAndSnapshots(t *testing.T) {
	for _, table := range []string{"deployment_target_revisions", "deployment_targets"} {
		if containsRecoveryTable(ReadModelTables, table) {
			t.Errorf("%s is in ReadModelTables; migration 0072 legacy rows require PostgreSQL recovery", table)
		}
		if containsRecoveryTable(snapshotTables, table) {
			t.Errorf("%s is in snapshotTables; independent PostgreSQL state must not be restored by snapshots", table)
		}
	}
}

func containsRecoveryTable(tables []string, want string) bool {
	for _, table := range tables {
		if table == want {
			return true
		}
	}
	return false
}
