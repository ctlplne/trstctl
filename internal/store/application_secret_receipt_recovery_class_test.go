// SPDX-License-Identifier: BUSL-1.1

package store

import "testing"

// The receipt is committed beside independent sealed primary state. It must
// survive both full read-model rebuild and snapshot restore; treating it as a
// projection would erase the only unambiguous delete tombstone before approval
// events are replayed.
func TestApplicationSecretMutationReceiptsUseIndependentPostgresRecovery(t *testing.T) {
	for _, table := range []string{
		"application_secret_mutation_fences",
		"application_secret_tenant_epochs",
		"application_secret_mutation_receipts",
	} {
		if containsRecoveryTable(ReadModelTables, table) {
			t.Errorf("%s is in ReadModelTables; rebuild must preserve sealed-mutation recovery state", table)
		}
		if containsRecoveryTable(snapshotTables, table) {
			t.Errorf("%s is in snapshotTables; read-model restore must not overwrite independent recovery state", table)
		}
	}
}
