// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"slices"
	"testing"
)

func TestIdentityIssuanceConcurrentIndexUsesActualRunnerDirective(t *testing.T) {
	const name = "0206_identity_issuance_result_index_no_transaction.sql"
	body, err := migrationFS.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if !migrationNoTransaction(body) {
		t.Fatal("the real migration runner would dispatch CREATE INDEX CONCURRENTLY inside a transaction")
	}
	// Exercise the runner's embedded inventory and actual index-name parser.
	names, err := migrationNames()
	if err != nil || !slices.Contains(names, name) {
		t.Fatalf("concurrent issuance index missing from runner inventory: %v", err)
	}
	indexes := createIndexConcurrentlyNames.FindAllStringSubmatch(stripSQLLineComments(string(body)), -1)
	if len(indexes) != 1 || indexes[0][1] != "identity_transitions_issuance_result_idx" {
		t.Fatalf("runner cannot verify the actual concurrent index: %v", indexes)
	}
}
