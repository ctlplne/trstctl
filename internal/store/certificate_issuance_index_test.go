// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"slices"
	"testing"
)

func TestCertificateReceiptIndexUsesActualRunnerDirective(t *testing.T) {
	const name = "0229_certificate_issuance_index_no_transaction.sql"
	body, err := migrationFS.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if !migrationNoTransaction(body) {
		t.Fatal("actual runner would create receipt index inside a transaction")
	}
	names, err := migrationNames()
	if err != nil || !slices.Contains(names, name) {
		t.Fatalf("receipt index absent from runner inventory: %v", err)
	}
	indexes := createIndexConcurrentlyNames.FindAllStringSubmatch(stripSQLLineComments(string(body)), -1)
	if len(indexes) != 1 || indexes[0][1] != "certificate_receipt_issuance_origin" {
		t.Fatalf("runner cannot validate the receipt index: %v", indexes)
	}
}
