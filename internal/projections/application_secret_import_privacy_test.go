// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestBatchImportPrivacyPrunesOnlyAffectedAADNames(t *testing.T) {
	data, err := json.Marshal(projections.ApplicationSecretBatchImport{
		TenantEpoch: "epoch", IdempotencyKeyDigest: "digest",
		RequestBinding: "binding", CommandEvidence: "evidence", Surface: "native",
		Items: []projections.ApplicationSecretBatchImportItem{
			{Name: "users/alice/key", Sealed: []byte("alice-cipher")},
			{Name: "users/bob/key", Sealed: []byte("bob-cipher")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pruned, version, changed, err := events.PseudonymizeEventDataForSubjectVersioned(
		data, "11111111-1111-4111-8111-111111111111", "alice",
		projections.EventApplicationSecretBatchImported, projections.ApplicationSecretBatchImportSchemaVersion)
	if err != nil || !changed || version != projections.ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion {
		t.Fatalf("first prune version=%d changed=%v err=%v", version, changed, err)
	}
	if bytes.Contains(pruned, []byte("alice")) || bytes.Contains(pruned, []byte("alice-cipher")) {
		t.Fatal("first prune retained the erased name or its sealed value")
	}
	var payload projections.ApplicationSecretBatchImportPrivacyPruned
	if err := json.Unmarshal(pruned, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 1 || payload.Items[0].Name != "users/bob/key" ||
		!bytes.Equal(payload.Items[0].Sealed, []byte("bob-cipher")) || payload.PrivacyRemovedCount != 1 {
		t.Fatalf("first prune lost unaffected item: %+v", payload)
	}
	prunedAgain, version, changed, err := events.PseudonymizeEventDataForSubjectVersioned(
		pruned, "11111111-1111-4111-8111-111111111111", "bob",
		projections.EventApplicationSecretBatchImported, version)
	if err != nil || !changed || version != projections.ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion {
		t.Fatalf("second prune version=%d changed=%v err=%v", version, changed, err)
	}
	if err := json.Unmarshal(prunedAgain, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 0 || payload.PrivacyRemovedCount != 2 || bytes.Contains(prunedAgain, []byte("bob-cipher")) {
		t.Fatalf("second prune retained a sealed item: %+v", payload)
	}
}
