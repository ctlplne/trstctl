// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/managedkeystate"
	"trstctl.com/trstctl/internal/reconcile/canon"
	corestore "trstctl.com/trstctl/internal/store"
)

// A168-L4: a record only one plane holds whose operation stamp — after the
// AWS marker in its native id, or in a GCP or Azure key name — matches one of
// the tenant's generate or rotate operations that never completed is noted
// with that operation; a record both planes hold, a stamp no unfinished
// operation made, a missing lookup or a failed one leave no note.
func TestExplainPresenceNamesTheUnfinishedOperationA168L4(t *testing.T) {
	generate := managedkeystate.OperationStamp("generate", "managedkey:op-1", "", "ECDSA-P256")
	rotate := managedkeystate.OperationFingerprint("rotate", "managedkey:op-2", "key-old", "RSA-3072")
	azure := managedkeystate.OperationFingerprint("generate", "managedkey:op-3", "", "ECDSA-P384")
	record := func(id, native string) canon.CanonicalRecord {
		return canon.CanonicalRecord{RecordKey: canon.RecordKey{StableID: id}, Provenance: canon.Provenance{NativeID: native}}
	}
	kms := canon.Set{Records: []canon.CanonicalRecord{
		record("aws-new", "arn:aws:kms:us-east-1:111122223333:key/k1"+awsOperationMarker+generate),
		record("gcp-rotated", "projects/p/locations/l/keyRings/r/cryptoKeys/trstctl-r-"+rotate+"/cryptoKeyVersions/1"),
		record("azure-new", "https://lab.vault.azure.net/keys/trstctl-generate-"+azure+"/v1"),
		record("held-by-both", "arn:aws:kms:us-east-1:111122223333:key/k2"+awsOperationMarker+generate),
		record("stranger", "arn:aws:kms:us-east-1:111122223333:key/k9"+awsOperationMarker+strings.Repeat("0", 64)),
	}}
	inventory := canon.Set{Records: []canon.CanonicalRecord{record("held-by-both", "managed-key:aws:k2")}}
	ops := func(context.Context, string) ([]corestore.ManagedKeyOperation, error) {
		return []corestore.ManagedKeyOperation{
			{OperationID: "managedkey:op-1", Action: "generate", Algorithm: "ECDSA-P256", Status: "queued"},
			{OperationID: "managedkey:op-2", Action: "rotate", KeyID: "key-old", Algorithm: "RSA-3072", Status: "failed"},
			{OperationID: "managedkey:op-3", Action: "generate", Algorithm: "ECDSA-P384", Status: "queued"},
		}, nil
	}
	notes := explainPresence(context.Background(), ops, "tenant-a", kms, inventory)
	if !strings.Contains(notes["aws-new"], "managedkey:op-1 (generate, queued)") ||
		!strings.Contains(notes["gcp-rotated"], "managedkey:op-2 (rotate, failed)") ||
		!strings.Contains(notes["azure-new"], "managedkey:op-3 (generate, queued)") || len(notes) != 3 {
		t.Fatalf("notes = %v", notes)
	}
	if !strings.Contains(notes["aws-new"], "/api/v1/managed-keys/operations/managedkey:op-1") {
		t.Fatalf("the note does not say where to look: %q", notes["aws-new"])
	}
	// The inventory side alone holding a record is explained the same way.
	if got := explainPresence(context.Background(), ops, "tenant-a", inventory, kms); len(got) != 3 {
		t.Fatalf("explaining with the planes swapped = %v", got)
	}
	if got := explainPresence(context.Background(), nil, "tenant-a", kms, inventory); got != nil {
		t.Fatalf("no lookup = %v", got)
	}
	failing := func(context.Context, string) ([]corestore.ManagedKeyOperation, error) {
		return nil, errors.New("store down")
	}
	if got := explainPresence(context.Background(), failing, "tenant-a", kms, inventory); got != nil {
		t.Fatalf("a failed lookup = %v", got)
	}
	if fp := operationFingerprint(record("short", "arn:x"+awsOperationMarker+"abc")); fp != "" {
		t.Fatalf("a short stamp read as %q", fp)
	}
}
