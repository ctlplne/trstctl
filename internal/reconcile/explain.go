// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/managedkeystate"
	"trstctl.com/trstctl/internal/reconcile/canon"
	corestore "trstctl.com/trstctl/internal/store"
)

// A168-L4: a key trstctl's own managed-key operation created at a cloud KMS
// provider, whose completion trstctl never recorded, is held only by the
// provider's observation. That presence divergence is honest, but alone it
// reads like a key created behind trstctl's back. The emitter names the
// operation on the witness entry.
//
// Every provider adapter stamps the key an operation creates with one digest
// (managedkeystate.OperationStamp): AWS KMS in the trstctl-managed-key-
// operation tag, which the source carries in the record's native id after
// awsOperationMarker; GCP Cloud KMS and Azure Key Vault in the key's name.
// The explainer computes the same fingerprint for the tenant's generate and
// rotate operations that never completed and matches.

// awsOperationMarker introduces an AWS key's operation stamp in its asserted
// native id.
const awsOperationMarker = " trstctl-operation:"

// maxUnfinishedOperations bounds the operations one explanation reads.
const maxUnfinishedOperations = 500

var operationNamePattern = regexp.MustCompile(`trstctl-(?:g|r|generate|rotate)-([0-9a-f]{48})`)

// unfinishedOperations lists a tenant's generate and rotate operations that
// never completed.
type unfinishedOperations func(ctx context.Context, tenantID string) ([]corestore.ManagedKeyOperation, error)

func storeUnfinishedOperations(store *corestore.Store) unfinishedOperations {
	if store == nil {
		return nil
	}
	return func(ctx context.Context, tenantID string) ([]corestore.ManagedKeyOperation, error) {
		return store.ListUnfinishedManagedKeyOperations(ctx, tenantID, maxUnfinishedOperations)
	}
}

// operationFingerprint is the operation stamp's fingerprint a cloud record
// carries: after awsOperationMarker in an AWS key's native id, or in a GCP or
// Azure key name.
func operationFingerprint(rec canon.CanonicalRecord) string {
	native := rec.Provenance.NativeID
	if i := strings.Index(native, awsOperationMarker); i >= 0 {
		value := strings.TrimSpace(native[i+len(awsOperationMarker):])
		if len(value) < managedkeystate.OperationFingerprintLen || !lowerHex(value[:managedkeystate.OperationFingerprintLen]) {
			return ""
		}
		return value[:managedkeystate.OperationFingerprintLen]
	}
	if m := operationNamePattern.FindStringSubmatch(native); m != nil {
		return m[1]
	}
	return ""
}

func lowerHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// explainPresence names, by record stable id, the unfinished trstctl
// operation behind each record only one plane holds. Nothing is explained
// without a store, without a stamp, or without a match; a lookup that fails
// leaves the witness unexplained rather than failing it.
func explainPresence(ctx context.Context, operations unfinishedOperations, tenantID string, left, right canon.Set) map[string]string {
	if operations == nil {
		return nil
	}
	held := func(set canon.Set) map[string]canon.CanonicalRecord {
		out := make(map[string]canon.CanonicalRecord, len(set.Records))
		for _, rec := range set.Records {
			out[rec.RecordKey.StableID] = rec
		}
		return out
	}
	l, r := held(left), held(right)
	wanted := map[string]string{} // fingerprint -> record stable id
	for _, side := range [][2]map[string]canon.CanonicalRecord{{l, r}, {r, l}} {
		for id, rec := range side[0] {
			if _, both := side[1][id]; both {
				continue
			}
			if fp := operationFingerprint(rec); fp != "" {
				wanted[fp] = id
			}
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	ops, err := operations(ctx, tenantID)
	if err != nil {
		return nil
	}
	notes := map[string]string{}
	for _, op := range ops {
		source := ""
		if op.Action == "rotate" {
			source = op.KeyID
		}
		id, ok := wanted[managedkeystate.OperationFingerprint(op.Action, op.OperationID, source, op.Algorithm)]
		if !ok {
			continue
		}
		notes[id] = "created by trstctl managed-key operation " + op.OperationID + " (" + op.Action + ", " + op.Status +
			"), whose completion trstctl has not recorded; see GET /api/v1/managed-keys/operations/" + op.OperationID
	}
	return notes
}
