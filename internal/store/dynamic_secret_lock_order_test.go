// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"os"
	"strings"
	"testing"
)

// ---- AN5-LOCKORDER: one lock order for the operations/leases pair -------------
//
// The reproduced defect (AH-24054b59) was a PostgreSQL ABBA lock-order inversion,
// not an idempotency-check race. Two transactions wrote the same pair in opposite
// orders:
//
//	request intent  (ApplyDynamicSecretIssueIntentTx):  operations -> leases
//	worker result   (ApplyDynamicSecretLeaseIssuedTx):  leases -> operations
//
// PostgreSQL's detector aborted one side with SQLSTATE 40P01. When the victim was
// the worker, its post-provider projection rolled back, the lease stayed 'pending',
// the outbox returned the row to pending and re-delivered, the state guard passed
// again -- and the provider minted a SECOND credential that trstctl then discarded.
// A live credential nobody tracks.
//
// The fix is a first-lock discipline: every transaction that writes the pair takes
// lockDynamicSecretOperationTx before touching either table, so both walks serialize
// on one lock and no cycle can form.
//
// This test is a SOURCE-LEVEL guard, deliberately. The behavioural reproduction
// needs a live PostgreSQL and two racing transactions, and it only fired about 1 in
// 60 runs under CPU load -- a regression test that flaky gets deleted as noise
// within a month. What actually keeps the class dead is the invariant "the lock is
// taken first", and that is checkable deterministically, offline, in milliseconds.

// TestDynamicSecretPairWritersTakeTheOperationLockFirst asserts that every
// transaction writing the dynamic_secret_operations / dynamic_secret_leases pair
// takes the shared per-command advisory lock as its first database statement.
//
// It reads the source rather than the database on purpose: the property is about
// STATEMENT ORDER, which is exactly what a source check can see and what a passing
// integration run cannot prove (the deadlock is timing-dependent, so green tells
// you nothing).
func TestDynamicSecretPairWritersTakeTheOperationLockFirst(t *testing.T) {
	for _, w := range []struct {
		file string
		fn   string
		why  string
	}{
		{"dynamic_secret_operation.go", "ApplyDynamicSecretOperationRequestedTx",
			"request-side intent: claims the idempotency key, then writes the leases row"},
		{"dynamic_secret_lease.go", "ApplyDynamicSecretLeaseIssuedTx",
			"worker-side result: updates the leases row, then completes the operation"},
		{"dynamic_secret_lease.go", "ApplyDynamicSecretLeaseIssuanceFailedForEpochTx",
			"worker-side terminal failure: same leases -> operations walk"},
	} {
		body, ok := funcBody(t, w.file, w.fn)
		if !ok {
			t.Errorf("AN5-LOCKORDER: %s not found in %s; if it was renamed, teach this guard the new name rather than dropping the writer", w.fn, w.file)
			continue
		}
		lockAt := strings.Index(body, "lockDynamicSecretOperationTx(")
		if lockAt < 0 {
			t.Errorf("AN5-LOCKORDER: %s (%s) does not take lockDynamicSecretOperationTx; it writes the operations/leases pair, so without that lock it can form an ABBA cycle with the other writers and deadlock (SQLSTATE 40P01), which is what caused a provider to mint a second credential", w.fn, w.why)
			continue
		}
		// Any table write appearing BEFORE the lock re-opens the cycle.
		for _, stmt := range []string{
			"INSERT INTO dynamic_secret_leases",
			"UPDATE dynamic_secret_leases",
			"INSERT INTO dynamic_secret_operations",
			"UPDATE dynamic_secret_operations",
		} {
			if at := strings.Index(body, stmt); at >= 0 && at < lockAt {
				t.Errorf("AN5-LOCKORDER: %s runs %q BEFORE lockDynamicSecretOperationTx; the lock must be the first statement or the ABBA cycle is back", w.fn, stmt)
			}
		}
	}
}

// TestDynamicSecretOperationLockKeyIsShared asserts the three writers serialize on
// the SAME key. A per-writer key would take a lock and still deadlock, which is the
// most plausible way to "fix" this and get nothing.
func TestDynamicSecretOperationLockKeyIsShared(t *testing.T) {
	body, ok := funcBody(t, "dynamic_secret_operation.go", "lockDynamicSecretOperationTx")
	if !ok {
		t.Fatal("AN5-LOCKORDER: lockDynamicSecretOperationTx not found; the first-lock discipline has no implementation")
	}
	if !strings.Contains(body, "pg_advisory_xact_lock") {
		t.Error("AN5-LOCKORDER: lockDynamicSecretOperationTx must use pg_advisory_xact_lock so the lock releases with the transaction; a session lock leaks on a panicking worker")
	}
	if !strings.Contains(body, "dynamic-secret-operation") {
		t.Error("AN5-LOCKORDER: the lock key must stay namespaced to dynamic-secret-operation so it cannot collide with another advisory-lock family")
	}
	// Inspect the constructed key, not merely the parameter list. A parameter can
	// remain validated yet accidentally disappear from the actual advisory lane.
	const exactKey = `"dynamic-secret-operation\x1f"+tenantID+"\x1f"+tenantEpoch+"\x1f"+idempotencyKey`
	if !strings.Contains(strings.ReplaceAll(body, " ", ""), exactKey) {
		t.Error("AN5-LOCKORDER: the advisory key must concatenate tenant, registration epoch, and idempotency key in that order")
	}
}

func TestDynamicSecretIssuanceFailureValidatesEpochBeforePairLock(t *testing.T) {
	body, ok := funcBody(t, "dynamic_secret_lease.go", "ApplyDynamicSecretLeaseIssuanceFailedForEpochTx")
	if !ok {
		t.Fatal("AUD108-LOCKORDER: epoch-scoped issuance failure projector is missing")
	}
	validateAt := strings.Index(body, "ValidateDynamicSecretTenantEpochTx(")
	lockAt := strings.Index(body, "lockDynamicSecretOperationTx(")
	leaseWriteAt := strings.Index(body, "UPDATE dynamic_secret_leases")
	if validateAt < 0 || lockAt < 0 || leaseWriteAt < 0 ||
		validateAt > lockAt || lockAt > leaseWriteAt {
		t.Errorf("AUD108-LOCKORDER: want tenant epoch validation -> operation advisory lock -> lease write; offsets validation=%d lock=%d write=%d",
			validateAt, lockAt, leaseWriteAt)
	}
}

// funcBody returns the source text of fn in the given file of this package, from
// its `func` keyword to the closing brace at column 0. Reading source is the point:
// the invariant under test is statement ORDER, which a passing integration run
// cannot demonstrate because the deadlock it prevents is timing-dependent.
func funcBody(t *testing.T, file, fn string) (string, bool) {
	t.Helper()
	raw, err := os.ReadFile(file) // #nosec G304 -- fixed sibling path inside this package's own directory (CWE-22)
	if err != nil {
		t.Fatalf("AN5-LOCKORDER: read %s: %v", file, err)
	}
	src := string(raw)
	start := strings.Index(src, "\nfunc "+fn+"(")
	if start < 0 {
		if idx := strings.Index(src, "\nfunc (s *Store) "+fn+"("); idx >= 0 {
			start = idx
		} else {
			return "", false
		}
	}
	rest := src[start+1:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end], true
	}
	return rest, true
}
