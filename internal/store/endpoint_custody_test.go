// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
)

// The last-executor query must actually RUN (epic B2).
//
// It previously applied `->>` to outbox.payload, which is declared bytea.
// PostgreSQL has no such operator for bytea, so the statement failed at plan
// time on EVERY call — and because the API layer treats this read as
// best-effort, the failure surfaced as an empty "Last renewed by" column rather
// than as an error. A query that cannot run looks exactly like an estate that
// has never renewed anything, which is the reading an operator would take.
//
// So the test that matters is not "does it return the right rows" but "does it
// execute at all against the real schema".
func TestLastRenewalExecutorsQueryExecutesAgainstTheRealSchema(t *testing.T) {
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)

	rows, err := st.LastRenewalExecutors(ctx, tenantID)
	if err != nil {
		t.Fatalf("LastRenewalExecutors: %v; the console's custody view swallows this error, so a "+
			"query that cannot run reads as an estate that has never renewed", err)
	}
	// An empty estate legitimately has no executors. The point is that we got
	// here rather than erroring.
	if len(rows) != 0 {
		t.Errorf("a tenant with no renewals reported %d executors", len(rows))
	}
}
