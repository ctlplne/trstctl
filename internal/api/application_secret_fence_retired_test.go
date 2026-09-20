// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// DP2-058: a retry of a secret-store command whose first attempt was shed after
// claiming its durable fence can find that fence already completed and retired
// by the crash-recovery sweep. Only the store's row-level not-found on the fence
// qualifies as "retired": the retry then consults the materialized receipt. A
// missing secret, backpressure or any other failure keeps its own contract.
func TestApplicationSecretFenceRetiredRecognisesOnlyTheVanishedFenceRow(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"fence row gone (pgx no rows)", pgx.ErrNoRows, true},
		{"wrapped fence row gone", fmt.Errorf("store: finalize fence: %w", pgx.ErrNoRows), true},
		{"secret missing keeps its 404 contract", store.ErrSecretNotFound, false},
		{"backpressure keeps its 503 contract", store.ErrDatastoreBusy, false},
		{"idempotency conflict keeps its 409 contract", store.ErrIdempotencyConflict, false},
		{"other error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := applicationSecretFenceRetired(tc.err); got != tc.want {
			t.Errorf("%s: applicationSecretFenceRetired(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}
