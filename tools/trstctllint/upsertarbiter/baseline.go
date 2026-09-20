// SPDX-License-Identifier: BUSL-1.1

package upsertarbiter

// reviewedUpserts lists the pre-existing upsert sites whose tables carry a second
// unique index and that neither lock nor retry (OPP-C01 closure sweep, 2026-09-07).
// They are the DP2-043/DP2-046 family still owed a fix; each is keyed by
// repo-relative file and enclosing function so a NEW site fails closed, and
// TestReviewedBaselineIsNotStale fails when an entry no longer needs listing.
// reviewedUpserts is intentionally empty: every dual-unique upsert in
// internal/store is guarded (advisory lock keyed on its arbiter, a unique_violation
// handler, or a target-less ON CONFLICT DO NOTHING). An entry here is a reviewed,
// dated exception and must name the finding that owns it.
var reviewedUpserts = map[string]map[string]bool{}
