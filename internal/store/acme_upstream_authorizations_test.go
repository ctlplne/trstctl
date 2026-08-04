// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A reuse must never erase the date of the last real validation (epic B7).
//
// This is the whole point of the table. An authority that already holds a valid
// authorization issues without a challenge, and if that observation overwrote
// "last validated", the row would report a healthy recent date for an install
// that has not proved control in months. The operator would then discover the
// truth on the day the reuse window closes — for every identifier authorized in
// the same original burst, on the same day.
//
// So the two observations write different columns, and the gap between them is
// the signal the surface is built to show.
func TestReuseDoesNotOverwriteTheLastRealValidation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "b7000001-0000-0000-0000-000000000001"
	seedTenant(t, s, tenantID)

	validated := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	reused := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	expires := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)

	apply := func(a store.ACMEUpstreamAuthorization) {
		t.Helper()
		a.TenantID = tenantID
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyACMEUpstreamAuthorizationObservedTx(ctx, tx, a)
		}); err != nil {
			t.Fatalf("apply observation: %v", err)
		}
	}

	// A real validation, then two reuses on top of it. Each carries the log
	// position of the event that produced it.
	apply(store.ACMEUpstreamAuthorization{
		Identifier: "api.example.test", Issuer: "letsencrypt",
		ChallengeType: "dns-01", ObservedAt: validated, ExpiresAt: expires, EventSequence: 10,
	})
	apply(store.ACMEUpstreamAuthorization{
		Identifier: "api.example.test", Issuer: "letsencrypt",
		Reused: true, ObservedAt: reused, EventSequence: 11,
	})
	apply(store.ACMEUpstreamAuthorization{
		Identifier: "api.example.test", Issuer: "letsencrypt",
		Reused: true, ObservedAt: reused.Add(time.Hour), EventSequence: 12,
	})

	rows, err := s.ListACMEUpstreamAuthorizations(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	got := rows[0]
	if !got.LastValidatedAt.Equal(validated) {
		t.Errorf("last_validated_at = %v, want %v — a reuse overwrote the date of the last real "+
			"validation, so the row reports control this install has not proved since %v",
			got.LastValidatedAt, validated, validated)
	}
	if !got.LastReusedAt.Equal(reused.Add(time.Hour)) {
		t.Errorf("last_reused_at = %v, want the most recent reuse", got.LastReusedAt)
	}
	if got.ReuseCount != 2 || got.ValidateCount != 1 {
		t.Errorf("counts = reuse %d / validate %d, want 2 / 1", got.ReuseCount, got.ValidateCount)
	}
	// The challenge type of the last REAL validation survives the reuses; a
	// reuse carries none, and blanking the column would lose how this
	// identifier is actually validated when it is.
	if got.ChallengeType != "dns-01" {
		t.Errorf("challenge_type = %q, want dns-01 to survive the reuses", got.ChallengeType)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("expires_at = %v, want the authority's stated expiry to survive", got.ExpiresAt)
	}
}

// An identifier that has NEVER been validated by this install reports so.
//
// This is the row an operator must act on, and it is invisible to any surface
// built on "last issued": issuance for it has always succeeded. The zero
// LastValidatedAt is what the API turns into never_validated.
func TestNeverValidatedIdentifiersAreDistinguishable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "b7000002-0000-0000-0000-000000000002"
	seedTenant(t, s, tenantID)

	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.ApplyACMEUpstreamAuthorizationObservedTx(ctx, tx, store.ACMEUpstreamAuthorization{
			TenantID: tenantID, Identifier: "*.app.example.test", Issuer: "letsencrypt",
			Reused: true, ObservedAt: time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC), EventSequence: 7,
		})
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	rows, err := s.ListACMEUpstreamAuthorizations(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if !rows[0].LastValidatedAt.IsZero() {
		t.Errorf("last_validated_at = %v; a reuse-only history must leave it unset, because every "+
			"issuance so far rode an authorization this install did not earn and cannot repeat",
			rows[0].LastValidatedAt)
	}
	if rows[0].ValidateCount != 0 {
		t.Errorf("validate_count = %d, want 0", rows[0].ValidateCount)
	}
}

// The same identifier at two authorities is two rows (AN-1 aside, this is about
// not reporting a union). Two CAs have independent reuse windows, and folding
// them together would hide whichever is about to lapse behind the other's
// healthier date.
func TestTwoAuthoritiesKeepIndependentRows(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "b7000003-0000-0000-0000-000000000003"
	seedTenant(t, s, tenantID)

	for _, issuer := range []string{"letsencrypt", "private-acme"} {
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyACMEUpstreamAuthorizationObservedTx(ctx, tx, store.ACMEUpstreamAuthorization{
				TenantID: tenantID, Identifier: "api.example.test", Issuer: issuer,
				ChallengeType: "dns-01", ObservedAt: time.Now().UTC(), EventSequence: 5,
			})
		}); err != nil {
			t.Fatalf("apply %s: %v", issuer, err)
		}
	}

	rows, err := s.ListACMEUpstreamAuthorizations(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want one per authority; the same name at two CAs has two "+
			"independent reuse windows", len(rows))
	}
}

// Replaying the log must not inflate the counters (AN-2/AN-5).
//
// Boot replays the WHOLE event log without truncating — only Projector.Rebuild
// truncates — and the durable tailer can re-deliver an event the inline path
// already applied. internal/projections states the contract plainly: applying an
// already-projected event is an idempotent upsert.
//
// Timestamps satisfy that for free, because they are set to a fixed observed
// value. A counter written as "count + 1" does not, and that is the shape this
// table needs: the headline an operator acts on is "six reuses, zero
// validations". Without a sequence guard, every restart would multiply those
// totals by the history, and a deployment that has never once validated could
// come to display a validation count — the precise class of false served claim
// this whole epic exists to remove.
func TestReplayingTheSameEventDoesNotInflateTheCounters(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "b7000004-0000-0000-0000-000000000004"
	seedTenant(t, s, tenantID)

	observation := store.ACMEUpstreamAuthorization{
		TenantID: tenantID, Identifier: "api.example.test", Issuer: "letsencrypt",
		ChallengeType: "dns-01", EventSequence: 42,
		ObservedAt: time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
	}
	reuse := store.ACMEUpstreamAuthorization{
		TenantID: tenantID, Identifier: "api.example.test", Issuer: "letsencrypt",
		Reused: true, EventSequence: 43,
		ObservedAt: time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC),
	}

	// Apply the pair, then apply the identical pair again — exactly what a boot
	// replay does to a read model that was already current.
	for round := 1; round <= 3; round++ {
		for _, a := range []store.ACMEUpstreamAuthorization{observation, reuse} {
			if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				return s.ApplyACMEUpstreamAuthorizationObservedTx(ctx, tx, a)
			}); err != nil {
				t.Fatalf("round %d apply: %v", round, err)
			}
		}
	}

	rows, err := s.ListACMEUpstreamAuthorizations(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	got := rows[0]
	if got.ValidateCount != 1 {
		t.Errorf("validate_count = %d after three replays of one validation, want 1 — the "+
			"counters inflate on every boot, so the surface reports validations that never "+
			"happened", got.ValidateCount)
	}
	if got.ReuseCount != 1 {
		t.Errorf("reuse_count = %d after three replays of one reuse, want 1", got.ReuseCount)
	}
	if got.EventSequence != 43 {
		t.Errorf("event_sequence = %d, want the highest applied sequence 43", got.EventSequence)
	}
	// A genuinely NEW event still advances the row after the replays.
	next := reuse
	next.EventSequence = 44
	next.ObservedAt = time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.ApplyACMEUpstreamAuthorizationObservedTx(ctx, tx, next)
	}); err != nil {
		t.Fatalf("apply new event: %v", err)
	}
	rows, err = s.ListACMEUpstreamAuthorizations(ctx, tenantID)
	if err != nil {
		t.Fatalf("list after new event: %v", err)
	}
	if rows[0].ReuseCount != 2 {
		t.Errorf("reuse_count = %d after a genuinely new reuse, want 2 — the guard that stops "+
			"replays must not also stop real events", rows[0].ReuseCount)
	}
}

// Never-validated rows sort above everything (epic B7).
//
// Sorting by expiry alone buries the rows that matter. An identifier this
// install has never once validated can carry the most comfortable expiry on the
// list, because the authority keeps reissuing it from an authorization the
// install did not earn — it looks the healthiest right up to the moment the
// reuse window closes. An operator scanning the top of this list has to find it
// there.
func TestNeverValidatedRowsSortAboveHealthierLookingOnes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "b7000005-0000-0000-0000-000000000005"
	seedTenant(t, s, tenantID)

	apply := func(a store.ACMEUpstreamAuthorization) {
		t.Helper()
		a.TenantID = tenantID
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyACMEUpstreamAuthorizationObservedTx(ctx, tx, a)
		}); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}

	// The dangerous row: never validated, but the LATEST expiry on the list.
	apply(store.ACMEUpstreamAuthorization{
		Identifier: "never.example.test", Issuer: "letsencrypt", Reused: true,
		ExpiresAt:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		ObservedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), EventSequence: 1,
	})
	// A healthy row that expires much sooner.
	apply(store.ACMEUpstreamAuthorization{
		Identifier: "healthy.example.test", Issuer: "letsencrypt", ChallengeType: "dns-01",
		ExpiresAt:  time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
		ObservedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), EventSequence: 2,
	})

	rows, err := s.ListACMEUpstreamAuthorizations(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Identifier != "never.example.test" {
		t.Errorf("first row is %q; the never-validated identifier sorted below one that expires "+
			"five months sooner, so the row an operator must act on is not where they look",
			rows[0].Identifier)
	}
}

// A re-verification sweep must never ratify a divergence (epic D2).
//
// The scheduler builds each sweep's expectation from the control plane's own
// record of what SHOULD be there. If it built the expectation from what was
// last OBSERVED, an endpoint serving the wrong certificate would be re-verified
// as correct on the very next sweep — the alarm would silence itself, and the
// longer a divergence persisted the more confidently the surface would report
// it as fine.
//
// This pins the property at the level the scheduler reads: a stored divergence
// keeps its EXPECTED fingerprint, which is what the next sweep will probe
// against, and never adopts the observed one.
func TestADivergentObservationKeepsItsExpectedFingerprint(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "d2000001-0000-0000-0000-000000000001"
	seedTenant(t, s, tenantID)

	apply := func(v store.EndpointVerification) {
		t.Helper()
		v.TenantID = tenantID
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyEndpointVerificationTx(ctx, tx, v)
		}); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}

	// First: healthy. The endpoint serves what was deployed.
	apply(store.EndpointVerification{
		EndpointID: "ep-1", Address: "api.example.test:443", Vantage: "relay",
		Reached: true, ExpectedFingerprint: "expected-aa", ObservedFingerprint: "expected-aa",
		LastCheckedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), EventSequence: 1,
	})

	// Then: the listener starts serving something else.
	apply(store.EndpointVerification{
		EndpointID: "ep-1", Address: "api.example.test:443", Vantage: "relay",
		Reached: true, Mismatch: "fingerprint",
		ExpectedFingerprint: "expected-aa", ObservedFingerprint: "wrong-bb",
		LastCheckedAt: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), EventSequence: 2,
	})

	rows, err := s.ListEndpointVerifications(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	got := rows[0]
	if got.ExpectedFingerprint != "expected-aa" {
		t.Errorf("expected_fingerprint = %q; the next sweep probes against this value, so "+
			"adopting the observed one would re-verify the divergence as correct and silence "+
			"its own alarm", got.ExpectedFingerprint)
	}
	if got.ObservedFingerprint != "wrong-bb" {
		t.Errorf("observed_fingerprint = %q, want the certificate actually being served", got.ObservedFingerprint)
	}
	// And the last-known-good date survives the failure, because it is the only
	// measure of how long this has been broken.
	if got.LastGoodAt.IsZero() {
		t.Error("last_good_at was erased by a failing observation; the age of the outage is " +
			"the one thing an operator cannot reconstruct afterwards")
	}
}
