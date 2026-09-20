// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"fmt"
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

// The tri-state counts three different claims, and "unverified" is the honest
// middle (epic D3).
//
// A dashboard that counted deliveries and called it health would be counting
// INTENTIONS — the pipeline's own account of what it did — which is exactly the
// blindness the verification engine exists to remove. The count that matters is
// how many endpoints were observed serving what was deployed.
//
// The subtle one is unverified: a delivered target nobody has probed is not a
// failure and is emphatically not a pass. Folding it into either direction
// would be the overclaim this epic removes, and on a fresh install every target
// is here — which is the correct starting picture.
func TestDeploymentTriStateSeparatesDeliveredFromVerified(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "d3000001-0000-0000-0000-000000000001"
	seedTenant(t, s, tenantID)

	n := 0
	receipt := func(connector, target, status, key string, at time.Time) {
		t.Helper()
		n++
		id := fmt.Sprintf("d3000001-0000-0000-0000-%012d", n)
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: id, TenantID: tenantID, Destination: "connector.deploy",
				Connector: connector, Target: target, Status: status,
				IdempotencyKey: key, CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatalf("record %s receipt: %v", status, err)
		}
	}

	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	// Target A: delivered and verified.
	receipt("nginx", "edge-a", "delivered", "a-1", base)
	receipt("nginx", "edge-a", "verified", "a-1:verified", base.Add(time.Minute))
	// Target B: delivered, and the endpoint is serving something else.
	receipt("nginx", "edge-b", "delivered", "b-1", base)
	receipt("nginx", "edge-b", "verify_failed", "b-1:verified", base.Add(time.Minute))
	// Target C: delivered, nobody has looked.
	receipt("nginx", "edge-c", "delivered", "c-1", base)

	got, err := s.SummarizeDeploymentTriState(ctx, tenantID)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got.Delivered != 3 {
		t.Errorf("Delivered = %d, want 3", got.Delivered)
	}
	if got.Verified != 1 {
		t.Errorf("Verified = %d, want 1 — only one endpoint was observed serving what was "+
			"deployed, and that is the number a health surface should lead with", got.Verified)
	}
	if got.VerifyFailed != 1 {
		t.Errorf("VerifyFailed = %d, want 1", got.VerifyFailed)
	}
	if got.Unverified != 1 {
		t.Errorf("Unverified = %d, want 1 — a delivered target nobody probed is neither a "+
			"failure nor a pass, and collapsing it into either is the overclaim this epic removes",
			got.Unverified)
	}
	// The headline property: delivered is NOT verified.
	if got.Delivered == got.Verified {
		t.Error("delivered and verified counted the same; the whole point of the tri-state is " +
			"that a connector applying a credential and an endpoint serving it are different facts")
	}
}

// A fleet run cannot show all-green while one replacement is not being served
// (epic D6).
//
// This is the gate's whole purpose. Before D2/D3 nothing re-read an endpoint, so
// every gate trstctl filled in itself was not_evaluated — correctly, because a
// verdict nobody computed is not a pass. Now there is evidence, and the two
// rules an operator relies on mid-incident are that failure dominates and
// absence beats success: a run must never read green while something in it is
// known-broken, and never read green for something nobody looked at.
func TestFleetVerificationSummaryDistinguishesFailedFromUnlooked(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "d6000001-0000-0000-0000-000000000001"
	seedTenant(t, s, tenantID)

	idA := "d6000001-0000-0000-0000-0000000000a1"
	idB := "d6000001-0000-0000-0000-0000000000b1"
	idC := "d6000001-0000-0000-0000-0000000000c1"

	n := 0
	receipt := func(identityID, status string, at time.Time) {
		t.Helper()
		n++
		id := fmt.Sprintf("d6000001-0000-0000-0000-%012d", n)
		ident := identityID
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			var jobID int64
			if err := tx.QueryRow(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
				VALUES ($1, 'connector.deploy', '{}'::bytea, $2) RETURNING id`, tenantID, id).Scan(&jobID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO agent_job_receipts
				(tenant_id, job_id, attempt, agent, kind, outcome, state, signer_fingerprint, statement, signature, observed_at)
				VALUES ($1, $2, 1, 'signed-agent', 'connector.deploy', $3, 'verified', 'sha256:test', 'canonical', 'signature', $4)`,
				tenantID, jobID, status, at); err != nil {
				return err
			}
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: id, TenantID: tenantID, IdentityID: &ident,
				Destination: "connector.deploy", Connector: "nginx", Target: "edge",
				Status: status, IdempotencyKey: id + ":verified", CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatalf("record receipt: %v", err)
		}
	}

	base := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	receipt(idA, "verified", base)
	receipt(idB, "verify_failed", base)
	// idC has no verification receipt at all — nobody looked.

	got, err := s.SummarizeFleetVerification(ctx, tenantID, []string{idA, idB, idC})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got.Verified != 1 {
		t.Errorf("Verified = %d, want 1", got.Verified)
	}
	if got.Failed != 1 {
		t.Errorf("Failed = %d, want 1 — one replacement's endpoint is serving something else, "+
			"and a run containing it must never display all-green", got.Failed)
	}
	if got.Unverified != 1 {
		t.Errorf("Unverified = %d, want 1 — a replacement nobody probed is not a pass, and "+
			"during an incident it is exactly the one worth knowing about", got.Unverified)
	}
}

// The latest verification wins, so a replacement that failed and was then fixed
// reads as verified rather than being condemned by its history.
func TestFleetVerificationTakesTheLatestOutcomePerIdentity(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "d6000002-0000-0000-0000-000000000002"
	seedTenant(t, s, tenantID)
	id := "d6000002-0000-0000-0000-0000000000a1"

	n := 0
	receipt := func(status string, at time.Time) {
		t.Helper()
		n++
		rid := fmt.Sprintf("d6000002-0000-0000-0000-%012d", n)
		ident := id
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			var jobID int64
			if err := tx.QueryRow(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
				VALUES ($1, 'connector.deploy', '{}'::bytea, $2) RETURNING id`, tenantID, rid).Scan(&jobID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO agent_job_receipts
				(tenant_id, job_id, attempt, agent, kind, outcome, state, signer_fingerprint, statement, signature, observed_at)
				VALUES ($1, $2, 1, 'signed-agent', 'connector.deploy', $3, 'verified', 'sha256:test', 'canonical', 'signature', $4)`,
				tenantID, jobID, status, at); err != nil {
				return err
			}
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: rid, TenantID: tenantID, IdentityID: &ident,
				Destination: "connector.deploy", Connector: "nginx", Target: "edge",
				Status: status, IdempotencyKey: rid + ":verified", CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatalf("record receipt: %v", err)
		}
	}

	base := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	receipt("verify_failed", base)
	receipt("verified", base.Add(time.Hour))

	got, err := s.SummarizeFleetVerification(ctx, tenantID, []string{id})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got.Verified != 1 || got.Failed != 0 {
		t.Errorf("verified=%d failed=%d; a replacement that was fixed must read as verified "+
			"rather than being condemned by an earlier failure", got.Verified, got.Failed)
	}
}

// The renewal SLO and its error budget (epic D6).
//
// The two things easy to get wrong here both teach a team to ignore the number:
// reporting a breach when nothing was due, and reporting a burn figure so
// extreme it stops meaning anything.
func TestRenewalSLOTreatsAnIdleWindowAsHealthy(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "d6100001-0000-0000-0000-000000000001"
	seedTenant(t, s, tenantID)

	got, err := s.SummarizeRenewalSLO(ctx, tenantID, 30, 99)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got.Breached() {
		t.Error("an estate with no renewals due reported an SLO breach; paging someone about " +
			"the absence of work is the fastest way to teach a team to ignore an SLO")
	}
	if got.ObservedPercent != 100 {
		t.Errorf("ObservedPercent = %v over an idle window, want 100", got.ObservedPercent)
	}
	if got.BudgetRemainingPercent != 100 {
		t.Errorf("BudgetRemainingPercent = %v with nothing spent, want 100", got.BudgetRemainingPercent)
	}
}

// Error budget burn is clamped at zero. An SLO reporting -340% consumed is not
// more actionable than one reporting none left, and the raw counts are beside it.
func TestRenewalSLOClampsBudgetBurn(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "d6100002-0000-0000-0000-000000000002"
	seedTenant(t, s, tenantID)

	n := 0
	run := func(status string) {
		t.Helper()
		n++
		id := fmt.Sprintf("d6100002-0000-0000-0000-%012d", n)
		now := time.Now().UTC()
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO lifecycle_rotation_runs
				        (id, tenant_id, identity_id, status, trigger, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, 'scheduler', $5, $5)`,
				id, tenantID, tenantID, status, now)
			return err
		}); err != nil {
			t.Fatalf("seed run: %v", err)
		}
	}

	// A 99% target over ten runs allows 0.1 failures; five failures is a very
	// deep breach.
	for i := 0; i < 5; i++ {
		run("completed")
	}
	for i := 0; i < 5; i++ {
		run("failed")
	}

	got, err := s.SummarizeRenewalSLO(ctx, tenantID, 30, 99)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got.Total != 10 || got.Failed != 5 {
		t.Fatalf("counts = %d total / %d failed, want 10/5", got.Total, got.Failed)
	}
	if !got.Breached() {
		t.Error("a 50% success rate against a 99% target did not report as breached")
	}
	if got.BudgetRemainingPercent < 0 {
		t.Errorf("BudgetRemainingPercent = %v; burn is clamped at zero because a large negative "+
			"number is not more actionable than none-left", got.BudgetRemainingPercent)
	}
	if got.ObservedPercent != 50 {
		t.Errorf("ObservedPercent = %v, want 50", got.ObservedPercent)
	}
}

// A renewal still in flight is neither a success nor a failure, and counting it
// as either would move the number for reasons unrelated to reliability.
func TestRenewalSLOExcludesRunsStillInFlight(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := "d6100003-0000-0000-0000-000000000003"
	seedTenant(t, s, tenantID)

	n := 0
	run := func(status string) {
		t.Helper()
		n++
		id := fmt.Sprintf("d6100003-0000-0000-0000-%012d", n)
		now := time.Now().UTC()
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO lifecycle_rotation_runs
				        (id, tenant_id, identity_id, status, trigger, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, 'scheduler', $5, $5)`,
				id, tenantID, tenantID, status, now)
			return err
		}); err != nil {
			t.Fatalf("seed run: %v", err)
		}
	}
	run("completed")
	run("executing")
	run("queued")

	got, err := s.SummarizeRenewalSLO(ctx, tenantID, 30, 99)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got.Total != 1 {
		t.Errorf("Total = %d, want 1 — only terminal runs count, because an unfinished renewal "+
			"is neither a success nor a failure yet", got.Total)
	}
}
