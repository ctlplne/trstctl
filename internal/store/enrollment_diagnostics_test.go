// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A diagnosis is tenant data even when its protocol vocabulary is identical.
// Exercise simultaneous observations so neither the collapse key nor the
// latest timestamp can accidentally become process-global again.
func TestEnrollmentDiagnosticsAggregateInsideTenantRLS(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)
	base := time.Date(2026, 8, 10, 5, 0, 0, 0, time.UTC)

	type observation struct {
		tenant, summary, eventID string
		at                       time.Time
		sequence                 uint64
	}
	observations := []observation{
		{tenant: tenantA, summary: "tenant A challenge refused", eventID: "diag-a-1", at: base, sequence: 1},
		{tenant: tenantB, summary: "tenant B challenge refused", eventID: "diag-b-2", at: base.Add(time.Second), sequence: 2},
		{tenant: tenantA, summary: "tenant A challenge refused again", eventID: "diag-a-3", at: base.Add(2 * time.Second), sequence: 3},
	}

	start := make(chan struct{})
	errCh := make(chan error, len(observations))
	var wg sync.WaitGroup
	for _, candidate := range observations {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errCh <- st.WithTenant(ctx, candidate.tenant, func(tx pgx.Tx) error {
				return st.ApplyEnrollmentDiagnosticObservedTx(ctx, tx, store.EnrollmentDiagnostic{
					TenantID: candidate.tenant, Protocol: "acme", Step: "challenge_validation",
					Cause: "challenge_failed", Summary: candidate.summary,
					Remediation: "repair the challenge response", Actionable: true,
					ObservedAt: candidate.at, SourceEventID: candidate.eventID,
					EventSequence: candidate.sequence,
				})
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("project simultaneous diagnostic: %v", err)
		}
	}

	gotA, err := st.ListEnrollmentDiagnostics(ctx, tenantA, 250)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := st.ListEnrollmentDiagnostics(ctx, tenantB, 250)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotA) != 1 || gotA[0].TenantID != tenantA || gotA[0].Count != 2 ||
		gotA[0].Summary != "tenant A challenge refused again" || !gotA[0].ObservedAt.Equal(base.Add(2*time.Second)) {
		t.Fatalf("tenant A diagnostics = %+v, want its two observations collapsed with the latest fields", gotA)
	}
	if len(gotB) != 1 || gotB[0].TenantID != tenantB || gotB[0].Count != 1 ||
		gotB[0].Summary != "tenant B challenge refused" || !gotB[0].ObservedAt.Equal(base.Add(time.Second)) {
		t.Fatalf("tenant B diagnostics = %+v, want only its observation", gotB)
	}
	// The inline command projection and later tail replay can present the exact
	// same event twice. Its source id must make the second application a no-op.
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyEnrollmentDiagnosticObservedTx(ctx, tx, store.EnrollmentDiagnostic{
			TenantID: tenantA, Protocol: "acme", Step: "challenge_validation", Cause: "challenge_failed",
			Summary: "tenant A challenge refused again", Remediation: "repair the challenge response", Actionable: true,
			ObservedAt: base.Add(2 * time.Second), SourceEventID: "diag-a-3", EventSequence: 3,
		})
	}); err != nil {
		t.Fatalf("reapply exact diagnostic event: %v", err)
	}
	gotA, err = st.ListEnrollmentDiagnostics(ctx, tenantA, 250)
	if err != nil || len(gotA) != 1 || gotA[0].Count != 2 {
		t.Fatalf("exact event replay changed tenant A count: %+v err=%v", gotA, err)
	}

	err = st.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return st.ApplyEnrollmentDiagnosticObservedTx(ctx, tx, store.EnrollmentDiagnostic{
			TenantID: tenantA, Protocol: "acme", Step: "authorization", Cause: "policy_denied",
			Summary: "cross-tenant write", ObservedAt: base, SourceEventID: "diag-cross-tenant", EventSequence: 4,
		})
	})
	if err == nil {
		t.Fatal("tenant B projected a tenant A diagnostic; FORCE RLS must reject it")
	}
}

func TestNewEnrollmentRefusalInvalidatesEarlierProofLink(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)
	base := time.Date(2026, 8, 13, 5, 0, 0, 0, time.UTC)
	observed := store.EnrollmentDiagnostic{
		TenantID: tenantA, DiagnosticID: "diagnostic:aud49-repeat", Protocol: "est",
		Step: "authorize", Cause: "template_acl_denied", Summary: "template refused",
		ObservedAt: base, SourceEventID: "diag-repeat-1", EventSequence: 1,
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyEnrollmentDiagnosticObservedTx(ctx, tx, observed)
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyEnrollmentDiagnosticVerificationQueuedTx(ctx, tx, tenantA,
			observed.DiagnosticID, "endpoint-proof-1", "fingerprint-proof-1", base.Add(time.Second), 2)
	}); err != nil {
		t.Fatal(err)
	}
	linked, err := st.ListEnrollmentDiagnostics(ctx, tenantA, 10)
	if err != nil || len(linked) != 1 || linked[0].VerificationEndpointID != "endpoint-proof-1" ||
		linked[0].ExpectedFingerprint != "fingerprint-proof-1" {
		t.Fatalf("queued proof link = %+v err=%v", linked, err)
	}
	observed.ObservedAt = base.Add(2 * time.Second)
	observed.SourceEventID = "diag-repeat-3"
	observed.EventSequence = 3
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyEnrollmentDiagnosticObservedTx(ctx, tx, observed)
	}); err != nil {
		t.Fatal(err)
	}
	invalidated, err := st.ListEnrollmentDiagnostics(ctx, tenantA, 10)
	if err != nil || len(invalidated) != 1 || invalidated[0].VerificationEndpointID != "" ||
		invalidated[0].ExpectedFingerprint != "" || !invalidated[0].VerificationQueuedAt.IsZero() {
		t.Fatalf("new refusal retained stale prove-fixed authority: %+v err=%v", invalidated, err)
	}
}

func TestEnrollmentDiagnosticRetentionIsBoundedPerTenant(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)
	base := time.Date(2026, 8, 10, 6, 0, 0, 0, time.UTC)

	for i := 0; i < 205; i++ {
		candidate := store.EnrollmentDiagnostic{
			TenantID: tenantA, Protocol: "acme", Step: "challenge_validation",
			Cause: fmt.Sprintf("cause-%03d", i), Summary: fmt.Sprintf("diagnosis %03d", i),
			ObservedAt: base.Add(time.Duration(i) * time.Second), SourceEventID: fmt.Sprintf("diag-a-%03d", i), EventSequence: uint64(i + 1),
		}
		if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return st.ApplyEnrollmentDiagnosticObservedTx(ctx, tx, candidate)
		}); err != nil {
			t.Fatalf("project tenant A diagnosis %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		candidate := store.EnrollmentDiagnostic{
			TenantID: tenantB, Protocol: "acme", Step: "finalize",
			Cause: fmt.Sprintf("tenant-b-%d", i), Summary: "tenant B diagnosis",
			ObservedAt: base.Add(time.Duration(i) * time.Second), SourceEventID: fmt.Sprintf("diag-b-%d", i), EventSequence: uint64(i + 1),
		}
		if err := st.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
			return st.ApplyEnrollmentDiagnosticObservedTx(ctx, tx, candidate)
		}); err != nil {
			t.Fatalf("project tenant B diagnosis %d: %v", i, err)
		}
	}

	gotA, err := st.ListEnrollmentDiagnostics(ctx, tenantA, 250)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := st.ListEnrollmentDiagnostics(ctx, tenantB, 250)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotA) != store.EnrollmentDiagnosticRetentionLimit {
		t.Fatalf("tenant A retained %d rows, want %d", len(gotA), store.EnrollmentDiagnosticRetentionLimit)
	}
	if gotA[0].Cause != "cause-204" || gotA[len(gotA)-1].Cause != "cause-005" {
		t.Fatalf("tenant A retention window = newest %q oldest %q, want cause-204..cause-005", gotA[0].Cause, gotA[len(gotA)-1].Cause)
	}
	if len(gotB) != 3 {
		t.Fatalf("tenant A retention evicted tenant B rows: %+v", gotB)
	}
}
