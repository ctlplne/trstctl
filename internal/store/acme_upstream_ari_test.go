// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestUpstreamARIProjectionQueuesOneBoundedFetchAndKeepsLastGoodWindow(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantA = "a7100000-0000-4000-8000-000000000001"
	const tenantB = "b7100000-0000-4000-8000-000000000002"
	seedTenant(t, s, tenantA)
	seedTenant(t, s, tenantB)
	issued := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	expires := issued.Add(90 * 24 * time.Hour)
	cert, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, Subject: "CN=ari.example.test", SANs: []string{"ari.example.test"},
		Fingerprint: "sha256-upstream-ari", Source: "external-ca:local-pebble", NotAfter: &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fixture for the authenticated issuance projection. Source is subsequently
	// overwritten by endpoint recording; ARI must bind the immutable issuer.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET source='issued', issuing_external_ca_id='local-pebble'
			WHERE tenant_id=$1 AND id=$2`, tenantA, cert.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	base := store.ACMEUpstreamARI{
		TenantID: tenantA, CertificateID: cert.ID, AuthorityID: "local-pebble",
		ARICertificateID: "AQID.BAUG", Fingerprint: cert.Fingerprint,
		UpdatedAt: issued, NextPollAt: issued, EventSequence: 10,
		EventID: "a7100000-0000-4000-8000-000000000010",
	}
	applyRequest := func(row store.ACMEUpstreamARI) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyACMEUpstreamARIRequestedTx(ctx, tx, row)
		}); err != nil {
			t.Fatal(err)
		}
	}
	applyOutcome := func(row store.ACMEUpstreamARI) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyACMEUpstreamARIObservedTx(ctx, tx, row)
		}); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='external-ca.ari.fetch'`, tenantA).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	applyRequest(base)
	applyRequest(base)
	if got := count(); got != 1 {
		t.Fatalf("initial fetch rows = %d, want one", got)
	}
	var role string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT required_agent_role FROM outbox
			WHERE tenant_id=$1 AND destination=$2`, tenantA, store.ACMEUpstreamARIFetchDestination).Scan(&role)
	}); err != nil {
		t.Fatal(err)
	}
	if role != "control_plane" {
		t.Fatalf("ARI fetch role = %q, want control_plane", role)
	}
	start, end := issued.Add(58*24*time.Hour), issued.Add(60*24*time.Hour)
	ready := base
	ready.Status = "ready"
	ready.WindowStart, ready.WindowEnd = &start, &end
	ready.UpdatedAt = issued.Add(time.Minute)
	ready.FetchedAt = &ready.UpdatedAt
	ready.NextPollAt = ready.UpdatedAt.Add(6 * time.Hour)
	ready.EventSequence = 11
	ready.EventID = "a7100000-0000-4000-8000-000000000011"
	applyOutcome(ready)
	applyOutcome(ready)
	if got := count(); got != 2 {
		t.Fatalf("next fetch rows = %d, want two", got)
	}
	applyRequest(base) // a late replay cannot put the observation back in queued.
	failed := ready
	failed.Status = "error"
	failed.WindowStart, failed.WindowEnd = nil, nil
	failed.FetchedAt = nil
	failed.ErrorClass = "upstream_unavailable"
	failed.FailureCount = 1
	failed.EventSequence = 12
	failed.EventID = "a7100000-0000-4000-8000-000000000012"
	failed.UpdatedAt = ready.UpdatedAt.Add(6 * time.Hour)
	failed.NextPollAt = failed.UpdatedAt.Add(5 * time.Minute)
	applyOutcome(failed)
	got, err := s.GetACMEUpstreamARI(ctx, tenantA, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" || got.WindowStart == nil || !got.WindowStart.Equal(start) ||
		got.WindowEnd == nil || !got.WindowEnd.Equal(end) || got.EventSequence != 12 || count() != 3 {
		t.Fatalf("failed fetch erased authoritative window or lost retry: %+v", got)
	}
	if _, err := s.GetACMEUpstreamARI(ctx, tenantB, cert.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("other tenant read = %v, want no rows", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.SetCertificateRevokedTx(ctx, tx, tenantA, cert.Fingerprint, "compromised", failed.UpdatedAt)
	}); err != nil {
		t.Fatal(err)
	}
	revoked := failed
	revoked.EventSequence = 13
	revoked.EventID = "a7100000-0000-4000-8000-000000000013"
	revoked.NextPollAt = failed.NextPollAt.Add(time.Hour)
	applyOutcome(revoked)
	if got := count(); got != 3 {
		t.Fatalf("revoked certificate queued %d fetches, want three retained", got)
	}
}
