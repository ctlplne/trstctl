// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A187: a tenant's customer assurance facts, read in one tenant transaction:
// the inventory and its ownership now, expiry against the window, renewals,
// revocations and failures inside the period, endpoint observations, and the
// incident runs open or active in it, with their evidence. Nothing outside the
// period, no expected ephemeral credential and nothing of another tenant's is
// counted.
func TestCustomerAssuranceFactsCountOneTenantsPeriod(t *testing.T) {
	const tenant, other = "a1870000-0000-4000-8000-000000000001", "b1870000-0000-4000-8000-000000000002"
	s := newStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	from, through := now.Add(-7*24*time.Hour), now.Add(time.Minute)
	before := from.Add(-time.Hour)
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenant, Kind: store.OwnerTeam, Name: "payments"})
	if err != nil {
		t.Fatal(err)
	}
	serial := 0
	record := func(tenantID, name string, owned bool, notAfter time.Time, key string) store.Certificate {
		t.Helper()
		serial++
		c := store.Certificate{TenantID: tenantID, Subject: "CN=" + name, Issuer: "CN=CA", Serial: fmt.Sprintf("%d", serial),
			Fingerprint: fmt.Sprintf("%064d", 1870000+serial), Source: "issued", Status: "active", NotAfter: &notAfter,
			IssuanceIdempotencyKey: key}
		if owned {
			c.OwnerID = &owner.ID
		}
		out, err := s.UpsertCertificate(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	soon, later, past := now.Add(3*24*time.Hour), now.Add(90*24*time.Hour), now.Add(-24*time.Hour)
	record(tenant, "soon.example.test", true, soon, "")
	record(tenant, "later.example.test", false, later, "")
	record(tenant, "expired.example.test", true, past, "")
	record(tenant, "ephemeral.example.test", false, soon, "ephemeral-issue:job-1")
	renewed := record(tenant, "renewed.example.test", true, later, "")
	renewedBefore := record(tenant, "renewed-before.example.test", true, later, "")
	revoked := record(tenant, "revoked.example.test", true, later, "")
	record(other, "other.example.test", false, soon, "")

	identityID := "18700000-0000-4000-8000-000000000001"
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		for _, u := range []struct {
			id     string
			status string
			at     time.Time
			column string
		}{
			{renewed.ID, "superseded", now.Add(-time.Hour), "renewed_at"},
			{renewedBefore.ID, "superseded", before, "renewed_at"},
			{revoked.ID, "revoked", now.Add(-time.Hour), "revoked_at"},
		} {
			if _, err := tx.Exec(ctx, `UPDATE certificates SET status = $3, `+u.column+` = $4 WHERE tenant_id = $1 AND id = $2`,
				tenant, u.id, u.status, u.at); err != nil {
				return err
			}
		}
		for i, r := range []store.RotationRun{
			{Status: "failed", Error: "ACME order rejected", UpdatedAt: now.Add(-2 * time.Hour)},
			{Status: "failed", Error: "outside the period", UpdatedAt: before},
			{Status: "succeeded", UpdatedAt: now.Add(-time.Hour)},
		} {
			r.ID, r.TenantID, r.IdentityID, r.Trigger = fmt.Sprintf("18700000-0000-4000-8000-0000000001%02d", i), tenant, identityID, "scheduler"
			r.IdempotencyKey, r.CreatedAt = fmt.Sprintf("a187-run-%d", i), r.UpdatedAt
			if err := s.ApplyRotationRunRecordedTx(ctx, tx, r); err != nil {
				return err
			}
		}
		for i, d := range []store.ConnectorDeliveryReceipt{
			{Status: "failed", Reason: "target refused the certificate", UpdatedAt: now.Add(-3 * time.Hour)},
			{Status: "verify_failed", Reason: "served a different certificate", UpdatedAt: now.Add(-4 * time.Hour)},
			{Status: "verified", UpdatedAt: now.Add(-5 * time.Hour)},
			{Status: "failed", Reason: "outside the period", UpdatedAt: before},
		} {
			d.ID, d.TenantID, d.IdentityID = fmt.Sprintf("18700000-0000-4000-8000-0000000002%02d", i), tenant, &identityID
			d.Destination, d.Connector, d.Target, d.IdempotencyKey, d.CreatedAt = "connector.deploy", "apache", "edge", fmt.Sprintf("a187-deploy-%d", i), d.UpdatedAt
			if err := s.ApplyConnectorDeliveryRecordedTx(ctx, tx, d); err != nil {
				return err
			}
		}
		for i, v := range []store.EndpointVerification{
			{Reached: true, ExpectedFingerprint: "aa", ObservedFingerprint: "aa", LastCheckedAt: now.Add(-time.Hour)},
			{Reached: true, ExpectedFingerprint: "aa", ObservedFingerprint: "bb", Mismatch: "fingerprint", LastCheckedAt: before},
			{Reached: false, ExpectedFingerprint: "aa", LastCheckedAt: now.Add(-2 * time.Hour)},
		} {
			v.TenantID, v.EndpointID, v.Address, v.Vantage, v.EventSequence = tenant, fmt.Sprintf("edge-%d:443", i), fmt.Sprintf("edge-%d.example.test:443", i), "relay", uint64(i+1)
			if err := s.ApplyEndpointVerificationTx(ctx, tx, v); err != nil {
				return err
			}
		}
		for _, in := range []struct {
			table, id, status string
			created, updated  time.Time
			evidence          string
		}{
			{"incident_executions", "18700000-0000-4000-8000-000000000301", "running", before, before, ""},
			{"incident_executions", "18700000-0000-4000-8000-000000000302", "executed", now.Add(-3 * time.Hour), now.Add(-2 * time.Hour), "header.payload.signature"},
			{"incident_executions", "18700000-0000-4000-8000-000000000303", "executed", before.Add(-time.Hour), before, ""},
			{"incident_fleet_reissuance_runs", "18700000-0000-4000-8000-000000000304", "running", now.Add(-time.Hour), now.Add(-time.Hour), ""},
		} {
			subject := "compromised_identity_id"
			if in.table == "incident_fleet_reissuance_runs" {
				subject = "issuer_id"
			}
			if _, err := tx.Exec(ctx, `INSERT INTO `+in.table+` (id, tenant_id, `+subject+`, status, phase, evidence_bundle_format,
				evidence_bundle, created_at, updated_at) VALUES ($1, $2, $3, $4, 'recorded', 'jws', $5, $6, $7)`,
				in.id, tenant, identityID, in.status, in.evidence, in.created, in.updated); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	f, err := s.CustomerAssuranceFacts(ctx, tenant, now, from, through, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Active: soon, later, expired (the ephemeral one is left out); owned: soon, expired.
	if f.ActiveCertificates != 3 || f.OwnedCertificates != 2 || f.ExpiredActive != 1 || f.Expiring != 1 {
		t.Fatalf("inventory = active %d owned %d expired %d expiring %d", f.ActiveCertificates, f.OwnedCertificates, f.ExpiredActive, f.Expiring)
	}
	if len(f.ExpiringSoonest) != 1 || f.ExpiringSoonest[0].Subject != "CN=soon.example.test" || f.ExpiringSoonest[0].Owner != "payments" {
		t.Fatalf("expiring soonest = %+v", f.ExpiringSoonest)
	}
	if len(f.UnownedSoonest) != 1 || f.UnownedSoonest[0].Subject != "CN=later.example.test" {
		t.Fatalf("unowned = %+v", f.UnownedSoonest)
	}
	if f.AddedInPeriod != 6 || f.RenewedInPeriod != 1 || f.RevokedInPeriod != 1 {
		t.Fatalf("period = added %d renewed %d revoked %d", f.AddedInPeriod, f.RenewedInPeriod, f.RevokedInPeriod)
	}
	if f.FailedRenewals != 1 || f.FailedDeliveries != 2 || f.VerifiedDeliveries != 1 || len(f.Failures) != 3 ||
		f.Failures[0].Kind != "renewal" || f.Failures[0].Reason != "ACME order rejected" || f.Failures[0].Subject != identityID ||
		f.Failures[1].Kind != "delivery" || f.Failures[1].Via != "apache" || f.Failures[1].Subject != "edge" {
		t.Fatalf("failures = renewals %d deliveries %d verified %d %+v", f.FailedRenewals, f.FailedDeliveries, f.VerifiedDeliveries, f.Failures)
	}
	if f.EndpointObservations != 3 || f.EndpointsMatching != 1 || f.EndpointsMismatched != 1 || f.EndpointsUnreachable != 1 || f.EndpointsCheckedInPeriod != 2 {
		t.Fatalf("endpoints = %d/%d/%d/%d checked %d", f.EndpointObservations, f.EndpointsMatching, f.EndpointsMismatched, f.EndpointsUnreachable, f.EndpointsCheckedInPeriod)
	}
	// In the period: the still-open one from before it, the one closed in it and
	// the fleet run opened in it; the one closed before it is out.
	if f.IncidentsInPeriod != 3 || f.IncidentsOpenedInPeriod != 2 || f.IncidentsOpen != 2 || len(f.Incidents) != 3 ||
		f.Incidents[0].Kind != "issuer_compromise" || f.Incidents[1].Evidence != "header.payload.signature" {
		t.Fatalf("incidents = in %d opened %d open %d %+v", f.IncidentsInPeriod, f.IncidentsOpenedInPeriod, f.IncidentsOpen, f.Incidents)
	}
	if _, err := s.CustomerAssuranceFacts(ctx, tenant, now, through, from, time.Hour); err == nil {
		t.Fatal("an empty period was accepted")
	}
	otherFacts, err := s.CustomerAssuranceFacts(ctx, other, now, from, through, 30*24*time.Hour)
	if err != nil || otherFacts.ActiveCertificates != 1 || otherFacts.FailedRenewals != 0 || otherFacts.IncidentsInPeriod != 0 {
		t.Fatalf("the other tenant's facts = %+v, %v", otherFacts, err)
	}
}
