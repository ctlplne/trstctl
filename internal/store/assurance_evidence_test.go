// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A179: one certificate's lifecycle evidence, read in one tenant transaction:
// owner, the discovery findings for its fingerprint, every connector receipt
// (with the agent's signed receipt behind a verification), endpoint
// observations, renewal runs and replacement links — and nothing of another
// tenant's.
func TestCredentialEvidenceJoinsOneCertificatesLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "assurance owner"})
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := now.Add(-time.Hour), now.Add(30*24*time.Hour)
	// Fingerprints no other test in this package uses: the database is shared.
	fp := strings.Repeat("7a", 32)
	old, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID, Subject: "CN=old.example.test",
		SANs: []string{"svc.example.test"}, Issuer: "CN=CA", Serial: "01", Fingerprint: strings.Repeat("7b", 32), Source: "issued",
		Status: "active", NotBefore: &notBefore, NotAfter: &notAfter})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID, Subject: "CN=svc.example.test",
		SANs: []string{"svc.example.test"}, Issuer: "CN=CA", Serial: "02", Fingerprint: fp, Source: "issued",
		IssuanceIdempotencyKey: "renew:transition:assurance-key", Status: "active", NotBefore: &notBefore, NotAfter: &notAfter})
	if err != nil {
		t.Fatal(err)
	}
	identityID := "17900000-0000-4000-8000-000000000001"
	const sourceID, runID, findingID = "17900000-0000-4000-8000-0000000000a1", "17900000-0000-4000-8000-0000000000a2", "17900000-0000-4000-8000-0000000000a3"
	var jobID int64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_sources (id, tenant_id, kind, name, created_at, updated_at) VALUES ($1, $2, 'network', 'edge scan', $3, $3)`, sourceID, tenantA, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_runs (id, tenant_id, source_id, status, created_at) VALUES ($1, $2, $3, 'succeeded', $4)`, runID, tenantA, sourceID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_findings (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, discovered_at)
			VALUES ($1, $2, $3, $4, 'certificate', '10.0.0.5:443', 'tls-handshake', $5, $6)`, findingID, tenantA, runID, sourceID, fp, now); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key) VALUES ($1, 'endpoint.renew', '{}', 'assurance-deploy') RETURNING id`, tenantA).Scan(&jobID); err != nil {
			return err
		}
		for _, r := range []store.ConnectorDeliveryReceipt{
			{ID: "17900000-0000-4000-8000-0000000000b1", TenantID: tenantA, IdentityID: &identityID, Destination: "connector.deploy", Connector: "apache",
				Target: "edge", Fingerprint: fp, Status: "delivered", IdempotencyKey: "assurance-deploy", CreatedAt: now, UpdatedAt: now},
			{ID: "17900000-0000-4000-8000-0000000000b2", TenantID: tenantA, IdentityID: &identityID, Destination: "connector.deploy", Connector: "apache",
				Target: "edge", Fingerprint: fp, Status: "verified", IdempotencyKey: "assurance-deploy:verified", CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second)},
		} {
			if err := s.ApplyConnectorDeliveryRecordedTx(ctx, tx, r); err != nil {
				return err
			}
		}
		if err := s.ApplyEndpointVerificationTx(ctx, tx, store.EndpointVerification{TenantID: tenantA, EndpointID: "edge:443", Address: "svc.example.test:443",
			Vantage: "relay", Reached: true, ExpectedFingerprint: fp, ObservedFingerprint: fp, CheckedSANs: true, CheckedChain: true,
			EvidenceDigest: "sha256:transcript", AgentCommonName: "relay-dmz", LastCheckedAt: now, EventSequence: 1}); err != nil {
			return err
		}
		if err := s.ApplyRotationRunRecordedTx(ctx, tx, store.RotationRun{ID: "17900000-0000-4000-8000-0000000000c1", TenantID: tenantA, IdentityID: identityID,
			Status: "succeeded", Trigger: "scheduler", PredecessorFingerprint: old.Fingerprint, SuccessorFingerprint: fp,
			IdempotencyKey: "assurance-run", CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		// The upsert writes no replacement link; the renewal projection does.
		if _, err := tx.Exec(ctx, `UPDATE certificates SET replaces_id = $3 WHERE tenant_id = $1 AND id = $2`, tenantA, cert.ID, old.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity_transitions (tenant_id, identity_id, seq, from_state, to_state, event_type, reason, occurred_at, idempotency_key)
			VALUES ($1, $2, 4242, 'deployed', 'renewing', 'identity.renewing', 'scheduled', $3, 'assurance-key')`, tenantA, identityID, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAgentJobReceipt(ctx, tenantA, store.AgentJobReceipt{JobID: jobID, Attempt: 1, Agent: "agent-host-1", State: store.AgentJobReceiptVerified,
		Outcome: "verified", Statement: "fixture statement", Signature: "fixture signature", SignerFingerprint: "sha256:agent"}); err != nil {
		t.Fatal(err)
	}

	evidence, err := s.CredentialEvidence(ctx, tenantA, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Certificate.ID != cert.ID || evidence.Owner == nil || evidence.Owner.Name != "assurance owner" {
		t.Fatalf("certificate/owner = %+v / %+v", evidence.Certificate.ID, evidence.Owner)
	}
	if len(evidence.Discoveries) != 1 || evidence.Discoveries[0].SourceName != "edge scan" || evidence.Discoveries[0].Ref != "10.0.0.5:443" {
		t.Fatalf("discoveries = %+v", evidence.Discoveries)
	}
	if len(evidence.Deliveries) != 2 || evidence.Deliveries[0].Receipt.Status != "delivered" || evidence.Deliveries[0].SignedBy != "" {
		t.Fatalf("deliveries = %+v", evidence.Deliveries)
	}
	signed := evidence.Deliveries[1]
	if signed.Receipt.Status != "verified" || signed.SignedBy != "agent-host-1" || signed.SignerFingerprint != "sha256:agent" || signed.SignedObservedAt == nil || signed.AgentJobID != jobID {
		t.Fatalf("signed verification = %+v", signed)
	}
	if len(evidence.Endpoints) != 1 || evidence.Endpoints[0].ObservedFingerprint != fp || !evidence.Endpoints[0].CheckedChain {
		t.Fatalf("endpoints = %+v", evidence.Endpoints)
	}
	if len(evidence.Rotations) != 1 || evidence.Rotations[0].SuccessorFingerprint != fp {
		t.Fatalf("rotations = %+v", evidence.Rotations)
	}
	if evidence.Predecessor == nil || evidence.Predecessor.ID != old.ID || len(evidence.Successors) != 0 || len(evidence.Truncated) != 0 {
		t.Fatalf("links = %+v / %+v / truncated %v", evidence.Predecessor, evidence.Successors, evidence.Truncated)
	}
	predecessor, err := s.CredentialEvidence(ctx, tenantA, old.ID)
	if err != nil || len(predecessor.Successors) != 1 || predecessor.Successors[0].ID != cert.ID || len(predecessor.Rotations) != 1 {
		t.Fatalf("predecessor evidence = %+v, %v", predecessor.Successors, err)
	}

	transition, found, err := s.IdentityTransitionForIssuance(ctx, tenantA, cert.IssuanceIdempotencyKey)
	if err != nil || !found || transition.Seq != 4242 || transition.IdentityID != identityID || transition.EventType != "identity.renewing" {
		t.Fatalf("transition = %+v found=%v err=%v", transition, found, err)
	}
	if _, found, err := s.IdentityTransitionForIssuance(ctx, tenantA, "protocol-issue:other"); err != nil || found {
		t.Fatalf("a protocol issuance key named a transition: %v %v", found, err)
	}
	if _, found, err := s.IdentityTransitionForIssuance(ctx, tenantB, cert.IssuanceIdempotencyKey); err != nil || found {
		t.Fatalf("another tenant resolved tenant A's transition: %v %v", found, err)
	}
	if _, err := s.CredentialEvidence(ctx, tenantB, cert.ID); !store.IsNotFound(err) && err != pgx.ErrNoRows {
		t.Fatalf("another tenant read tenant A's certificate evidence: %v", err)
	}
}

// A179: evidence packs carry the records of the certificates whose lifecycle
// changed inside their window, newest change first, bounded, tenant-scoped.
func TestAssuranceSubjectsAreTheWindowsChangedCertificates(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	notBefore, notAfter := now.Add(-time.Hour), now.Add(30*24*time.Hour)
	seed := func(tenant, serial string) store.Certificate {
		t.Helper()
		c, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenant, Subject: "CN=" + serial, Issuer: "CN=CA", Serial: serial,
			// Fingerprints no other test in this package uses: the database is shared.
			Fingerprint: strings.Repeat(serial, 32), Source: "issued", Status: "active", NotBefore: &notBefore, NotAfter: &notAfter})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	older, newer, outside, quiet := seed(tenantA, "51"), seed(tenantA, "52"), seed(tenantA, "53"), seed(tenantA, "54")
	other := seed(tenantB, "55")
	receipt := func(tenant string, c store.Certificate, at time.Time, id string) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{ID: id, TenantID: tenant,
				Destination: "connector.deploy", Connector: "apache", Target: "edge", Fingerprint: c.Fingerprint, Status: "delivered",
				IdempotencyKey: "subjects-" + id, CreatedAt: at, UpdatedAt: at})
		}); err != nil {
			t.Fatal(err)
		}
	}
	receipt(tenantA, older, now.Add(-2*time.Hour), "17900000-0000-4000-8000-0000000000e1")
	receipt(tenantA, newer, now.Add(-time.Hour), "17900000-0000-4000-8000-0000000000e2")
	receipt(tenantA, outside, now.Add(-48*time.Hour), "17900000-0000-4000-8000-0000000000e3")
	receipt(tenantB, other, now.Add(-time.Hour), "17900000-0000-4000-8000-0000000000e4")
	_ = quiet

	ids, truncated, err := s.ListAssuranceSubjects(ctx, tenantA, now.Add(-24*time.Hour), now, 10)
	if err != nil || truncated || len(ids) != 2 || ids[0] != newer.ID || ids[1] != older.ID {

		t.Fatalf("subjects = %v truncated=%v err=%v, want [%s %s]", ids, truncated, err, newer.ID, older.ID)
	}
	ids, truncated, err = s.ListAssuranceSubjects(ctx, tenantA, now.Add(-24*time.Hour), now, 1)
	if err != nil || !truncated || len(ids) != 1 || ids[0] != newer.ID {
		t.Fatalf("bounded subjects = %v truncated=%v err=%v", ids, truncated, err)
	}
}
