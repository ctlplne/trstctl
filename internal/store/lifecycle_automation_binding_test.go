// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Same owner and SAN are common during CA replacement. A short-lived successor
// must not inherit the old CA's later expiry in the operator's automation plan.
func TestLifecycleAutomationUsesIdentityBoundServedCertificate(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "same service owner"})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture is stored in PostgreSQL, whose timestamp precision is microseconds.
	now := time.Now().UTC().Truncate(time.Microsecond)
	var identities []store.Identity
	var certs []store.Certificate
	// These are relational read-model fixtures, not signing or live TLS proof.
	for i, lifetime := range []time.Duration{10 * time.Minute, 90 * 24 * time.Hour} {
		identity, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA,
			Kind: store.KindX509Certificate, Name: "shared.example.test", OwnerID: owner.ID})
		if err != nil {
			t.Fatal(err)
		}
		identity.Status = "deployed"
		if err := s.UpsertIdentity(ctx, identity); err != nil {
			t.Fatal(err)
		}
		end := now.Add(lifetime)
		cert, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
			Subject: "CN=shared.example.test", SANs: []string{"shared.example.test"}, Issuer: fmt.Sprintf("CA %d", i),
			Serial: fmt.Sprint(i + 1), Fingerprint: strings.Repeat(fmt.Sprint(i+1), 64),
			Source: "issued", Status: "active", NotBefore: &now, NotAfter: &end})
		if err != nil {
			t.Fatal(err)
		}
		identities, certs = append(identities, identity), append(certs, cert)
	}
	for i, fixture := range []struct {
		identity, certificate int
		status                string
	}{{0, 0, "verified"}, {1, 1, "verified"}, {0, 1, "verify_failed"}} {
		at := now.Add(time.Duration(i) * time.Second)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: fmt.Sprintf("33333333-3333-4333-8333-%012d", i+1), TenantID: tenantA,
				IdentityID: &identities[fixture.identity].ID, Destination: "connector.deploy", Connector: "caddy", Target: "same-target",
				Fingerprint: certs[fixture.certificate].Fingerprint, Status: fixture.status,
				IdempotencyKey: fmt.Sprintf("delivery-%d", i), CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil || len(rows) != 2 {
		t.Fatalf("inventory count=%d error=%v", len(rows), err)
	}
	for _, row := range rows {
		for i, identity := range identities {
			if row.IdentityID == identity.ID && (row.CertificateID != certs[i].ID || !row.CertificateEnd.Equal(*certs[i].NotAfter)) {
				t.Fatalf("identity %s plan uses certificate %s expiring %v; exact deployed certificate is %s expiring %v",
					identity.ID, row.CertificateID, row.CertificateEnd, certs[i].ID, certs[i].NotAfter)
			}
		}
	}
	// A restore changes the served leaf only after the executor proves success.
	// In particular, the older leaf's earlier expiry must become authoritative.
	// Issuance keeps the predecessor as superseded even when an executor restores it.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.SetCertificateSupersededTx(ctx, tx, tenantA, certs[0].Fingerprint, now)
	}); err != nil {
		t.Fatal(err)
	}
	for i, step := range []struct {
		destination, status string
		certificate, want   int
	}{
		{"connector.rollback", "rollback_queued", 0, 1},
		{"connector.rollback", "rollback_failed", 0, 1},
		{"connector.rollback", "rolled_back", 0, 0},
		{"connector.deploy", "verify_failed", 1, 0},
		{"connector.deploy", "verified", 1, 1},
		{"connector.rollback", "rolled_back", 0, 1},
	} {
		at := now.Add(time.Duration(i+10) * time.Second)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if i == 5 {
				// Even a newer retained receipt must never revive a revoked leaf.
				if err := s.SetCertificateRevokedTx(ctx, tx, tenantA, certs[0].Fingerprint, "keyCompromise", at); err != nil {
					return err
				}
			}
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: fmt.Sprintf("44444444-4444-4444-8444-%012d", i+1), TenantID: tenantA,
				IdentityID: &identities[1].ID, Destination: step.destination, Connector: "caddy", Target: "same-target",
				Fingerprint: certs[step.certificate].Fingerprint, Status: step.status,
				IdempotencyKey: fmt.Sprintf("restore-step-%d", i), CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatal(err)
		}
		fingerprint, found, err := s.LatestDeployedCertificateFingerprintForIdentity(ctx, tenantA, identities[1].ID)
		if err != nil || !found || fingerprint != certs[step.want].Fingerprint {
			t.Fatalf("after %s/%s scheduler selected %q found=%v error=%v; want %q", step.destination, step.status, fingerprint, found, err, certs[step.want].Fingerprint)
		}
		rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
		// Identity 0 retains a failed delivery to show as blocked, even
		// though its older certificate is superseded. Identity 1 stays bound
		// to its exact served leaf through each pending and failed step.
		if err != nil || len(rows) != 2 {
			t.Fatalf("after restore inventory count=%d error=%v", len(rows), err)
		}
		seenBound := false
		for _, row := range rows {
			if row.IdentityID == identities[0].ID {
				if !row.DeliveryUnverified {
					t.Fatalf("failed delivery disappeared for identity %s", row.IdentityID)
				}
				continue
			}
			seenBound = true
			if row.IdentityID != identities[1].ID || row.CertificateID != certs[step.want].ID || !row.CertificateEnd.Equal(*certs[step.want].NotAfter) {
				t.Fatalf("after %s/%s plan selected %s expiring %v; want %s expiring %v", step.destination, step.status, row.CertificateID, row.CertificateEnd, certs[step.want].ID, certs[step.want].NotAfter)
			}
		}
		if !seenBound {
			t.Fatal("identity-bound served leaf disappeared")
		}
	}
	if fingerprint, found, err := s.LatestDeployedCertificateFingerprintForIdentity(ctx, tenantB, identities[1].ID); err != nil || found || fingerprint != "" {
		t.Fatalf("foreign tenant resolved certificate=%q found=%v error=%v", fingerprint, found, err)
	}
}

func TestLifecycleAutomationShowsFailedDeliveryWithoutBorrowingAnotherCertificate(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "failed delivery owner"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA, Kind: store.KindX509Certificate,
		Name: "failed-delivery.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	identity.Status = "deployed"
	if err := s.UpsertIdentity(ctx, identity); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	end := now.Add(10 * time.Minute)
	failed, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
		Subject: "CN=failed-delivery.example.test", SANs: []string{identity.Name}, Issuer: "CA 1",
		Serial: "failed", Fingerprint: strings.Repeat("a", 64), Source: "issued", Status: "active",
		NotBefore: &now, NotAfter: &end})
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(90 * 24 * time.Hour)
	if _, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
		Subject: "CN=failed-delivery.example.test", SANs: []string{identity.Name}, Issuer: "CA 2",
		Serial: "other", Fingerprint: strings.Repeat("b", 64), Source: "issued", Status: "active",
		NotBefore: &now, NotAfter: &later}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
			ID: "66666666-6666-4666-8666-666666666666", TenantID: tenantA, IdentityID: &identity.ID,
			Destination: "connector.deploy", Connector: "caddy", Target: "failed-target",
			Fingerprint: failed.Fingerprint, Status: "failed", IdempotencyKey: "failed-delivery",
			CreatedAt: now, UpdatedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil || len(rows) != 1 || rows[0].CertificateID != failed.ID || !rows[0].DeliveryUnverified {
		t.Fatalf("failed delivery must be visible and bound to its own certificate: rows=%+v err=%v", rows, err)
	}
}

// The event log orders observations even when PostgreSQL rounds their wall
// clock times to the same microsecond. UUID order carries no temporal meaning.
func TestLifecycleAutomationOrdersSameTimestampReceiptsByEventSequence(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "same timestamp owner"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA, Kind: store.KindX509Certificate,
		Name: "same-timestamp.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	identity.Status = "deployed"
	if err := s.UpsertIdentity(ctx, identity); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	end := at.Add(time.Hour)
	served, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
		Subject: identity.Name, SANs: []string{identity.Name}, Issuer: "local", Serial: "served-same-time",
		Fingerprint: strings.Repeat("a", 64), Source: "issued", Status: "active", NotBefore: &at, NotAfter: &end})
	if err != nil {
		t.Fatal(err)
	}
	failedEnd := at.Add(24 * time.Hour)
	successor, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
		Subject: identity.Name, SANs: []string{identity.Name}, Issuer: "local", Serial: "successor-same-time",
		Fingerprint: strings.Repeat("b", 64), Source: "issued", Status: "active", NotBefore: &at, NotAfter: &failedEnd})
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range []struct {
		id, status, fingerprint string
		sequence                uint64
	}{
		{"77777777-7777-4777-8777-000000000003", "verified", served.Fingerprint, 10},
		{"77777777-7777-4777-8777-000000000002", "verify_failed", successor.Fingerprint, 11},
	} {
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: receipt.id, TenantID: tenantA, IdentityID: &identity.ID, Destination: "connector.deploy",
				Connector: "apache", Target: "same-timestamp", Fingerprint: receipt.fingerprint,
				Status: receipt.status, IdempotencyKey: receipt.id, EventSequence: receipt.sequence,
				CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	blocked, err := s.HasUnverifiedConnectorDeliveryAfterConfirmedServe(ctx, tenantA, identity.ID)
	if err != nil || !blocked {
		t.Fatalf("later failed event must block unattended renewal: blocked=%v err=%v", blocked, err)
	}
	rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil || len(rows) != 1 || !rows[0].DeliveryUnverified || rows[0].CertificateID != served.ID {
		t.Fatalf("same-time failure must stay visible beside last served leaf: rows=%+v err=%v", rows, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
			ID: "77777777-7777-4777-8777-000000000001", TenantID: tenantA, IdentityID: &identity.ID,
			Destination: "connector.deploy", Connector: "apache", Target: "same-timestamp",
			Fingerprint: successor.Fingerprint, Status: "verified", IdempotencyKey: "same-time-recovery",
			EventSequence: 12, CreatedAt: at, UpdatedAt: at,
		})
	}); err != nil {
		t.Fatal(err)
	}
	blocked, err = s.HasUnverifiedConnectorDeliveryAfterConfirmedServe(ctx, tenantA, identity.ID)
	if err != nil || blocked {
		t.Fatalf("later verified event must clear hold: blocked=%v err=%v", blocked, err)
	}
	rows, err = s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil || len(rows) != 1 || rows[0].DeliveryUnverified || rows[0].CertificateID != successor.ID {
		t.Fatalf("same-time recovery must select successor: rows=%+v err=%v", rows, err)
	}
}

// The host can install a successor but fail its listener probe. The last
// confirmed rollback still determines the renewal clock, while the new failure
// must remain visible and block unattended action.
func TestLifecycleAutomationFlagsFailedVerificationAfterConfirmedRollback(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "failed verifier owner"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA, Kind: store.KindX509Certificate,
		Name: "failed-verifier.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	identity.Status = "renewal_failed"
	if err := s.UpsertIdentity(ctx, identity); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	end := now.Add(time.Hour)
	served, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA,
		Subject: identity.Name, SANs: []string{identity.Name}, Issuer: "local", Serial: "served",
		Fingerprint: strings.Repeat("a", 64), Source: "discovery:network", IssuanceIdempotencyKey: "agentcsr:prior:fixture",
		Status: "superseded", NotBefore: &now, NotAfter: &end})
	if err != nil {
		t.Fatal(err)
	}
	failedEnd := now.Add(30 * 24 * time.Hour)
	failed, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
		Subject: identity.Name, SANs: []string{identity.Name}, Issuer: "local", Serial: "failed",
		Fingerprint: strings.Repeat("b", 64), Source: "issued", Status: "active", NotBefore: &now, NotAfter: &failedEnd})
	if err != nil {
		t.Fatal(err)
	}
	for i, step := range []struct{ destination, status, reason, fingerprint, key string }{
		{"connector.rollback", "rolled_back", "rolled_back_and_reverified", served.Fingerprint, "restore"},
		{"connector.deploy", "delivered", "agent_delivered_verification_failed", failed.Fingerprint, "renew"},
		{"connector.deploy", "verify_failed", "endpoint_unreachable", failed.Fingerprint, "renew:verified"},
	} {
		at := now.Add(time.Duration(i) * time.Second)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: fmt.Sprintf("66666666-6666-4666-8666-%012d", i+1), TenantID: tenantA,
				IdentityID: &identity.ID, Destination: step.destination, Connector: "apache", Target: "failed-verifier",
				Fingerprint: step.fingerprint, Status: step.status, Reason: step.reason, IdempotencyKey: step.key,
				CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil || len(rows) != 1 || rows[0].CertificateID != served.ID || !rows[0].DeliveryUnverified {
		t.Fatalf("plan must show last confirmed leaf and current verifier failure: rows=%+v err=%v", rows, err)
	}
	candidates, err := s.ListRenewalIdentityCandidates(ctx, tenantA, now.Add(2*time.Hour), now)
	if err != nil || len(candidates) != 1 || candidates[0].Certificate.ID != served.ID {
		t.Fatalf("scheduler prefilter lost rediscovered restored leaf: candidates=%+v err=%v", candidates, err)
	}
	blocked, err := s.HasUnverifiedConnectorDeliveryAfterConfirmedServe(ctx, tenantA, identity.ID)
	if err != nil || !blocked {
		t.Fatalf("unattended retry must wait for repair: blocked=%v err=%v", blocked, err)
	}
	at := now.Add(3 * time.Second)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
			ID: "66666666-6666-4666-8666-000000000004", TenantID: tenantA,
			IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "apache", Target: "failed-verifier",
			Fingerprint: failed.Fingerprint, Status: "verified", Reason: "endpoint_serving_deployed_identity",
			IdempotencyKey: "recovery:verified", CreatedAt: at, UpdatedAt: at,
		})
	}); err != nil {
		t.Fatal(err)
	}
	blocked, err = s.HasUnverifiedConnectorDeliveryAfterConfirmedServe(ctx, tenantA, identity.ID)
	if err != nil || blocked {
		t.Fatalf("confirmed recovery must clear unattended hold: blocked=%v err=%v", blocked, err)
	}
}

// A revoked served leaf must not make a different identity's active certificate
// with the same owner and SAN look like this identity's renewal source.
func TestLifecycleAutomationDoesNotBorrowCertificateAfterServedLeafRevoked(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "revoked shared service owner"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	var identities []store.Identity
	var certs []store.Certificate
	for i, lifetime := range []time.Duration{10 * time.Minute, 30 * 24 * time.Hour} {
		identity, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA,
			Kind: store.KindX509Certificate, Name: "revoked-shared.example.test", OwnerID: owner.ID})
		if err != nil {
			t.Fatal(err)
		}
		identity.Status = "deployed"
		if err := s.UpsertIdentity(ctx, identity); err != nil {
			t.Fatal(err)
		}
		end := now.Add(lifetime)
		cert, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
			Subject: "CN=revoked-shared.example.test", SANs: []string{identity.Name}, Issuer: fmt.Sprintf("CA %d", i),
			Serial: fmt.Sprint(i + 11), Fingerprint: strings.Repeat(fmt.Sprint(i+3), 64),
			Source: "issued", Status: "active", NotBefore: &now, NotAfter: &end})
		if err != nil {
			t.Fatal(err)
		}
		identities, certs = append(identities, identity), append(certs, cert)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: fmt.Sprintf("55555555-5555-4555-8555-%012d", i+1), TenantID: tenantA,
				IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "nginx", Target: "same-target",
				Fingerprint: cert.Fingerprint, Status: "verified", IdempotencyKey: fmt.Sprintf("revoked-delivery-%d", i),
				CreatedAt: now, UpdatedAt: now,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.SetCertificateRevokedTx(ctx, tx, tenantA, certs[1].Fingerprint, "keyCompromise", now.Add(time.Second))
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].IdentityID != identities[0].ID || rows[0].CertificateID != certs[0].ID {
		t.Fatalf("revoked identity borrowed another identity's certificate: rows=%+v", rows)
	}
}

func TestLifecycleAutomationPlanExcludesIdentityWithActiveEndpointReplacement(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "replacement plan owner"})
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA, Kind: store.KindX509Certificate,
		Name: "replacement-plan.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	original.Status = "deployed"
	if err := s.UpsertIdentity(ctx, original); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	nb, na := now.Add(-5*time.Minute), now.Add(10*time.Minute)
	if _, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
		Subject: "CN=replacement-plan.example.test", SANs: []string{original.Name}, Issuer: "old external CA",
		Serial: "01", Fingerprint: strings.Repeat("a", 64), Source: "issued", Status: "active", NotBefore: &nb, NotAfter: &na}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil || len(rows) != 1 || rows[0].IdentityID != original.ID {
		t.Fatalf("before replacement plan rows=%+v error=%v", rows, err)
	}
	replacement, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA, Kind: store.KindX509Certificate,
		Name: original.Name, OwnerID: owner.ID,
		Attributes: []byte(fmt.Sprintf(`{"endpoint_replaces_identity_id":%q}`, original.ID))})
	if err != nil {
		t.Fatal(err)
	}
	replacement.Status = "issued"
	if err := s.UpsertIdentity(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	rows, err = s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil || len(rows) != 0 {
		t.Fatalf("plan offered obsolete predecessor for renewal after replacement: rows=%+v error=%v", rows, err)
	}
}
