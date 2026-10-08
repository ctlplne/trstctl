// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"strings"
	"testing"
	"time"

	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A real signed CRL in the retained log closes an already completed publication
// command after outbox GC. Without that exact proof, the rebuild leaves a pending
// repair command. This exercises real PostgreSQL and embedded JetStream.
func TestManagedCRLRebuildKeepsPendingAndDoesNotResurrectCompleted(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	ca, leafDER, _, serial := internalCA(t, "replay.example.test")
	caInfo, err := certinfo.Inspect(ca.CertificateDER())
	if err != nil {
		t.Fatal(err)
	}
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	const caID = "10000000-0000-4000-8000-000000000b01"
	const ceremonyID = "10000000-0000-4000-8000-000000000b02"
	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "CRL replay"})
	appendJSONEvent(t, log, projections.EventCACeremonyStarted, tenantA, projections.CACeremonyStarted{
		CeremonyID: ceremonyID, Purpose: "root:crl-replay", Threshold: 1, Opener: "operator",
	})
	appendJSONEvent(t, log, projections.EventCACeremonyApproved, tenantA, projections.CACeremonyApproved{
		CeremonyID: ceremonyID, Custodian: "custodian",
	})
	appendVersionedJSONEvent(t, log, projections.EventCARootCreated, tenantA,
		projections.CAAuthorityCreatedEventSchemaVersion, projections.CAAuthorityCreated{
			CAID: caID, CommonName: "CRL Replay CA", Kind: "root",
			CertificatePEM: string(ca.CertificatePEM()), SignerHandle: "test-crl-ca",
			Serial: caInfo.SerialNumber, NotAfter: caInfo.NotAfter, CeremonyID: ceremonyID,
		})
	issued := appendVersionedJSONEvent(t, log, projections.EventCAEndEntityIssued, tenantA,
		projections.CAIssuedCertificateEvidenceSchemaVersion, struct {
			projections.CAIssuedCertificate
			Subject string `json:"subject"`
		}{
			CAIssuedCertificate: projections.CAIssuedCertificate{
				CAID: caID, Serial: serial, CertificateDER: leafDER,
				Fingerprint: leafInfo.SHA256Fingerprint,
			},
			Subject: leafInfo.Subject,
		})
	projector := projections.New(st)
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("pending issuance rebuild: %v", err)
	}
	assertCRLReplayCommandCount(t, st, 1)

	// A full, CA-signed CRL was then published; the original command was
	// delivered and its outbox row garbage collected before disaster recovery.
	now := time.Now().UTC().Truncate(time.Second)
	crlDER, err := ca.CreateCRL(nil, 1, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	appendVersionedJSONEvent(t, log, projections.EventCRLPublished, tenantA,
		projections.CRLPublishedEventSchemaVersion, projections.CRLPublished{
			CAID: caID, Number: 1, DER: crlDER, Kind: store.CRLKindFull,
			ThisUpdate: now, NextUpdate: now.Add(24 * time.Hour), ShardCount: 1,
		})
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
		tenantA, store.CertificateCRLPublicationDestination,
		store.CertificateCRLPublicationDestination+":"+issued.ID+":"+caID); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("completed issuance rebuild: %v", err)
	}
	assertCRLReplayCommandCount(t, st, 0)
	crl, found, err := st.LatestCRL(ctx, tenantA, caID)
	if err != nil || !found || string(crl.DER) != string(crlDER) {
		t.Fatalf("signed published CRL did not survive rebuild: found=%t err=%v", found, err)
	}

	// Revocation is a separate command. The initial empty CRL must not make its
	// publication look completed, even though it was signed by the same CA.
	const reason = "cessationOfOperation"
	appendVersionedJSONEvent(t, log, projections.EventCertificateRevocationBatchApplied, tenantA,
		1, projections.CertificateRevocationBatchApplied{
			RequestBinding: strings.Repeat("a", 64), Reason: reason,
			Items: []projections.CertificateRevocationItem{{
				ID: projections.LegacyManagedCAInventoryID(issued), Matched: true,
				Status: "revoked", Fingerprint: leafInfo.SHA256Fingerprint,
				Serial: serial, CAID: caID,
			}},
		})
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("pending revocation rebuild: %v", err)
	}
	assertCRLReplayCommandCount(t, st, 1)

	secondCRL, err := ca.CreateCRL([]cryptoca.RevokedSerial{{
		Serial: serial, RevokedAt: now, Reason: 5,
	}}, 2, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	appendVersionedJSONEvent(t, log, projections.EventCRLPublished, tenantA,
		projections.CRLPublishedEventSchemaVersion, projections.CRLPublished{
			CAID: caID, Number: 2, DER: secondCRL, Kind: store.CRLKindFull,
			ThisUpdate: now, NextUpdate: now.Add(24 * time.Hour), ShardCount: 1,
			RevokedCount: 1,
		})
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		tenantA, store.CertificateCRLPublicationDestination); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("completed revocation rebuild: %v", err)
	}
	assertCRLReplayCommandCount(t, st, 0)
}

func assertCRLReplayCommandCount(t *testing.T, st *store.Store, want int) {
	t.Helper()
	var got int
	if err := st.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		tenantA, store.CertificateCRLPublicationDestination).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("CRL publication command count = %d, want %d", got, want)
	}
}
