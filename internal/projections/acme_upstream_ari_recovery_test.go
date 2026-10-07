// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestACMEUpstreamARIObservationSurvivesSnapshotAndEventRebuild(t *testing.T) {
	s, log := newStore(t), openLog(t)
	ctx := t.Context()
	p := projections.New(s)
	const certificateID = "00000000-0000-4000-8000-00000000a149"
	const fingerprint = "external-ari-recovery-fingerprint"
	issued := time.Now().UTC().Add(-time.Minute)
	expires := issued.Add(90 * 24 * time.Hour)
	appendJSON := func(eventType string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{TenantID: tenantA, Type: eventType, Data: data})
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Upstream ARI")})
	externalKey := "ari-recovery-external-issue"
	external := projections.CertificateRecorded{
		ID: certificateID, Subject: "CN=ari.example.test", Fingerprint: fingerprint,
		Source: "external-ca:pebble", NotBefore: &issued, NotAfter: &expires,
		IssuanceIdempotencyKey: externalKey, IssuanceRequestBinding: strings.Repeat("a", 64),
	}
	externalData, err := json.Marshal(external)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, log, events.Event{
		ID:       uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantA+"\x00certificate.recorded\x00"+externalKey)).String(),
		TenantID: tenantA, Type: projections.EventCertificateRecorded, Data: externalData,
	})
	external.Source = "issued"
	external.IssuanceIdempotencyKey = "issue:transition:ari-recovery"
	external.IssuanceRequestBinding = ""
	appendJSON(projections.EventCertificateRecorded, external)
	request := projections.ACMEUpstreamARIRequested{
		CertificateID: certificateID, AuthorityID: "pebble",
		ARICertificateID: "AQID.BAUG", Fingerprint: fingerprint,
	}
	appendJSON(projections.EventACMEUpstreamARIRequested, request)
	start, end := issued.Add(58*24*time.Hour), issued.Add(60*24*time.Hour)
	appendJSON(projections.EventACMEUpstreamARIObserved, projections.ACMEUpstreamARIObserved{
		CertificateID: certificateID, AuthorityID: "pebble",
		ARICertificateID: request.ARICertificateID, Fingerprint: fingerprint,
		Status: "ready", WindowStart: &start, WindowEnd: &end,
		NextPollAt: time.Now().UTC().Add(6 * time.Hour),
	})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertProjection := func(stage string) {
		t.Helper()
		cert, err := s.GetCertificate(ctx, tenantA, certificateID)
		if err != nil || cert.Source != "issued" || cert.IssuingExternalCAID != "pebble" {
			t.Fatalf("%s lost immutable external issuer: %+v, %v", stage, cert, err)
		}
		got, err := s.GetACMEUpstreamARI(ctx, tenantA, certificateID)
		if err != nil || got.Status != "ready" || got.WindowStart == nil ||
			!got.WindowStart.Equal(start) || got.WindowEnd == nil || !got.WindowEnd.Equal(end) {
			t.Fatalf("%s lost CA renewal window: %+v, %v", stage, got, err)
		}
		var outboxRows int
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox
				WHERE tenant_id=$1 AND destination=$2`, tenantA, store.ACMEUpstreamARIFetchDestination).Scan(&outboxRows)
		}); err != nil || outboxRows != 2 {
			t.Fatalf("%s outbox intents = %d, %v; want exactly two", stage, outboxRows, err)
		}
	}
	assertProjection("first projection")
	// Simulate a warm upgrade from a projector that retained only mutable
	// source. Its ordinary checkpoint already covers the original CA event.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET issuing_external_ca_id=''
			WHERE tenant_id=$1 AND id=$2`, tenantA, certificateID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE projection_checkpoint
		SET external_issuer_checked_through=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertProjection("warm upgrade recovery")
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, s)
	if restored, err := p.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("snapshot restore: restored=%v err=%v", restored, err)
	}
	assertProjection("snapshot restore")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertProjection("event rebuild")
}
