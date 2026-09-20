// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func brokerRecordedFixture() projections.CertificateRecorded {
	nb, na := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour)
	ownerID := "00000000-0000-0000-0000-00000000b001"
	return projections.CertificateRecorded{
		ID: "00000000-0000-0000-0000-00000000c001", OwnerID: &ownerID,
		Subject: "original certificate subject", Fingerprint: "broker-public-fingerprint", Serial: "01",
		Source: "broker:stub_broker", NotBefore: &nb, NotAfter: &na,
		IssuanceIdempotencyKey: "broker-issue:projection-fixture", IssuanceRequestBinding: strings.Repeat("a", 64),
		BrokerIssuance: &store.BrokerIssuance{AgentID: "privacy-broker-agent", Subject: "verified-workload",
			OwnerID: ownerID, Method: "stub_broker", Scopes: []string{"tool:inventory.read"},
			RequestedTTLSeconds: 120, EffectiveTTLSeconds: 120},
	}
}

func brokerRecordedEvent(t *testing.T, payload projections.CertificateRecorded) events.Event {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return events.Event{ID: uuid.NewString(), Type: projections.EventCertificateRecorded, TenantID: tenantA, Time: time.Now().UTC(), Data: raw}
}

func TestBrokerFactsSurviveRediscoverySnapshotAndEventOnlyRebuild(t *testing.T) {
	s, log := newStore(t), openLog(t)
	p := projections.New(s)
	ctx := t.Context()
	fixture := brokerRecordedFixture()
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Broker tenant")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated(*fixture.OwnerID, "original owner")})
	mustAppend(t, log, brokerRecordedEvent(t, fixture))
	observation := fixture
	observation.ID = "00000000-0000-0000-0000-00000000c002"
	observation.Subject, observation.Source, observation.OwnerID = "later observed subject", "discovery:network", nil
	observation.BrokerIssuance, observation.IssuanceRequestBinding, observation.IssuanceIdempotencyKey = nil, "", ""
	mustAppend(t, log, brokerRecordedEvent(t, observation))
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertOriginal := func(stage string) {
		t.Helper()
		certs, err := s.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantA, fixture.IssuanceIdempotencyKey)
		if err != nil || len(certs) != 1 {
			t.Fatalf("%s: certificates=%d error=%v", stage, len(certs), err)
		}
		c := certs[0]
		if c.ID != fixture.ID || c.Subject != observation.Subject || c.Source != observation.Source || c.OwnerID != nil ||
			c.IssuanceRequestBinding != fixture.IssuanceRequestBinding || !reflect.DeepEqual(c.BrokerIssuance, fixture.BrokerIssuance) {
			t.Fatalf("%s: rediscovery replaced original broker facts or duplicated the shared certificate", stage)
		}
		if _, err := s.GetCertificate(ctx, tenantB, fixture.ID); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("neighbor tenant could read certificate")
		}
	}
	assertOriginal("initial projection")
	if store.SnapshotFormatVersion < 36 {
		t.Fatal("older snapshots can silently lose broker facts")
	}
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, s)
	if _, err := p.RestoreFromSnapshot(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertOriginal("snapshot restore")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertOriginal("event-only rebuild")

	// A conflicting second issuance must roll back every inventory change too.
	changed := fixture
	metadata := *fixture.BrokerIssuance
	metadata.Scopes = []string{"tool:inventory.write"}
	changed.BrokerIssuance, changed.Subject = &metadata, "must not commit"
	conflicting, err := log.Append(ctx, brokerRecordedEvent(t, changed))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, conflicting); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("conflicting broker facts: got %v, want explicit command conflict", err)
	}
	assertOriginal("rejected conflicting fact")
}

func TestBrokerV35SnapshotCannotSkipIssuanceFacts(t *testing.T) {
	s, log := newStore(t), openLog(t)
	p, ctx := projections.New(s), t.Context()
	fixture := brokerRecordedFixture()
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Broker upgrade")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated(*fixture.OwnerID, "original owner")})
	mustAppend(t, log, brokerRecordedEvent(t, fixture))
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	// Deliberately make the disposable test snapshot look like v35: the
	// certificate exists, but its original broker facts were not captured.
	// Keeping the covered offset would otherwise skip the event that owns them.
	// The current runtime installs an additional version floor. Remove it only
	// inside this disposable test database to emulate bytes from an older backup.
	if _, err := s.SystemPool().Exec(ctx, `ALTER TABLE read_model_snapshots DROP CONSTRAINT read_model_snapshots_format_floor_v22`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE read_model_snapshots SET format_version = 35,
		payload = jsonb_set(payload, '{certificates}',
			(SELECT jsonb_agg(item - 'broker_issuance') FROM jsonb_array_elements(payload->'certificates') AS item))
		WHERE tenant_id = $1`, tenantA); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, s)
	if offset, err := s.LatestSnapshotOffset(ctx); !errors.Is(err, store.ErrNoSnapshot) || offset != 0 {
		t.Fatalf("v35 snapshot must not advance the read checkpoint: offset=%d err=%v", offset, err)
	}
	if restored, err := p.RestoreFromSnapshot(ctx, log); err != nil || restored {
		t.Fatalf("v35 snapshot must request event replay, not restore incomplete facts: restored=%v err=%v", restored, err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	cert, err := s.GetCertificate(ctx, tenantA, fixture.ID)
	if err != nil || !reflect.DeepEqual(cert.BrokerIssuance, fixture.BrokerIssuance) || cert.IssuanceRequestBinding != fixture.IssuanceRequestBinding {
		t.Fatalf("replay after an old snapshot lost original broker facts or anti-reissue binding: %v", err)
	}
}

func TestBrokerFactsAreIncludedInPrivacyExportErasureAndRetention(t *testing.T) {
	for _, operation := range []string{"erasure", "retention"} {
		t.Run(operation, func(t *testing.T) {
			s, log := newStore(t), openLog(t)
			p := projections.New(s)
			ctx := t.Context()
			fixture := brokerRecordedFixture()
			mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Broker tenant")})
			mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated(*fixture.OwnerID, "unrelated owner name")})
			mustAppend(t, log, brokerRecordedEvent(t, fixture))
			if err := p.ProjectCatchUp(ctx, log); err != nil {
				t.Fatal(err)
			}
			export, err := s.SelectPrivacySubjectExport(ctx, tenantA, fixture.BrokerIssuance.AgentID)
			if err != nil || len(export.Certificates) != 1 || export.Certificates[0].BrokerIssuance == nil {
				t.Fatalf("metadata-only subject is absent from privacy export: %v", err)
			}
			if operation == "erasure" {
				selected, err := s.SelectPrivacySubjectErasure(ctx, tenantA, fixture.BrokerIssuance.AgentID)
				if err != nil || len(selected.Selectors.CertificateRefs) != 1 {
					t.Fatalf("metadata-only subject is absent from erasure selection: %v", err)
				}
				if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, selected) }); err != nil {
					t.Fatal(err)
				}
			} else {
				// Store-level projector test: the cutoff is deliberately after this
				// fixture's expiry, without changing the process clock or a live stack.
				run := store.PrivacyRetentionRun{TenantID: tenantA, RunID: "00000000-0000-0000-0000-00000000d001", EnforcedAt: time.Now().UTC(),
					Cutoffs: store.PrivacyRetentionCutoffs{CertificateTerminalBefore: fixture.NotAfter.Add(time.Hour)}}
				if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacyRetentionEnforcedTx(ctx, tx, run) }); err != nil {
					t.Fatal(err)
				}
			}
			c, err := s.GetCertificate(ctx, tenantA, fixture.ID)
			if err != nil || c.BrokerIssuance != nil || c.IssuanceRequestBinding != fixture.IssuanceRequestBinding {
				t.Fatalf("%s must clear broker facts but keep the non-PII anti-reissue binding: %v", operation, err)
			}
		})
	}
}

func TestBrokerIssuancePrivacyPolicyRedactsIdentityPathsAndRejectsProofFields(t *testing.T) {
	payload := brokerRecordedEvent(t, brokerRecordedFixture()).Data
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(payload, tenantA, "privacy-broker-agent", projections.EventCertificateRecorded, 1)
	if err != nil || !changed || strings.Contains(string(rewritten), "privacy-broker-agent") {
		t.Fatalf("broker identity not pseudonymized: changed=%v err=%v", changed, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["broker_issuance"].(map[string]any)["payload_base64"] = "must-never-be-stored"
	bad, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := events.PseudonymizeEventDataForSubject(bad, tenantA, "privacy-broker-agent", projections.EventCertificateRecorded, 1); err == nil {
		t.Fatal("closed broker event shape accepted raw proof field")
	}
}
