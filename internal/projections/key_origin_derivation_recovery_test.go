// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Owner decision 2026-10-24: certificates issued before their path recorded
// custody get the origin their retained issuance event proves, marked as
// derived and naming that event; a certificate no rule proves stays
// unrecorded, and a recorded origin always replaces a derived one. The
// derivation is a function of the event alone, so a warm upgrade from a
// projector that did not derive, a snapshot restore and a rebuild all agree.
func TestPreCustodyCertificatesGetDerivedKeyOriginsThatSurviveRecovery(t *testing.T) {
	s, log := newStore(t), openLog(t)
	ctx := t.Context()
	p := projections.New(s)
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Derived origins")})
	july := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	october := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	record := func(id, fingerprint, source, key string, at time.Time, keyOrigin string) string {
		t.Helper()
		data, err := json.Marshal(projections.CertificateRecorded{
			ID: id, Subject: "CN=" + fingerprint, Fingerprint: fingerprint, Source: source,
			IssuanceIdempotencyKey: key, KeyOrigin: keyOrigin, CertificateDER: []byte("der-" + fingerprint),
		})
		if err != nil {
			t.Fatal(err)
		}
		eventID := uuid.NewString()
		mustAppend(t, log, events.Event{ID: eventID, TenantID: tenantA, Type: projections.EventCertificateRecorded, Time: at, Data: data})
		return eventID
	}
	acmeID, identityID, lateID, replacedID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	acmeEvent := record(acmeID, "fp-acme", "protocol:acme", "protocol-issue:acme:"+strings.Repeat("c", 64), july, "")
	identityEvent := record(identityID, "fp-identity", "issued", "issue:transition:k1", july, "")
	record(lateID, "fp-scep-late", "protocol:scep", "protocol-issue:scep:tx-1", october, "")
	record(replacedID, "fp-replaced", "issued", "issue:transition:k2", july, "")
	record(uuid.NewString(), "fp-replaced", "issued", "issue:transition:k2", october, string(custody.OriginRequester))
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertOrigins := func(stage string) {
		t.Helper()
		for _, want := range []struct {
			id, origin, rule, proof string
		}{
			{acmeID, "requester", string(custody.DerivedProtocolEnrollment), acmeEvent},
			{identityID, "control_plane", string(custody.DerivedIdentityIssuance), identityEvent},
			{lateID, "", "", ""},
			{replacedID, "requester", "", ""},
		} {
			cert, err := s.GetCertificate(ctx, tenantA, want.id)
			if err != nil {
				t.Fatalf("%s: read %s: %v", stage, want.id, err)
			}
			if cert.KeyOrigin != want.origin || cert.KeyOriginDerivation != want.rule || cert.KeyOriginProofEventID != want.proof {
				t.Fatalf("%s: %s custody = origin %q rule %q proof %q; want %q %q %q", stage, cert.Fingerprint,
					cert.KeyOrigin, cert.KeyOriginDerivation, cert.KeyOriginProofEventID, want.origin, want.rule, want.proof)
			}
		}
	}
	assertOrigins("first projection")

	// A warm upgrade from a projector that did not derive origins: its rows
	// carry none, and its ordinary checkpoint already covers their events.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET key_origin = '', key_origin_derivation = '', key_origin_proof_event_id = ''
			WHERE tenant_id = $1 AND key_origin_derivation <> ''`, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE projection_checkpoint
		SET key_origin_derivation_checked_through = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertOrigins("warm upgrade recovery")
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, s)
	if restored, err := p.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("snapshot restore: restored=%v err=%v", restored, err)
	}
	assertOrigins("snapshot restore")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	assertOrigins("event rebuild")
}
