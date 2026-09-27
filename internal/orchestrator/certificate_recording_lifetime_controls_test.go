// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateRecordingLegacyRenameKeepsPendingCurrentLifetime(t *testing.T) {
	st, log, projector := recordingSpine(t)
	ctx := t.Context()
	orch := orchestrator.NewOrchestrator(log, st, nil)
	leaf, _ := recordingCertificates(t)
	_, err := st.SystemPool().Exec(ctx, `CREATE FUNCTION lifetime_recording_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned lifetime rollback control'; END $$; CREATE TRIGGER lifetime_recording_fail BEFORE INSERT ON certificates FOR EACH ROW EXECUTE FUNCTION lifetime_recording_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := st.SystemPool().Exec(cleanupCtx, `DROP TRIGGER IF EXISTS lifetime_recording_fail ON certificates; DROP FUNCTION IF EXISTS lifetime_recording_fail()`); err != nil {
			t.Error(err)
		}
	}
	defer cleanup()
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RecordCertificateWithEventID(ctx, tenantA, "pending-before-legacy-rename", leaf); err == nil {
		t.Fatal("SQL fault did not reject projection")
	}
	pending, err := log.LastSequence(ctx)
	if err != nil || pending != before+1 {
		t.Fatalf("append-won SQL-lost cut=%d error=%v", pending, err)
	}
	if _, err := st.GetCertificateByFingerprint(ctx, tenantA, leaf.Fingerprint); !store.IsNotFound(err) {
		t.Fatalf("failed projection survived: %v", err)
	}
	cleanup()
	rename, err := log.Append(ctx, events.Event{ID: "legacy-rename-current-lifetime", Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegisteredJSON("renamed-current-customer")})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, rename); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetTenant(ctx, tenantA)
	if err != nil || current.EventSeq != rename.Sequence {
		t.Fatalf("rename not applied: %+v %v", current, err)
	}
	row, err := orch.RecordCertificateWithEventID(ctx, tenantA, "pending-before-legacy-rename", leaf)
	if err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != rename.Sequence {
		t.Fatalf("recovery appended duplicate: %d %v", head, err)
	}
	got, err := st.GetCertificateByFingerprint(ctx, tenantA, leaf.Fingerprint)
	if err != nil || got.ID != row.ID || !bytes.Equal(got.CertificatePEM, leaf.CertificatePEM) {
		t.Fatalf("current-lifetime recovery lost exact leaf: %+v %v", got, err)
	}
}

func TestCertificateRecordingLegacyRegistrationCannotRecoverErasedLifetime(t *testing.T) {
	st, log, projector := recordingSpine(t)
	ctx := t.Context()
	orch := orchestrator.NewOrchestrator(log, st, nil)
	leaf, _ := recordingCertificates(t)
	old, err := orch.RecordCertificateWithEventID(ctx, tenantA, "legacy-erased-recording", leaf)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{TenantID: tenantA, RegistrationIdentity: proof.EventID}); err != nil {
		t.Fatal(err)
	}
	next, err := log.Append(ctx, events.Event{ID: "legacy-new-lifetime", Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegisteredJSON("legacy-replacement")})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, next); err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RecordCertificateWithEventID(ctx, tenantA, "legacy-erased-recording", leaf); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("old command accepted/wrong refusal: %v", err)
	}
	if _, err := st.GetCertificate(ctx, tenantA, old.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("erased certificate returned: %v", err)
	}
	newer, _ := recordingCertificates(t)
	newer.IssuanceIdempotencyKey += "-legacy-replacement"
	if _, err := orch.RecordCertificateWithEventID(ctx, tenantA, "legacy-new-recording", newer); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetCertificate(ctx, tenantA, old.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("new command restored erased certificate: %v", err)
	}
}

func TestCertificateRecordingMissingRegistrationAnchorDoesNotAppend(t *testing.T) {
	for _, scenario := range []string{"missing-envelope", "neighbor-envelope"} {
		t.Run(scenario, func(t *testing.T) {
			st, log, projector := recordingSpine(t)
			ctx := t.Context()
			orch := orchestrator.NewOrchestrator(log, st, nil)
			seq := uint64(999999)
			if scenario == "neighbor-envelope" {
				ev, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantB, Data: tenantRegisteredJSON("neighbor")})
				if err != nil {
					t.Fatal(err)
				}
				if err := projector.Apply(ctx, ev); err != nil {
					t.Fatal(err)
				}
				seq = ev.Sequence
			}
			// Owned corruption injection only: the live row must be checked against its
			// exact retained tenant envelope before any recording is recovered/appended.
			if _, err := st.SystemPool().Exec(ctx, `UPDATE tenants SET event_seq=$2 WHERE tenant_id=$1`, tenantA, seq); err != nil {
				t.Fatal(err)
			}
			before, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := recordingCertificates(t)
			if _, err := orch.RecordCertificate(ctx, tenantA, leaf); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
				t.Fatalf("bad registration anchor accepted/wrong refusal: %v", err)
			}
			after, err := log.LastSequence(ctx)
			if err != nil || after != before {
				t.Fatalf("rejected command appended: %d -> %d (%v)", before, after, err)
			}
			if _, err := st.GetCertificateByFingerprint(ctx, tenantA, leaf.Fingerprint); !store.IsNotFound(err) {
				t.Fatalf("rejected command projected: %v", err)
			}
		})
	}
}
