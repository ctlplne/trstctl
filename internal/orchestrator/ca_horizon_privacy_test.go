// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCAHorizonPrivacyErasureRewritesAndRecoversNotification(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Second)
	defer cancel()
	s := newStore(t)
	key, err := jose.GenerateRSASigningKey("ca-horizon-privacy")
	if err != nil {
		t.Fatal(err)
	}
	log := openLogWithOptions(t, events.WithRequiredPrivacyEventPolicies(),
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)),
		events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(key)))
	p := projections.New(s)
	appendAndProject := func(eventType string, version int, body any) events.Event {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(ctx, events.Event{
			Type: eventType, TenantID: tenantA, SchemaVersion: version, Data: data,
		})
		if err != nil {
			t.Fatalf("append %s: %v", eventType, err)
		}
		if err := p.Apply(ctx, event); err != nil {
			t.Fatalf("project %s: %v", eventType, err)
		}
		return event
	}
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegisteredJSON("ca-horizon-privacy"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	const ceremonyID = "00000000-0000-4000-8000-00000000ca11"
	appendAndProject(projections.EventCACeremonyStarted, 1, projections.CACeremonyStarted{
		CeremonyID: ceremonyID, Purpose: "root:privacy-fixture", Threshold: 1, Opener: "operator",
	})
	appendAndProject(projections.EventCACeremonyApproved, 1, projections.CACeremonyApproved{
		CeremonyID: ceremonyID, Custodian: "custodian",
	})
	const caID = "00000000-0000-4000-8000-00000000ca12"
	const subject = "alice@example.com"
	const authorityName = "QA Privacy Root"
	notAfter := time.Now().UTC().Add(30 * 30 * 24 * time.Hour)
	appendAndProject(projections.EventCARootCreated, projections.CAAuthorityCreatedEventSchemaVersion,
		projections.CAAuthorityCreated{
			CAID: caID, CommonName: authorityName, Kind: "root",
			CertificatePEM: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
			SignerHandle:   "ca-hierarchy-" + ceremonyID, Serial: "ca-horizon-privacy-root",
			NotAfter: notAfter, MaxPathLen: 1, CeremonyID: ceremonyID,
		})
	o := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s),
		orchestrator.WithTenantDataRewriteOptions(
			events.WithTenantDataContinuity(historycontinuity.NewReceiptSigner(key)),
			events.WithTenantDataCutoverPreparation(s.PrepareTenantDataCutover),
			events.WithTenantDataAuditContinuity(historycontinuity.AuditCheckpointProvider(s))))
	decision := projections.CAAuthorityHorizonAlerted{
		CAAuthorityID: caID, CommonName: authorityName, Kind: "root", NotAfter: notAfter,
		HorizonMonths: 36, MonthsRemaining: 30, RenewBy: notAfter.Add(-90 * 24 * time.Hour),
		AlertKind: notify.KindCAHorizon, AlertDetail: subject + " requires trust-anchor migration",
		Severity: notify.AlertSeverityLow,
	}
	if err := o.RecordCAAuthorityHorizonAlert(ctx, tenantA, decision); err != nil {
		t.Fatalf("record replayable horizon alert: %v", err)
	}
	idempotencyKey := "ca-horizon:" + caID + ":36"
	var outboxID int64
	var before []byte
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantA, idempotencyKey).Scan(&outboxID, &before)
	}); err != nil || !bytes.Contains(before, []byte(subject)) {
		t.Fatalf("original horizon outbox = %s, err %v", before, err)
	}
	if _, err := o.ErasePrivacySubject(ctx, tenantA, subject, "erase CA alert subject"); err != nil {
		t.Fatalf("erase horizon subject: %v", err)
	}
	outbox := orchestrator.NewOutbox(s)
	rewritten, err := outbox.Get(ctx, tenantA, outboxID)
	if err != nil || bytes.Contains(rewritten.Payload, []byte(subject)) {
		t.Fatalf("rewritten horizon outbox retained subject: %+v err %v", rewritten, err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild after horizon privacy erasure: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantA, outboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if healed, err := o.ReconcileOutbox(ctx, log); err != nil || healed != 1 {
		t.Fatalf("recover rewritten horizon command: healed %d err %v", healed, err)
	}
	var recovered []byte
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantA, idempotencyKey).Scan(&recovered)
	}); err != nil || bytes.Contains(recovered, []byte(subject)) || !bytes.Equal(recovered, rewritten.Payload) {
		t.Fatalf("recovered horizon outbox differs from erased authority: %s err %v", recovered, err)
	}
}
