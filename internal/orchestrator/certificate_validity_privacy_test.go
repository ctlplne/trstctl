// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateValidityAnchorSurvivesVerifiedPrivacyRewrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	s := newStore(t)
	key, err := jose.GenerateRSASigningKey("metadata-privacy-regression")
	if err != nil {
		t.Fatal(err)
	}
	log := openLogWithOptions(t, events.WithRequiredPrivacyEventPolicies(),
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)),
		events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(key)))
	p := projections.New(s)
	tenant, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegisteredJSON("metadata-privacy")})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	o := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s), orchestrator.WithTenantDataRewriteOptions(
		events.WithTenantDataContinuity(historycontinuity.NewReceiptSigner(key)),
		events.WithTenantDataCutoverPreparation(s.PrepareTenantDataCutover),
		events.WithTenantDataAuditContinuity(historycontinuity.AuditCheckpointProvider(s))))
	const subject = "anchor.example.test"
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: subject, Roles: []string{"operator"}})
	owner, err := o.CreateOwnerRecord(actorCtx, store.Owner{TenantID: tenantA, Kind: store.OwnerWorkload, Name: subject})
	if err != nil {
		t.Fatal(err)
	}
	in := anchoredRecordingCertificate(t)
	in.OwnerID = &owner.ID
	cert, err := o.RecordCertificate(actorCtx, tenantA, in)
	if err != nil {
		t.Fatal(err)
	}
	original, found, err := log.EventByID(ctx, cert.IssuanceEventID)
	if err != nil || !found || original.SchemaVersion != projections.CertificateValidityEventSchemaVersion {
		t.Fatalf("explicit anchored source schema absent: %v", err)
	}
	if _, err := o.ErasePrivacySubject(ctx, tenantA, subject, "owned source regression"); err != nil {
		t.Fatal(err)
	}
	canonical, found, err := log.EventByID(ctx, original.ID)
	if err != nil || !found || canonical.Actor == nil || canonical.Actor.Subject == subject {
		t.Fatalf("signed privacy generation did not rewrite the actual actor: %v", err)
	}
	if err := p.Apply(ctx, canonical); err != nil {
		t.Fatalf("rewritten anchor receipt was not reusable: %v", err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	retained, err := s.GetCertificate(ctx, tenantA, cert.ID)
	if err != nil || retained.ValidityAnchor == nil || !retained.ValidityAnchor.Equal(*in.ValidityAnchor) {
		t.Fatalf("privacy/rebuild changed actual issuance anchor: %v", err)
	}
	for _, version := range []int{1, projections.CertificateApprovalEventSchemaVersion} {
		if _, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: original.Type, SchemaVersion: version, Data: original.Data}); err == nil || !strings.Contains(err.Error(), "validity_anchor") {
			t.Fatalf("old closed schema %d did not specifically reject the new anchor field: %v", version, err)
		}
	}
}
