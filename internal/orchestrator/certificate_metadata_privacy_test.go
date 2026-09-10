// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateMetadataPrivacyRebindRejectsOrdinaryContext(t *testing.T) {
	// No SQL or source lookup may run outside the event layer's private context.
	s := &store.Store{}
	called := false
	err := s.RebindCertificateMetadataPrivacyReceiptsTx(t.Context(), nil, tenantA, "subject", func(context.Context, uint64, uint64, func(events.Event) error) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("ordinary context reached receipt rebinding")
	}
}

func TestCertificateMetadataReceiptsFollowVerifiedPrivacyGeneration(t *testing.T) {
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
	const subject = "metadata-erasure@example.test"
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: subject, Roles: []string{"operator"}})
	owner, err := o.CreateOwnerRecord(actorCtx, store.Owner{TenantID: tenantA, Kind: store.OwnerUser, Name: subject, Email: subject})
	if err != nil {
		t.Fatal(err)
	}
	in, _ := recordingCertificates(t)
	in.Source, in.IssuanceIdempotencyKey = "import", ""
	in.CertificateDER, in.CertificatePEM = nil, nil
	in.OwnerID = &owner.ID
	if _, err := o.RecordCertificate(actorCtx, tenantA, in); err != nil {
		t.Fatal(err)
	}
	// Cross the receipt page boundary with actual completed commands. Every
	// canonical rewritten receipt must remain usable, including the last page.
	for range 128 {
		if _, err := o.RecordCertificate(actorCtx, tenantA, in); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	var original events.Event
	if err := log.Replay(ctx, 3, func(e events.Event) error { original = e; return nil }); err != nil {
		t.Fatal(err)
	}
	if original.Actor == nil || original.Actor.Subject != subject {
		t.Fatal("real actor was not retained")
	}
	if _, err := o.ErasePrivacySubject(ctx, tenantA, subject, "owned source regression"); err != nil {
		t.Fatal(err)
	}
	canonical, found, err := log.EventByID(ctx, original.ID)
	if err != nil || !found || canonical.Actor == nil || canonical.Actor.Subject == subject {
		t.Fatalf("signed privacy rewrite absent: %v", err)
	}
	if err := p.Apply(ctx, canonical); err != nil {
		t.Fatalf("canonical rewritten event rejected by old receipt: %v", err)
	}
	// Reuse every rewritten recording receipt before Rebuild replaces any of
	// them. Testing only the final event would miss a broken first page.
	var canonicalRecordings []events.Event
	if err := log.Replay(ctx, 3, func(e events.Event) error {
		if e.Type == projections.EventCertificateRecorded {
			canonicalRecordings = append(canonicalRecordings, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(canonicalRecordings) != 129 {
		t.Fatalf("canonical recording count=%d", len(canonicalRecordings))
	}
	for _, e := range canonicalRecordings {
		if err := p.Apply(ctx, e); err != nil {
			t.Fatalf("rewritten receipt at sequence%d failed before rebuild: %v", e.Sequence, err)
		}
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	before := certificateOrderState(t, ctx, s, in.Fingerprint)
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, certificateOrderState(t, ctx, s, in.Fingerprint)) {
		t.Fatal("warm privacy completion differs from ordered rewritten history")
	}
}
