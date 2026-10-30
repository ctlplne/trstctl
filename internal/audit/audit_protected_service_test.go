// SPDX-License-Identifier: BUSL-1.1

package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

type auditProtectionFixture struct {
	mu      sync.Mutex
	ref     eventprotect.KeyRef
	request eventprotect.DestructionRequest
}

func (f *auditProtectionFixture) WithKeyLock(ctx context.Context, _ eventprotect.KeyRef, visit func(context.Context) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return visit(ctx)
}
func (f *auditProtectionFixture) WithTenantEventProtection(ctx context.Context, _ string, visit func(context.Context) error) error {
	return visit(ctx)
}
func (f *auditProtectionFixture) EventProtectionFor(_ context.Context, event events.Event) (events.EventProtectionDecision, error) {
	if event.TenantID != f.ref.TenantID {
		return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionSensitive, Ref: f.ref}, nil
}
func (f *auditProtectionFixture) AuthorizeDestruction(_ context.Context, request eventprotect.DestructionRequest) error {
	if request != f.request {
		return eventprotect.ErrContext
	}
	return nil
}

const auditProtectedFixtureType = "a233.audit_protected_fixture"

type auditProtectedFixturePayload struct {
	Email string `json:"email"`
}

func init() {
	if err := events.RegisterPrivacyEventPolicy(auditProtectedFixtureType, 1, events.PrivacyEventPolicy{Rules: []events.PrivacyFieldRule{{Path: "/email", Mode: events.PrivacyFieldIdentityExact}}, PayloadShape: events.PrivacyPayloadShapeOf[auditProtectedFixturePayload]()}); err != nil {
		panic(err)
	}
}

// Real NATS and independent file-custody removal plus signed audit export.
// Admission/authorizer/local signer here are explicit component fixtures, not
// production retained-source/outbox/SQL or isolated-signer qualification.
func TestSignedProtectedAuditRetainsCiphertextAndVerifiesAfterRealKeyRemoval(t *testing.T) {
	ctx := t.Context()
	base := t.TempDir()
	signer, err := jose.GenerateRSASigningKey("a233-audit-component-fixture")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &auditProtectionFixture{ref: eventprotect.KeyRef{TenantID: tenantA, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"}}
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: fixture, EvidenceKey: signer, DestructionAuthority: fixture})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	if err := keys.Provision(ctx, fixture.ref); err != nil {
		t.Fatal(err)
	}
	creation, err := keys.CreationEvidence(ctx, fixture.ref)
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")}, events.WithEventProtection(events.EventProtection{Admission: fixture, Keys: keys}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := 0; i < 2; i++ {
		wire, err := json.Marshal(auditProtectedFixturePayload{Email: "audit-private-person@example.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{Type: auditProtectedFixtureType, TenantID: tenantA, Data: wire, Actor: &events.Actor{Subject: "audit-private-operator@example.invalid"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(ctx, events.Event{Type: "neighbor.unaffected", TenantID: tenantB, Data: []byte(`{"name":"neighbor remains readable"}`)}); err != nil {
		t.Fatal(err)
	}
	service := audit.NewService(log, signer)
	query := audit.Query{TenantID: tenantA}
	if _, err := service.SearchReadableView(ctx, audit.Query{}); !errors.Is(err, audit.ErrMissingTenant) {
		t.Fatal("readable view accepted an unscoped query")
	}
	view, err := service.SearchReadableView(ctx, audit.Query{TenantID: tenantA, Limit: 1, Latest: true})
	if err != nil || len(view.Records) != 1 || len(view.ReadableEvents) != 1 {
		t.Fatalf("authorized readable view failed: %v", err)
	}
	readable := view.ReadableEvents[0]
	if readable.Sequence != view.Records[0].Sequence || readable.ID != view.Records[0].ID || readable.Actor == nil || readable.Actor.Subject != "audit-private-operator@example.invalid" || readable.SensitiveErased || !bytes.Contains(readable.Data, []byte("audit-private-person@example.invalid")) {
		t.Fatal("readable fields were lost or associated with a different limited record")
	}
	if view.Records[0].Actor != nil || bytes.Contains(view.Records[0].Data, []byte("example.invalid")) {
		t.Fatal("readable view changed the immutable signed core")
	}
	beforeSigned, before, err := service.ExportWithBundle(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if before.Count != 2 {
		t.Fatalf("protected export count=%d", before.Count)
	}
	beforeBytes, err := signer.JWKS().VerifyArtifact(beforeSigned, jose.ArtifactAuditExport)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(beforeBytes, []byte("example.invalid")) {
		t.Fatal("signed managed audit artifact exposed protected readable data or actor")
	}
	for _, record := range before.Records {
		if record.Actor != nil || !bytes.Contains(record.Data, []byte("trstctl.protected-audit-source/v1")) {
			t.Fatal("signed record did not retain a stable protected source commitment")
		}
	}
	neighborBefore, err := service.Search(ctx, audit.Query{TenantID: tenantB})
	if err != nil {
		t.Fatal(err)
	}
	offboarded := time.Now().UTC()
	fixture.request = eventprotect.DestructionRequest{Ref: fixture.ref, OperationID: "fdc5ca32-fb7d-4ea3-b640-fcf032cb0ac5", RegistrationIdentity: "audit-fixture-registration", ActivationEventID: "audit-fixture-activation", ActivationSequence: 1, CreationDigest: creation.Digest(), OffboardEventID: "audit-fixture-offboard", OffboardSequence: 4, OffboardedAt: offboarded, NotBefore: offboarded.Add(2 * time.Millisecond)}
	time.Sleep(time.Until(fixture.request.NotBefore))
	receipt, err := keys.Destroy(ctx, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventprotect.VerifyDestructionReceipt(signer.JWKS(), receipt); err != nil {
		t.Fatal(err)
	}
	if current, erased, err := keys.DestructionReceipt(ctx, fixture.ref); err != nil || !erased || current != receipt {
		t.Fatalf("independent removal readback: %v", err)
	}
	afterSigned, after, err := service.ExportWithBundle(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	afterView, err := service.SearchReadableView(ctx, query)
	if err != nil || len(afterView.Records) != 2 || len(afterView.ReadableEvents) != 2 {
		t.Fatalf("erased readable view failed: %v", err)
	}
	for index, readable := range afterView.ReadableEvents {
		if readable.Sequence != afterView.Records[index].Sequence || readable.ID != afterView.Records[index].ID || !readable.SensitiveErased || len(readable.Data) != 0 || readable.Actor != nil {
			t.Fatal("erased readable view retained private details or lost its exact record identity")
		}
	}
	filtered, err := service.SearchReadableView(ctx, audit.Query{TenantID: tenantA, Contains: "example.invalid"})
	if err != nil || len(filtered.Records) != 0 || len(filtered.ReadableEvents) != 0 {
		t.Fatalf("erased content filtering retained former private details: %v", err)
	}
	if before.ChainHead != after.ChainHead || before.Count != after.Count {
		t.Fatal("key destruction changed the committed audit chain")
	}
	for i := range before.Records {
		if before.Records[i].Hash != after.Records[i].Hash || !bytes.Equal(before.Records[i].Data, after.Records[i].Data) {
			t.Fatal("erasure rewrote signed record commitments")
		}
	}
	for _, signed := range []string{beforeSigned, afterSigned} {
		if _, err := audit.VerifyBundle(signed, signer.JWKS()); err != nil {
			t.Fatalf("offline audit verification failed after removal: %v", err)
		}
	}
	if _, err := service.VerifyChain(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	neighborAfter, err := service.Search(ctx, audit.Query{TenantID: tenantB})
	if err != nil || len(neighborAfter) != 1 || len(neighborBefore) != 1 || neighborAfter[0].Hash != neighborBefore[0].Hash || !strings.Contains(string(neighborAfter[0].Data), "neighbor remains readable") {
		t.Fatalf("neighbor audit was changed: %v", err)
	}
}
