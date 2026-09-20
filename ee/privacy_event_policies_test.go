// SPDX-License-Identifier: LicenseRef-trstctl-EE

package ee_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	enterprise "trstctl.com/trstctl/ee"
	"trstctl.com/trstctl/ee/provider"
	"trstctl.com/trstctl/ee/silo"
	"trstctl.com/trstctl/internal/agentid/delegation"
	agidrevoke "trstctl.com/trstctl/internal/agentid/revoke"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/reprotect"
	"trstctl.com/trstctl/internal/decommission/retirement"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/pqcmigration"
	"trstctl.com/trstctl/internal/privacyref"
	"trstctl.com/trstctl/internal/reconcile/quarantine"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
	"trstctl.com/trstctl/internal/succession"
)

func TestLicensedProductionPrivacyCatalogIsRegistered(t *testing.T) {
	covered := 0
	for _, schema := range enterprise.LicensedProductionPrivacyEventSchemas() {
		if !events.HasPrivacyEventPolicy(schema.EventType, schema.SchemaVersion) {
			t.Errorf("licensed event %s v%d has no privacy policy", schema.EventType, schema.SchemaVersion)
		}
		count, err := events.ValidatePrivacyEventPolicySubjectFixtures(schema.EventType, schema.SchemaVersion)
		if err != nil {
			t.Errorf("licensed event %s v%d subject fixture: %v", schema.EventType, schema.SchemaVersion, err)
		}
		covered += count
	}
	if covered == 0 {
		t.Fatal("licensed production privacy catalog exercised no subject-bearing paths")
	}
}

// fullBinaryProducerPrivacyCoordinates is intentionally maintained separately
// from ee.LicensedProductionPrivacyEventSchemas. It is the test-side census of
// every full-binary producer family, so adding a catalog row cannot make its own
// denominator grow and silently certify an event no producer owns.
func fullBinaryProducerPrivacyCoordinates() []events.ProductionPrivacyEventSchema {
	return []events.ProductionPrivacyEventSchema{
		{EventType: provider.AuditTenantProvisioned, SchemaVersion: 1},
		{EventType: provider.AuditTenantSuspended, SchemaVersion: 1},
		{EventType: provider.AuditTenantResumed, SchemaVersion: 1},
		{EventType: provider.AuditTenantOffboarded, SchemaVersion: 1},
		{EventType: provider.EventDelegationGranted, SchemaVersion: 1},
		{EventType: provider.EventDelegationRevoked, SchemaVersion: 1},
		{EventType: provider.EventOperatorUpserted, SchemaVersion: 1},
		{EventType: provider.EventOperatorOffboarded, SchemaVersion: 1},
		{EventType: provider.EventTenantQuotaSet, SchemaVersion: 1},
		{EventType: provider.EventTenantBrandSet, SchemaVersion: 1},
		{EventType: provider.AuditBreakGlassRequested, SchemaVersion: 1},
		{EventType: provider.AuditBreakGlassConsented, SchemaVersion: 1},
		{EventType: provider.AuditBreakGlassDenied, SchemaVersion: 1},
		{EventType: provider.AuditBreakGlassAccessed, SchemaVersion: 1},
		{EventType: "provider.isolation.drill", SchemaVersion: 1},
		{EventType: pqcmigration.EventTLSFindingPrepared, SchemaVersion: 1},
		{EventType: pqcmigration.EventTLSFindingCompleted, SchemaVersion: 1},
		{EventType: pqcmigration.EventTLSFindingRollbackCompleted, SchemaVersion: 1},
		{EventType: pqcmigration.EventTLSFindingFailed, SchemaVersion: 1},
		{EventType: "licensed_crypto.migration.tls_posture.rollback_requested", SchemaVersion: 1},
		{EventType: agidrevoke.TypeRevocationEffectRecorded, SchemaVersion: agidrevoke.RevocationEffectSchemaV1},
		{EventType: agidrevoke.TypeRevocationIntervalExceeded, SchemaVersion: agidrevoke.RevocationIntervalExceededSchemaV1},
		{EventType: agidrevoke.TypeRevocationTerminal, SchemaVersion: agidrevoke.RevocationTerminalSchemaV1},
		{EventType: rounds.EventTypeRoundInitiated, SchemaVersion: 1},
		{EventType: rounds.EventTypeRoundAgreement, SchemaVersion: 1},
		{EventType: rounds.EventTypeRoundStaleness, SchemaVersion: 1},
		{EventType: witness.EventTypeWitnessRecorded, SchemaVersion: 1},
		{EventType: witness.EventTypeWitnessCountersigned, SchemaVersion: 1},
		{EventType: witness.EventTypeWitnessDisputed, SchemaVersion: 1},
		{EventType: quarantine.EventTypeEntered, SchemaVersion: 1},
		{EventType: quarantine.EventTypeRefused, SchemaVersion: 1},
		{EventType: quarantine.EventTypeCompleted, SchemaVersion: 1},
		{EventType: quarantine.EventTypeReleased, SchemaVersion: 1},
		{EventType: depstate.TypeDependencyRegistered, SchemaVersion: depstate.SchemaV1},
		{EventType: depstate.TypeDependencyReleased, SchemaVersion: depstate.SchemaV1},
		{EventType: depstate.TypeDependencyErasureDesignated, SchemaVersion: depstate.SchemaV1},
		{EventType: depstate.TypeReprotectionCompleted, SchemaVersion: depstate.SchemaV1},
		{EventType: depstate.TypeRevocationCompleted, SchemaVersion: depstate.SchemaV1},
		{EventType: reprotect.TypeCredentialSupersession, SchemaVersion: depstate.SchemaV1},
		{EventType: retirement.TypeRetirementRequested, SchemaVersion: retirement.SchemaV1},
		{EventType: retirement.TypeRetirementRefused, SchemaVersion: retirement.SchemaV1},
		{EventType: retirement.TypeDestructionRecorded, SchemaVersion: retirement.SchemaV1},
		{EventType: "kmip.state.object.created", SchemaVersion: 1},
		{EventType: "kmip.state.object.registered", SchemaVersion: 1},
		{EventType: "kmip.state.object.rekeyed", SchemaVersion: 1},
		{EventType: "kmip.state.object.revoked", SchemaVersion: 1},
		{EventType: "kmip.state.object.destroyed", SchemaVersion: 1},
		{EventType: "kmip.unauthenticated", SchemaVersion: 1},
		{EventType: "kmip.object.created", SchemaVersion: 1},
		{EventType: "kmip.object.registered", SchemaVersion: 1},
		{EventType: "kmip.object.rekeyed", SchemaVersion: 1},
		{EventType: "kmip.object.revoke", SchemaVersion: 1},
		{EventType: "kmip.object.destroyed", SchemaVersion: 1},
		{EventType: silo.LaneProbeEventType, SchemaVersion: 1},
		{EventType: delegation.TypeDelegationRecorded, SchemaVersion: delegation.DelegationRecordedSchemaV1},
		{EventType: delegation.TypeIssuanceRecorded, SchemaVersion: delegation.IssuanceRecordedSchemaV1},
		{EventType: delegation.TypeRefusalRecorded, SchemaVersion: delegation.RefusalRecordedSchemaV1},
		{EventType: delegation.TypeRevocationDirective, SchemaVersion: delegation.RevocationDirectiveSchemaV1},
		{EventType: succession.TypeFinding, SchemaVersion: succession.FindingSchemaV1},
		{EventType: succession.TypeSuccession, SchemaVersion: succession.SuccessionSchemaV1},
		{EventType: succession.TypeRetirement, SchemaVersion: succession.RetirementSchemaV1},
		{EventType: succession.TypeRPAck, SchemaVersion: succession.RPAckSchemaV1},
		{EventType: succession.TypeRefusal, SchemaVersion: succession.RefusalSchemaV1},
		{EventType: succession.TypeRewrapStage, SchemaVersion: succession.RewrapStageSchemaV1},
		{EventType: succession.TypeRewrapCompleted, SchemaVersion: succession.RewrapCompletedSchemaV1},
		{EventType: succession.TypeMisissuance, SchemaVersion: succession.MisissuanceSchemaV1},
	}
}

func TestFullBinaryProducerVocabularyAndPrivacyCatalogHaveSetEquality(t *testing.T) {
	producerSet := make(map[events.ProductionPrivacyEventSchema]struct{})
	for _, schema := range fullBinaryProducerPrivacyCoordinates() {
		if _, duplicate := producerSet[schema]; duplicate {
			t.Errorf("full-binary producer census repeats %s v%d", schema.EventType, schema.SchemaVersion)
		}
		producerSet[schema] = struct{}{}
	}
	catalogSet := make(map[events.ProductionPrivacyEventSchema]struct{})
	for _, schema := range enterprise.LicensedProductionPrivacyEventSchemas() {
		if _, duplicate := catalogSet[schema]; duplicate {
			t.Errorf("licensed privacy catalog repeats %s v%d", schema.EventType, schema.SchemaVersion)
		}
		catalogSet[schema] = struct{}{}
	}
	for schema := range producerSet {
		if _, present := catalogSet[schema]; !present {
			t.Errorf("full-binary producer %s v%d is missing from the licensed privacy catalog", schema.EventType, schema.SchemaVersion)
		}
		if !events.HasPrivacyEventPolicy(schema.EventType, schema.SchemaVersion) {
			t.Errorf("full-binary producer %s v%d has no privacy policy", schema.EventType, schema.SchemaVersion)
		}
	}
	for schema := range catalogSet {
		if _, present := producerSet[schema]; !present {
			t.Errorf("licensed privacy catalog has orphan coordinate %s v%d with no producer census entry", schema.EventType, schema.SchemaVersion)
		}
	}
}

func TestRetirementPrivacyPoliciesCoverEveryImmutableEventShape(t *testing.T) {
	for _, schema := range []events.ProductionPrivacyEventSchema{
		{EventType: retirement.TypeRetirementRequested, SchemaVersion: retirement.SchemaV1},
		{EventType: retirement.TypeRetirementRefused, SchemaVersion: retirement.SchemaV1},
		{EventType: retirement.TypeDestructionRecorded, SchemaVersion: retirement.SchemaV1},
	} {
		if !events.HasPrivacyEventPolicy(schema.EventType, schema.SchemaVersion) {
			t.Fatalf("retirement event %s v%d has no privacy policy", schema.EventType, schema.SchemaVersion)
		}
		if _, err := events.ValidatePrivacyEventPolicySubjectFixtures(schema.EventType, schema.SchemaVersion); err != nil {
			t.Fatalf("retirement event %s v%d privacy fixture: %v", schema.EventType, schema.SchemaVersion, err)
		}
	}
}

func TestLicensedProviderAuthorityRewriteStillDecodes(t *testing.T) {
	const subject = "operator@example.test"
	payload := provider.AuthorityEvent{
		Tenant: &provider.Tenant{
			ID: "tenant-a", Slug: "customer-" + subject, Name: "Customer " + subject,
			Status: provider.TenantActive, CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
			UpdatedAt: time.Unix(1_700_000_100, 0).UTC(),
		},
		EffectiveAt: time.Unix(1_700_000_100, 0).UTC(),
		Audit: provider.AuditEvent{
			Type: provider.AuditTenantProvisioned, TenantID: "tenant-a",
			OperatorID: subject, OperatorEmail: subject, Reason: "created for " + subject,
			At: time.Unix(1_700_000_100, 0).UTC(),
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(
		raw, "tenant-a", subject, provider.AuditTenantProvisioned, 1,
	)
	if err != nil || !changed {
		t.Fatalf("provider rewrite changed=%t err=%v data=%s", changed, err, rewritten)
	}
	if bytes.Contains(rewritten, []byte(subject)) {
		t.Fatalf("provider rewrite retained subject: %s", rewritten)
	}
	var decoded provider.AuthorityEvent
	if err := json.Unmarshal(rewritten, &decoded); err != nil {
		t.Fatalf("rewritten provider authority no longer decodes: %v", err)
	}
	want := privacyref.Placeholder(privacyref.SubjectRef("tenant-a", subject))
	if decoded.Audit.OperatorID != want || decoded.Audit.OperatorEmail != want || decoded.Audit.Reason != "" {
		t.Fatalf("provider audit rewrite = %+v, want placeholder identities and cleared reason", decoded.Audit)
	}
}

func TestLicensedDelegationDirectiveRewriteStillDecodes(t *testing.T) {
	const subject = "agent@example.test"
	payload := delegation.RevocationDirectiveV1{
		TenantID: "tenant-a", SubjectID: subject, Reason: "retire " + subject, Watermark: 42,
	}
	event, err := delegation.Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(
		event.Data, event.TenantID, subject, event.Type, event.SchemaVersion,
	)
	if err != nil || !changed || bytes.Contains(rewritten, []byte(subject)) {
		t.Fatalf("delegation rewrite changed=%t err=%v data=%s", changed, err, rewritten)
	}
	decoded, err := delegation.Decode(eventspec.Event{
		Type: event.Type, TenantID: event.TenantID, SchemaVersion: event.SchemaVersion, Data: rewritten,
	})
	if err != nil {
		t.Fatalf("rewritten delegation directive no longer decodes: %v", err)
	}
	directive, ok := decoded.(delegation.RevocationDirectiveV1)
	if !ok || directive.SubjectID == subject || directive.Reason != "" {
		t.Fatalf("delegation directive rewrite = %#v", decoded)
	}
}

func TestLicensedSuccessionFindingRewriteStillDecodes(t *testing.T) {
	const subject = "operator@example.test"
	event, err := succession.Encode(succession.FindingV1{
		IdentityID: "identity-a", TenantID: "tenant-a", Epoch: 1,
		Algorithm: "rsa", Reason: "reported by " + subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(
		event.Data, event.TenantID, subject, event.Type, event.SchemaVersion,
	)
	if err != nil || !changed || bytes.Contains(rewritten, []byte(subject)) {
		t.Fatalf("succession rewrite changed=%t err=%v data=%s", changed, err, rewritten)
	}
	decoded, err := succession.Decode(eventspec.Event{
		Type: event.Type, TenantID: event.TenantID, SchemaVersion: event.SchemaVersion, Data: rewritten,
	})
	if err != nil {
		t.Fatalf("rewritten succession finding no longer decodes: %v", err)
	}
	finding, ok := decoded.(succession.FindingV1)
	if !ok || finding.Reason != "" {
		t.Fatalf("succession finding rewrite = %#v", decoded)
	}
}
