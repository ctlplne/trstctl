// SPDX-License-Identifier: LicenseRef-trstctl-EE

package ee

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"trstctl.com/trstctl/ee/agentid/delegation"
	agidrevoke "trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/reprotect"
	"trstctl.com/trstctl/ee/decommission/retirement"
	"trstctl.com/trstctl/ee/pqcmigration"
	"trstctl.com/trstctl/ee/provider"
	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/ee/reconcile/rounds"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/ee/silo"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/events"
)

type licensedPrivacyEventPolicy struct {
	events.ProductionPrivacyEventSchema
	Policy events.PrivacyEventPolicy
}

type providerTenantAuthorityPayload struct {
	Tenant         *provider.Tenant    `json:"tenant,omitempty"`
	EffectiveAt    time.Time           `json:"effective_at,omitempty"`
	RequestBinding string              `json:"request_binding,omitempty"`
	Audit          provider.AuditEvent `json:"audit"`
}

type providerDelegationAuthorityPayload struct {
	Delegation     *provider.DelegationMutation  `json:"delegation,omitempty"`
	Delegations    []provider.DelegationMutation `json:"delegations,omitempty"`
	EffectiveAt    time.Time                     `json:"effective_at,omitempty"`
	RequestBinding string                        `json:"request_binding,omitempty"`
	Audit          provider.AuditEvent           `json:"audit"`
}

type providerOperatorAuthorityPayload struct {
	Operator       *provider.OperatorIdentity `json:"operator,omitempty"`
	EffectiveAt    time.Time                  `json:"effective_at,omitempty"`
	RequestBinding string                     `json:"request_binding,omitempty"`
	Audit          provider.AuditEvent        `json:"audit"`
}

type providerQuotaAuthorityPayload struct {
	Quota          *billing.Quota      `json:"quota,omitempty"`
	EffectiveAt    time.Time           `json:"effective_at,omitempty"`
	RequestBinding string              `json:"request_binding,omitempty"`
	Audit          provider.AuditEvent `json:"audit"`
}

type providerBrandAuthorityPayload struct {
	Brand               *provider.TenantBrand `json:"brand,omitempty"`
	BrandTokenOverrides map[string]string     `json:"brand_token_overrides,omitempty"`
	EffectiveAt         time.Time             `json:"effective_at,omitempty"`
	RequestBinding      string                `json:"request_binding,omitempty"`
	Audit               provider.AuditEvent   `json:"audit"`
}

type providerBreakGlassAuthorityPayload struct {
	Grant          *provider.BreakGlassGrant `json:"break_glass_grant,omitempty"`
	EffectiveAt    time.Time                 `json:"effective_at,omitempty"`
	RequestBinding string                    `json:"request_binding,omitempty"`
	Audit          provider.AuditEvent       `json:"audit"`
}

type providerBreakGlassAccessAuthorityPayload struct {
	Grant          *provider.BreakGlassGrant `json:"break_glass_grant,omitempty"`
	Snapshot       *provider.TenantSnapshot  `json:"tenant_snapshot,omitempty"`
	EffectiveAt    time.Time                 `json:"effective_at,omitempty"`
	RequestBinding string                    `json:"request_binding,omitempty"`
	Audit          provider.AuditEvent       `json:"audit"`
}

type providerIsolationDrillAuthorityPayload struct {
	Drill          *provider.IsolationDrillReport `json:"isolation_drill,omitempty"`
	EffectiveAt    time.Time                      `json:"effective_at,omitempty"`
	RequestBinding string                         `json:"request_binding,omitempty"`
	Audit          provider.AuditEvent            `json:"audit"`
}

// These payloads mirror package-private wire structs at the edition catalog
// boundary. They intentionally duplicate only JSON field names and kinds: the
// owning packages retain behavior and validation, while the root EE package can
// close every full-binary event shape without exporting implementation details.
type licensedPQCTLSRollbackIntent struct {
	TargetID       string          `json:"target_id"`
	AssetIDs       []string        `json:"asset_ids"`
	IdempotencyKey string          `json:"idempotency_key"`
	Payload        json.RawMessage `json:"payload"`
}

type licensedPQCTLSRollbackRequested struct {
	RunID   string                         `json:"run_id"`
	Intents []licensedPQCTLSRollbackIntent `json:"intents"`
}

type licensedAgentRevocationTerminal struct {
	DirectiveID string                       `json:"directive_id"`
	Aggregate   agidrevoke.AggregateEvidence `json:"aggregate"`
}

type licensedKMIPStateEvent struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm,omitempty"`
	State     string `json:"state,omitempty"`
	Version   int    `json:"version,omitempty"`
	SealedKey []byte `json:"sealed_key,omitempty"`
}

type licensedKMIPUnauthenticated struct {
	Operation string `json:"op"`
}

type licensedKMIPObjectCreated struct {
	ID        string `json:"id"`
	Algorithm string `json:"alg"`
}

type licensedKMIPObjectRekeyed struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

type licensedKMIPObjectTransitioned struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type licensedKMIPObjectDestroyed struct {
	ID string `json:"id"`
}

type licensedSiloLaneProbe struct {
	Drill  string `json:"drill"`
	Tenant string `json:"tenant"`
}

func licensedPrivacyRule(path string, mode events.PrivacyFieldMode) events.PrivacyFieldRule {
	return events.PrivacyFieldRule{Path: path, Mode: mode}
}

func typedLicensedPrivacyPolicy[T any](rules ...events.PrivacyFieldRule) events.PrivacyEventPolicy {
	return events.PrivacyEventPolicy{
		Rules:        rules,
		PayloadShape: events.PrivacyPayloadShapeOf[T](),
	}
}

func rejectingTypedLicensedPrivacyPolicy[T any](rules ...events.PrivacyFieldRule) events.PrivacyEventPolicy {
	return events.PrivacyEventPolicy{
		Rules:             rules,
		PayloadShape:      events.PrivacyPayloadShapeOf[T](),
		RejectSubjectData: true,
	}
}

func providerAuditPrivacyRules() []events.PrivacyFieldRule {
	return []events.PrivacyFieldRule{
		licensedPrivacyRule("/audit/operator_id", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/audit/operator_email", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/audit/subject", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/audit/reason", events.PrivacyFieldFreeTextClear),
	}
}

func legacyProviderAuditPrivacyRules() []events.PrivacyFieldRule {
	return []events.PrivacyFieldRule{
		licensedPrivacyRule("/operator_id", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/operator_email", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/subject", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/reason", events.PrivacyFieldFreeTextClear),
	}
}

func providerPolicy[T any](rules ...events.PrivacyFieldRule) events.PrivacyEventPolicy {
	rules = append(rules, providerAuditPrivacyRules()...)
	rules = append(rules, legacyProviderAuditPrivacyRules()...)
	return events.PrivacyEventPolicy{
		Rules: rules,
		PayloadShape: events.PrivacyPayloadShapeOneOf(
			events.PrivacyPayloadShapeOf[T](),
			events.PrivacyPayloadShapeOf[provider.AuditEvent](),
		),
	}
}

var licensedProductionPrivacyEventCatalog = func() []licensedPrivacyEventPolicy {
	entry := func(eventType string, version int, policy events.PrivacyEventPolicy) licensedPrivacyEventPolicy {
		return licensedPrivacyEventPolicy{
			ProductionPrivacyEventSchema: events.ProductionPrivacyEventSchema{
				EventType: eventType, SchemaVersion: version,
			},
			Policy: policy,
		}
	}
	tenantPolicy := providerPolicy[providerTenantAuthorityPayload](
		licensedPrivacyRule("/tenant/slug", events.PrivacyFieldSubjectToken),
		licensedPrivacyRule("/tenant/name", events.PrivacyFieldSubjectToken),
	)
	delegationPolicy := providerPolicy[providerDelegationAuthorityPayload](
		licensedPrivacyRule("/delegation/operator_id", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/delegation/granted_by", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/delegations/*/operator_id", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/delegations/*/granted_by", events.PrivacyFieldIdentityExact),
	)
	operatorRules := []events.PrivacyFieldRule{
		licensedPrivacyRule("/operator/id", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/operator/external_id", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/operator/user_name", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/operator/email", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/operator/display_name", events.PrivacyFieldFreeTextClear),
		licensedPrivacyRule("/operator/source", events.PrivacyFieldSubjectToken),
	}
	operatorRules = append(operatorRules, providerAuditPrivacyRules()...)
	operatorPolicy := typedLicensedPrivacyPolicy[providerOperatorAuthorityPayload](operatorRules...)
	breakGlassPolicy := providerPolicy[providerBreakGlassAuthorityPayload](
		licensedPrivacyRule("/break_glass_grant/operator_id", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/break_glass_grant/operator_email", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/break_glass_grant/reason", events.PrivacyFieldFreeTextClear),
		licensedPrivacyRule("/break_glass_grant/consented_by", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/break_glass_grant/second_consented_by", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/break_glass_grant/denied_by", events.PrivacyFieldIdentityExact),
	)
	breakGlassAccessPolicy := providerPolicy[providerBreakGlassAccessAuthorityPayload](
		licensedPrivacyRule("/break_glass_grant/operator_id", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/break_glass_grant/operator_email", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/break_glass_grant/reason", events.PrivacyFieldFreeTextClear),
		licensedPrivacyRule("/break_glass_grant/consented_by", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/break_glass_grant/second_consented_by", events.PrivacyFieldIdentityExact),
		licensedPrivacyRule("/break_glass_grant/denied_by", events.PrivacyFieldIdentityExact),
	)
	catalog := []licensedPrivacyEventPolicy{
		entry(provider.AuditTenantProvisioned, 1, tenantPolicy),
		entry(provider.AuditTenantSuspended, 1, tenantPolicy),
		entry(provider.AuditTenantResumed, 1, tenantPolicy),
		entry(provider.AuditTenantOffboarded, 1, tenantPolicy),
		entry(provider.EventDelegationGranted, 1, delegationPolicy),
		entry(provider.EventDelegationRevoked, 1, delegationPolicy),
		entry(provider.EventOperatorUpserted, 1, operatorPolicy),
		entry(provider.EventOperatorOffboarded, 1, operatorPolicy),
		entry(provider.EventTenantQuotaSet, 1, providerPolicy[providerQuotaAuthorityPayload](
			licensedPrivacyRule("/quota/updated_by", events.PrivacyFieldIdentityExact),
		)),
		entry(provider.EventTenantBrandSet, 1, providerPolicy[providerBrandAuthorityPayload](
			licensedPrivacyRule("/brand/TenantID", events.PrivacyFieldOpaqueExact),
			licensedPrivacyRule("/brand/ProductName", events.PrivacyFieldSubjectToken),
			licensedPrivacyRule("/brand/LogoDataURI", events.PrivacyFieldOpaqueExact),
			licensedPrivacyRule("/brand/LoginMessage", events.PrivacyFieldFreeTextClear),
			licensedPrivacyRule("/brand/EmailFromName", events.PrivacyFieldSubjectToken),
			licensedPrivacyRule("/brand/EmailFooter", events.PrivacyFieldFreeTextClear),
			licensedPrivacyRule("/brand/CustomDomain", events.PrivacyFieldSubjectToken),
			// Brand token overrides are free-form display strings a tenant
			// substitutes into emails and UI chrome, exactly like the sibling
			// /brand/LoginMessage and /brand/EmailFooter fields. They are not
			// cataloged schemaless identity maps, so JSONIdentityValues (which
			// rewrites only a value that is EXACTLY the subject, and hard-errors
			// on any other occurrence) was the wrong contract: an override such
			// as "Contact ops@acme.test" made the whole erasure fail closed
			// rather than erase. FreeTextClear clears any override containing
			// the subject, which removes the identity and lets the token fall
			// back to its default.
			licensedPrivacyRule("/brand_token_overrides", events.PrivacyFieldFreeTextClear),
		)),
		entry(provider.AuditBreakGlassRequested, 1, breakGlassPolicy),
		entry(provider.AuditBreakGlassConsented, 1, breakGlassPolicy),
		entry(provider.AuditBreakGlassDenied, 1, breakGlassPolicy),
		entry(provider.AuditBreakGlassAccessed, 1, breakGlassAccessPolicy),
		entry("provider.isolation.drill", 1, providerPolicy[providerIsolationDrillAuthorityPayload](
			licensedPrivacyRule("/isolation_drill/checks/*/detail", events.PrivacyFieldFreeTextClear),
		)),

		// Full-binary PQC migration events. TargetConfig and sealed outbox bytes
		// are deliberately opaque; the surrounding typed shape still rejects an
		// added field or container change under schema v1.
		entry(pqcmigration.EventTLSFindingPrepared, 1,
			rejectingTypedLicensedPrivacyPolicy[pqcmigration.TLSFindingPrepared]()),
		entry(pqcmigration.EventTLSFindingCompleted, 1,
			rejectingTypedLicensedPrivacyPolicy[pqcmigration.TLSFindingCompleted](
				licensedPrivacyRule("/intent/target_config", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/intent/sealed_outbox_payload", events.PrivacyFieldOpaqueExact),
			)),
		entry(pqcmigration.EventTLSFindingRollbackCompleted, 1,
			rejectingTypedLicensedPrivacyPolicy[pqcmigration.TLSFindingRollbackCompleted]()),
		entry(pqcmigration.EventTLSFindingFailed, 1,
			rejectingTypedLicensedPrivacyPolicy[pqcmigration.TLSFindingFailure]()),
		entry("licensed_crypto.migration.tls_posture.rollback_requested", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedPQCTLSRollbackRequested](
				licensedPrivacyRule("/intents/*/payload", events.PrivacyFieldOpaqueExact),
			)),

		// Agent revocation adds three schemas beyond the closed delegation event
		// set. The interval event is unsigned and can pseudonymize its subject;
		// effect and terminal artifacts are signed evidence and refuse mutation.
		entry(agidrevoke.TypeRevocationEffectRecorded, agidrevoke.RevocationEffectSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[agidrevoke.CompletionEvidence]()),
		entry(agidrevoke.TypeRevocationIntervalExceeded, agidrevoke.RevocationIntervalExceededSchemaV1,
			typedLicensedPrivacyPolicy[agidrevoke.IntervalExceededPayload](
				licensedPrivacyRule("/subject_id", events.PrivacyFieldIdentityExact),
			)),
		entry(agidrevoke.TypeRevocationTerminal, agidrevoke.RevocationTerminalSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[licensedAgentRevocationTerminal]()),

		// XREC's signed witness/completion artifacts refuse subject-bearing
		// mutation. Unsigned containment explanations have their exact text fields
		// classified so erasure can clear them without changing state semantics.
		entry(rounds.EventTypeRoundInitiated, 1,
			rejectingTypedLicensedPrivacyPolicy[rounds.RoundInitiated]()),
		entry(rounds.EventTypeRoundAgreement, 1,
			rejectingTypedLicensedPrivacyPolicy[rounds.RoundAgreement]()),
		entry(rounds.EventTypeRoundStaleness, 1,
			rejectingTypedLicensedPrivacyPolicy[rounds.StalenessDivergence]()),
		entry(witness.EventTypeWitnessRecorded, 1,
			rejectingTypedLicensedPrivacyPolicy[witness.WitnessRecorded]()),
		entry(witness.EventTypeWitnessCountersigned, 1,
			rejectingTypedLicensedPrivacyPolicy[witness.WitnessCountersigned]()),
		entry(witness.EventTypeWitnessDisputed, 1,
			rejectingTypedLicensedPrivacyPolicy[witness.WitnessDisputed]()),
		entry(quarantine.EventTypeEntered, 1,
			typedLicensedPrivacyPolicy[quarantine.Entered](
				licensedPrivacyRule("/reason", events.PrivacyFieldFreeTextClear),
			)),
		entry(quarantine.EventTypeRefused, 1,
			typedLicensedPrivacyPolicy[quarantine.Refused](
				licensedPrivacyRule("/identity_id", events.PrivacyFieldIdentityExact),
				licensedPrivacyRule("/reason", events.PrivacyFieldFreeTextClear),
			)),
		entry(quarantine.EventTypeCompleted, 1,
			rejectingTypedLicensedPrivacyPolicy[quarantine.Completed]()),
		entry(quarantine.EventTypeReleased, 1,
			typedLicensedPrivacyPolicy[quarantine.Released](
				licensedPrivacyRule("/justification_ref", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/release_reason_text", events.PrivacyFieldFreeTextClear),
			)),

		// VDEC dependency and completion events are not signed artifacts. Stable
		// object identifiers can carry an erased identity token, while free-form
		// release reasons are cleared as one field.
		entry(depstate.TypeDependencyRegistered, depstate.SchemaV1,
			typedLicensedPrivacyPolicy[depstate.DependencyRegisteredV1](
				licensedPrivacyRule("/key_id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/dependent/id", events.PrivacyFieldSubjectToken),
			)),
		entry(depstate.TypeDependencyReleased, depstate.SchemaV1,
			typedLicensedPrivacyPolicy[depstate.DependencyReleasedV1](
				licensedPrivacyRule("/key_id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/dependent/id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/reason", events.PrivacyFieldFreeTextClear),
			)),
		entry(depstate.TypeDependencyErasureDesignated, depstate.SchemaV1,
			typedLicensedPrivacyPolicy[depstate.DependencyErasureDesignatedV1](
				licensedPrivacyRule("/key_id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/dependent/id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/designation_ref", events.PrivacyFieldSubjectToken),
			)),
		entry(depstate.TypeReprotectionCompleted, depstate.SchemaV1,
			typedLicensedPrivacyPolicy[depstate.ReprotectionCompletedV1](
				licensedPrivacyRule("/key_id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/dependent/id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/successor_key_id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/credential_supersession/old_credential_id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/credential_supersession/new_credential_id", events.PrivacyFieldSubjectToken),
			)),
		entry(depstate.TypeRevocationCompleted, depstate.SchemaV1,
			typedLicensedPrivacyPolicy[depstate.RevocationCompletedV1](
				licensedPrivacyRule("/key_id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/dependent/id", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/destination", events.PrivacyFieldSubjectToken),
			)),
		entry(reprotect.TypeCredentialSupersession, depstate.SchemaV1,
			typedLicensedPrivacyPolicy[reprotect.CredentialSupersession](
				licensedPrivacyRule("/OldCredentialID", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/NewCredentialID", events.PrivacyFieldSubjectToken),
				licensedPrivacyRule("/SuccessorKeyID", events.PrivacyFieldSubjectToken),
			)),
		entry(retirement.TypeRetirementRequested, retirement.SchemaV1,
			typedLicensedPrivacyPolicy[retirement.RequestedV1](
				licensedPrivacyRule("/tenant_id", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/key_id", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/signer_handle", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/required_set", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/required_set_digest", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/audit_chain_head", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/completion_events_digest", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/revocation_completion_digest", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/key_class", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/approvals/*", events.PrivacyFieldIdentityExact),
			)),
		entry(retirement.TypeRetirementRefused, retirement.SchemaV1,
			typedLicensedPrivacyPolicy[retirement.RefusedV1](
				licensedPrivacyRule("/tenant_id", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/key_id", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/command_event_id", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/refusal_record", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/signer_evidence", events.PrivacyFieldOpaqueExact),
			)),
		entry(retirement.TypeDestructionRecorded, retirement.SchemaV1,
			typedLicensedPrivacyPolicy[retirement.RecordedV1](
				licensedPrivacyRule("/tenant_id", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/key_id", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/command_event_id", events.PrivacyFieldOpaqueExact),
				licensedPrivacyRule("/record", events.PrivacyFieldOpaqueExact),
			)),

		// The BYOK/KMIP server owns both replay state and audit-shaped payloads.
		entry("kmip.state.object.created", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPStateEvent]()),
		entry("kmip.state.object.registered", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPStateEvent]()),
		entry("kmip.state.object.rekeyed", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPStateEvent]()),
		entry("kmip.state.object.revoked", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPStateEvent]()),
		entry("kmip.state.object.destroyed", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPStateEvent]()),
		entry("kmip.unauthenticated", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPUnauthenticated]()),
		entry("kmip.object.created", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPObjectCreated]()),
		entry("kmip.object.registered", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPObjectCreated]()),
		entry("kmip.object.rekeyed", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPObjectRekeyed]()),
		entry("kmip.object.revoke", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPObjectTransitioned]()),
		entry("kmip.object.destroyed", 1,
			rejectingTypedLicensedPrivacyPolicy[licensedKMIPObjectDestroyed]()),

		entry(silo.LaneProbeEventType, 1,
			rejectingTypedLicensedPrivacyPolicy[licensedSiloLaneProbe]()),

		entry(delegation.TypeDelegationRecorded, delegation.DelegationRecordedSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[delegation.DelegationRecordedV1]()),
		entry(delegation.TypeIssuanceRecorded, delegation.IssuanceRecordedSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[delegation.IssuanceRecordedV1]()),
		entry(delegation.TypeRefusalRecorded, delegation.RefusalRecordedSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[delegation.RefusalRecordedV1]()),
		entry(delegation.TypeRevocationDirective, delegation.RevocationDirectiveSchemaV1,
			typedLicensedPrivacyPolicy[delegation.RevocationDirectiveV1](
				licensedPrivacyRule("/subject_id", events.PrivacyFieldIdentityExact),
				licensedPrivacyRule("/reason", events.PrivacyFieldFreeTextClear),
			)),

		entry(succession.TypeFinding, succession.FindingSchemaV1,
			typedLicensedPrivacyPolicy[succession.FindingV1](
				licensedPrivacyRule("/reason", events.PrivacyFieldFreeTextClear),
			)),
		entry(succession.TypeSuccession, succession.SuccessionSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[succession.SuccessionV1]()),
		entry(succession.TypeRetirement, succession.RetirementSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[succession.RetirementV1]()),
		entry(succession.TypeRPAck, succession.RPAckSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[succession.RPAckV1]()),
		entry(succession.TypeRefusal, succession.RefusalSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[succession.RefusalV1]()),
		entry(succession.TypeRewrapStage, succession.RewrapStageSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[succession.RewrapStageV1]()),
		entry(succession.TypeRewrapCompleted, succession.RewrapCompletedSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[succession.RewrapCompletedV1]()),
		entry(succession.TypeMisissuance, succession.MisissuanceSchemaV1,
			rejectingTypedLicensedPrivacyPolicy[succession.MisissuanceV1]()),
	}
	sort.Slice(catalog, func(i, j int) bool {
		if catalog[i].EventType == catalog[j].EventType {
			return catalog[i].SchemaVersion < catalog[j].SchemaVersion
		}
		return catalog[i].EventType < catalog[j].EventType
	})
	return catalog
}()

// LicensedProductionPrivacyEventSchemas returns a defensive, deterministic
// copy of the full-binary-only event vocabulary.
func LicensedProductionPrivacyEventSchemas() []events.ProductionPrivacyEventSchema {
	out := make([]events.ProductionPrivacyEventSchema, len(licensedProductionPrivacyEventCatalog))
	for i, entry := range licensedProductionPrivacyEventCatalog {
		out[i] = entry.ProductionPrivacyEventSchema
	}
	return out
}

func init() {
	seen := make(map[events.ProductionPrivacyEventSchema]struct{}, len(licensedProductionPrivacyEventCatalog))
	for _, entry := range licensedProductionPrivacyEventCatalog {
		if _, duplicate := seen[entry.ProductionPrivacyEventSchema]; duplicate {
			panic(fmt.Sprintf("ee: duplicate licensed privacy catalog entry for %s v%d", entry.EventType, entry.SchemaVersion))
		}
		seen[entry.ProductionPrivacyEventSchema] = struct{}{}
		if err := events.RegisterPrivacyEventPolicy(entry.EventType, entry.SchemaVersion, entry.Policy); err != nil {
			panic(fmt.Sprintf("ee: register licensed privacy catalog entry %s v%d: %v", entry.EventType, entry.SchemaVersion, err))
		}
	}
}
