// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/connector"
	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/custody"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	ephemerallib "trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/privacyref"
	"trstctl.com/trstctl/internal/revocationhealth"
	"trstctl.com/trstctl/internal/rotationcommand"
	"trstctl.com/trstctl/internal/store"
)

// Event types for the served domain (AN-2). Every served mutation emits one of
// these; the read model is rebuilt by applying them. They are the contract
// between the command side (which appends them) and the projector (which builds
// the read model from them).
const (
	EventTenantRegistered            = "tenant.registered"
	EventTenantOffboarded            = "tenant.offboarded"
	EventOwnerCreated                = "owner.created"
	EventOwnerUpdated                = "owner.updated"
	EventOwnershipAttested           = "owner.ownership_attested"
	EventOwnerReattestationRequested = "owner.reattestation.requested"
	EventOwnershipExceptionGranted   = "ownership.exception.granted"
	EventOwnershipExceptionRevoked   = "ownership.exception.revoked"
	// I2: an external source's reconciliation against recorded ownership. It
	// carries BOTH halves — what was applied and what was refused — because a
	// replay that reconstructed only the applied half would rebuild an estate
	// with no record of the disagreements somebody still has to resolve.
	EventOwnershipReconciled = "ownership.reconciled"
	// I2: a tenant's standing instruction to re-read its CMDB.
	EventCMDBScheduleConfigured = "cmdb.schedule.configured"
	// I3: a first-class issuance request and every decision on it. The whole
	// point of the object is that a denial and an expiry are DIFFERENT and both
	// visible, so the decision is an event rather than a column somebody
	// overwrote.
	EventIssuanceRequestOpened  = "issuance.request.opened"
	EventIssuanceRequestDecided = "issuance.request.decided"
	// I3: a tenant's standing instruction to read its ITSM for
	// certificate-request tickets.
	EventTicketIntakeConfigured = "ticket.intake.configured"
	// I4: one typed enrollment refusal. The envelope carries tenant_id and time;
	// PostgreSQL collapses repeats into a tenant-local bounded projection.
	EventEnrollmentDiagnosticObserved = "enrollment.diagnostic.observed"
	// I5: one MDM device record joined to one SCEP transaction.
	EventMDMDeviceCorrelated = "mdm.device.correlated"
	// I5: a tenant's standing instruction to re-read an MDM.
	EventMDMPollConfigured = "mdm.poll.configured"
	// B6: the constrained edge sub-CA ledger. The policy event is a segment's
	// opt-in (attestation roots + the identifiers its delegations are scoped
	// to); issued/revoked are the delegated CA's lifecycle; reconciled is one
	// locally-issued leaf reported back to the brain — the record that keeps a
	// no-path host's issuance from being shadow issuance.
	EventEdgeSegmentPolicySet   = "edge.segment.policy_set"
	EventEdgeDelegationIssued   = "edge.delegation.issued"
	EventEdgeDelegationRevoked  = "edge.delegation.revoked"
	EventEdgeIssuanceReconciled = "edge.issuance.reconciled"
	// F4: one sweep of an AD CS certificate database, summarized by disposition.
	EventADCSDatabaseIngested = "adcs.ca_database.ingested"
)

// edgeIssuanceCertNamespace derives stable inventory row ids for reconciled
// edge leaves, so direct projection and tail replay converge on one row.
var edgeIssuanceCertNamespace = uuid.MustParse("7be1a6f4-52f0-5c2e-9d61-8a7ce3f14b02")

const (
	// I2: an operator closing an ownership disagreement. An event because the
	// resolution is a JUDGEMENT — which side was right and why — and a
	// judgement that lives only in a mutable column cannot be audited later.
	EventOwnershipConflictResolved = "ownership.conflict.resolved"
	// A5: a staged agent-upgrade campaign and every state change on it. The
	// halt is the product, so it is an event: an automatic halt that lived only
	// in a mutable column could not be audited after the fact.
	EventAgentUpgradeCampaignOpened   = "agent.upgrade.campaign.opened"
	EventAgentUpgradeCampaignAdvanced = "agent.upgrade.campaign.advanced"
	EventAgentUpgradeRingAssigned     = "agent.upgrade.ring.assigned"
	EventAgentUpgradeRingDispatched   = "agent.upgrade.ring.dispatched"
	EventOwnerDeleted                 = "owner.deleted"
	EventIssuerCreated                = "issuer.created"
	EventIdentityCreated              = "identity.created"
	EventIdentityIssued               = "identity.issued"
	EventIdentityDeployed             = "identity.deployed"
	EventIdentityRevoked              = "identity.revoked"
	EventIdentityRenewing             = "identity.renewing"
	EventIdentityRenewed              = "identity.renewed"
	EventIdentityRetired              = "identity.retired"
	EventCertificateRecorded          = "certificate.recorded"
	// CertificateApprovalEventSchemaVersion adds both the exact one-shot
	// approval and the privacy-stable command binding recomputed from the issued
	// certificate. Version 1 remains replayable for ordinary inventory and
	// historical issuance events. The incomplete draft v2 shape is deliberately
	// not accepted because it could attach authority A to certificate B.
	CertificateApprovalEventSchemaVersion         = 3
	EventCertificateRevoked                       = "certificate.revoked"
	EventCertificateSuperseded                    = "certificate.superseded"
	EventCAIssuedCertificate                      = "ca.certificate.issued"
	EventCACertificateRevoked                     = "ca.certificate.revoked"
	EventCACeremonyStarted                        = "ca.ceremony.started"
	EventCACeremonyApproved                       = "ca.ceremony.approved"
	EventCARootCreated                            = "ca.root.created"
	EventCAAuthorityImported                      = "ca.authority.imported"
	EventCAAuthorityRotated                       = "ca.authority.rotated"
	EventCAAuthorityRekeyed                       = "ca.authority.rekeyed"
	EventCAIntermediateCreated                    = "ca.intermediate.created"
	EventCAIntermediateCSRSignRequested           = "ca.intermediate_csr.sign_requested"
	EventCAIntermediateCSRIssued                  = "ca.intermediate_csr.issued"
	EventCAEndEntityIssued                        = "ca.endentity.issued"
	EventCACrossSigned                            = "ca.cross_signed"
	EventBreakglassIssued                         = "breakglass.issued"
	EventBreakglassCARotated                      = "breakglass.ca.rotated"
	EventBreakglassCACrossSigned                  = "breakglass.ca.cross_signed"
	EventCRLPublished                             = "ca.crl.published"
	EventOCSPResponderRotated                     = "ca.ocsp_responder.rotated"
	EventAgentHeartbeat                           = "agent.heartbeat"
	EventAgentCertRenewed                         = "agent.cert.renewed"
	EventAgentCertRevoked                         = "agent.cert.revoked"
	EventAgentOffboarded                          = "agent.offboarded"
	EventProfileCreated                           = "profile.created"
	EventProfileUpdated                           = "profile.updated"
	EventDiscoverySegmentUpserted                 = "discovery.segment.upserted"
	EventDiscoverySourceUpserted                  = "discovery.source.upserted"
	EventDiscoveryScheduleUpserted                = "discovery.schedule.upserted"
	EventDiscoveryRunQueued                       = "discovery.run.queued"
	EventDiscoveryRunStarted                      = "discovery.run.started"
	EventDiscoveryFindingRecorded                 = "discovery.finding.recorded"
	EventDiscoveryFindingTriageChanged            = "discovery.finding.triage_changed"
	EventDiscoveryRunCompleted                    = "discovery.run.completed"
	EventADCSInventoryObserved                    = "adcs.template.inventory.observed"
	EventRevocationProbeQueued                    = "revocation.probe.queued"
	EventRevocationHealthObserved                 = "revocation.health.observed"
	EventMigrationRunRecorded                     = "migration.run.recorded"
	EventACMEDNS01ProviderConfigUpserted          = "acme.dns01.provider_config.upserted"
	EventACMEDNS01ProviderConfigDeleted           = "acme.dns01.provider_config.deleted"
	EventACMEDNS01Preflighted                     = "acme.dns01.preflighted"
	EventACMEDNS01RecordPresented                 = "acme.dns01.record.presented"
	EventACMEDNS01RecordCleaned                   = "acme.dns01.record.cleaned"
	EventACMEUpstreamAuthorizationObserved        = "acme.dns01.upstream.authorization.observed"
	EventEndpointVerified                         = "endpoint.verification.observed"
	EventMDMSCEPPolicyUpserted                    = "mdm.scep_policy.upserted"
	EventMDMSCEPPolicyDeleted                     = "mdm.scep_policy.deleted"
	EventMDMSCEPChallengeRotated                  = "mdm.scep_challenge.rotated"
	EventWorkloadAttesterTrustSourceUpserted      = "workload.attester_trust_source.upserted"
	EventWorkloadAttesterTrustSourceRotated       = "workload.attester_trust_source.rotated"
	EventWorkloadAttesterTrustSourceRevoked       = "workload.attester_trust_source.revoked"
	EventWorkloadAttesterTrustSourceDeleted       = "workload.attester_trust_source.deleted"
	EventComplianceReportScheduleUpserted         = "compliance.report_schedule.upserted"
	EventSecretRotationScheduleUpserted           = "secret.rotation_schedule.upserted"
	EventSecretRotationScheduleRan                = "secret.rotation_schedule.ran"
	EventNotificationRead                         = "notification.read"
	EventNotificationChannelUpserted              = "notification.channel.upserted"
	EventNotificationChannelDeleted               = "notification.channel.deleted"
	EventNotificationRoutingPolicyUpserted        = "notification.routing_policy.upserted"
	EventNotificationRoutingPolicyDeleted         = "notification.routing_policy.deleted"
	EventNotificationThresholdDelivered           = "notification.threshold.delivered"
	EventNotificationTestQueued                   = "notification.test.queued"
	EventNotificationDeliveryRecorded             = "notification.delivery.recorded"
	EventCBOMAssetObserved                        = "cbom.asset.observed"
	EventLicensedCryptoMigrationStarted           = "licensed_crypto.migration.started"
	EventLicensedCryptoMigrationAssetCompleted    = "licensed_crypto.migration.asset_completed"
	EventLicensedCryptoMigrationRollbackCompleted = "licensed_crypto.migration.rollback_completed"
	EventDeploymentTargetUpserted                 = "deployment_target.upserted"
	EventDeploymentTargetDeleted                  = "deployment_target.deleted"
	EventIdentityConnectorTargetBound             = "identity.connector_target_bound"
	EventConnectorDeliveryRecorded                = "connector.delivery.recorded"
	EventLifecycleRotationRecorded                = "lifecycle.rotation.recorded"
	EventOutboxReconciliationConflictRecorded     = "outbox.reconciliation_conflict.recorded"
	EventIncidentExecutionRecorded                = "incident.execution.recorded"
	EventIncidentFleetReissuanceRecorded          = "incident.fleet_reissuance.recorded"
	EventRemediationPlaybookRunRecorded           = "remediation.playbook_run.recorded"
	EventResponseIntegrationDispatched            = "response.integration.dispatched"
	EventPrivacySubjectErased                     = "privacy.subject.erased"
	EventHistoryTenantDataRewriteContinuity       = "history.tenant_data_rewrite.continuity"
	EventPrivacyRetentionEnforced                 = "privacy.retention.enforced"
	EventPrivacyArchiveErasureAttested            = "privacy.archive_erasure.attested"
	EventTenantMemberUpserted                     = "tenant.member.upserted"
	EventTenantMemberOffboarded                   = "tenant.member.offboarded"
	EventAPITokenCreated                          = "api_token.created"
	EventAPITokenRevoked                          = "api_token.revoked"
	EventPAMSessionStarted                        = "pam.session.started"
	EventPAMSessionExpired                        = "pam.session.expired"
	EventMachineSessionStarted                    = "secrets.session.started"
	EventMachineSessionRevoked                    = "secrets.session.revoked"
	EventMachineAuthMethodDisabled                = "secrets.auth_method.disabled"
	EventMachineAuthMethodEnabled                 = "secrets.auth_method.enabled"
	EventNHIAccessReviewCampaignStarted           = "nhi.access_review.campaign.started"
	EventNHIAccessReviewItemDecided               = "nhi.access_review.item.decided"
	EventPQCMigrationCampaignStarted              = "pqc.migration_campaign.started"
	EventPQCMigrationCampaignUpdated              = "pqc.migration_campaign.updated"
	EventPQCMigrationCampaignFindingDispositioned = "pqc.migration_campaign.finding_dispositioned"
	EventPQCMigrationCampaignClosed               = "pqc.migration_campaign.closed"
	EventAccessChangeRequestCreated               = "access.change_request.created"
	EventAccessChangeRequestDecided               = "access.change_request.decided"
	EventTenantKeyDomainMigrationStarted          = "tenant.key_domain.migration_started"
	EventTenantKeyDomainMigrationProgressed       = "tenant.key_domain.migration_progressed"
	EventTenantKeyDomainMigrationCompleted        = "tenant.key_domain.migration_completed"
	EventTenantKeyDomainMigrationFailed           = "tenant.key_domain.migration_failed"
	EventTenantKeyDomainSealRequested             = "tenant.key_domain.seal_requested"
	EventTenantKeyDomainSealFailed                = "tenant.key_domain.seal_failed"
	EventTenantKeyDomainSealed                    = "tenant.key_domain.sealed"
	EventTenantKeyDomainUnsealRequested           = "tenant.key_domain.unseal_requested"
	EventTenantKeyDomainUnsealed                  = "tenant.key_domain.unsealed"
	EventRestoreDrillRecorded                     = "backup.restore_drill.recorded"

	// initialIdentityStatus is the lifecycle status a newly-created identity
	// holds until a transition moves it (matches the identities.status column
	// default and orchestrator.StateRequested).
	initialIdentityStatus = "requested"
)

// ProfileEventSchemaVersion is the first profile event shape that carries the full
// certificate_profiles row. Version 1 profile events were audit-only
// name/version breadcrumbs.
const ProfileEventSchemaVersion = 2

// CRLPublishedEventSchemaVersion is the first ca.crl.published shape that carries
// CRL artifact metadata for full, sharded, and delta CRLs. Version 1 was
// audit-only metadata and version 2 rebuilt only the legacy full CRL row.
const CRLPublishedEventSchemaVersion = 3

// LifecycleEventSchemaVersion is the first identity lifecycle payload shape that
// can carry the served request Idempotency-Key used to bind async outbox effects.
const LifecycleEventSchemaVersion = 2

// LifecycleSideEffectEventSchemaVersion is the first identity lifecycle payload
// shape that carries the replayable outbox side-effect payload and event-derived
// idempotency key. Older lifecycle events are reconciled through the legacy
// metadata-only fallback.
const LifecycleSideEffectEventSchemaVersion = 3

// LifecycleApprovalEventSchemaVersion carries the exact one-shot approval use.
// Rebuild consumes the same request while applying the lifecycle event, so the
// live path and a zero-state replay produce identical authority state.
const LifecycleApprovalEventSchemaVersion = 4

// LifecycleIssuanceEventSchemaVersion carries the exact profile revision and
// clamped TTL for an issuance that does not require an approval. Like v4, its
// outbox body is derived from the canonical outer event instead of being copied
// into side_effect.payload.
const LifecycleIssuanceEventSchemaVersion = 5

// LifecycleOwnershipReadinessEventSchemaVersion binds a deployed/renewed event
// to the exact current owner attestation or active exception that authorized the
// steady-state edge. Earlier history remains readable; new served writes never
// emit a steady-state event without this proof when the cadence gate is enabled.
const LifecycleOwnershipReadinessEventSchemaVersion = 6

// OwnerDepthEventSchemaVersion is the first owner.created/owner.updated shape
// that carries the complete I1 application model. V1 remains readable and is
// deliberately applied as a basic-field update so absent legacy fields cannot
// erase depth added after migration.
const OwnerDepthEventSchemaVersion = 2

// CAAuthorityCreatedEventSchemaVersion is the first CA create/import event shape
// that carries the full ca_authorities row. Version 1 events were audit-only
// breadcrumbs and cannot rebuild the authority read model.
const CAAuthorityCreatedEventSchemaVersion = 2

// PrivacySubjectErasedOperationEventSchemaVersion is the first
// privacy.subject.erased shape that binds the durable operation and canonical
// authenticated command. Version 1 events remain replayable but cannot act as
// an AN-5 receiver.
const PrivacySubjectErasedOperationEventSchemaVersion = 2

// PrivacySubjectErasedEventSchemaVersion is the current privacy.subject.erased
// shape. Version 3 adds the closed, non-PII disposition of every append-recovery
// fence changed by the SQL preparation, so cold history proves why no raw
// command can be resurrected after erasure.
const PrivacySubjectErasedEventSchemaVersion = 3

// Payloads. Each carries everything needed to reconstruct the read-model row
// (the surrogate id included), so a replay is deterministic. created_at is NOT a
// payload field: it is the event's own time, set by the projector, so a rebuild
// reproduces it exactly.

// OwnerCreated is the payload of an owner.created event.
type OwnerCreated struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	ApplicationID   string   `json:"application_id,omitempty"`
	Service         string   `json:"service,omitempty"`
	BusinessUnit    string   `json:"business_unit,omitempty"`
	Environment     string   `json:"environment,omitempty"`
	EscalationChain []string `json:"escalation_chain,omitempty"`
}

// OwnerUpdated is the payload of an owner.updated event.
type OwnerUpdated struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	ApplicationID   string   `json:"application_id,omitempty"`
	Service         string   `json:"service,omitempty"`
	BusinessUnit    string   `json:"business_unit,omitempty"`
	Environment     string   `json:"environment,omitempty"`
	EscalationChain []string `json:"escalation_chain,omitempty"`
}

type OwnershipAttested struct {
	OwnerID     string    `json:"owner_id"`
	AttestedBy  string    `json:"attested_by"`
	AttestedAt  time.Time `json:"attested_at"`
	ModelDigest string    `json:"model_digest"`
}

type OwnerReattestationRequested struct {
	OwnerID              string     `json:"owner_id"`
	VerifiedFor          *time.Time `json:"verified_for,omitempty"`
	DueAt                time.Time  `json:"due_at"`
	RequestedAt          time.Time  `json:"requested_at"`
	CadenceSeconds       int        `json:"cadence_seconds"`
	OwnerName            string     `json:"owner_name"`
	OwnerEmail           string     `json:"owner_email,omitempty"`
	EscalationRecipients []string   `json:"escalation_recipients,omitempty"`
}

type OwnershipExceptionGranted struct {
	ID         string    `json:"id"`
	IdentityID string    `json:"identity_id"`
	Reason     string    `json:"reason"`
	GrantedBy  string    `json:"granted_by"`
	GrantedAt  time.Time `json:"granted_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type OwnershipExceptionRevoked struct {
	ID        string    `json:"id"`
	RevokedBy string    `json:"revoked_by"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// AgentUpgradeCampaignOpened is the payload of agent.upgrade.campaign.opened (A5).
//
// Artifacts is the operator-published download set for the target version.
// Empty means an OBSERVE-ONLY campaign: rings gate on the versions the fleet
// reports, but nothing is dispatched — which is the only mode that existed
// before dispatch was built, and remains valid for fleets upgraded by an
// external mechanism.
type AgentUpgradeCampaignOpened struct {
	ID            string           `json:"id"`
	TargetVersion string           `json:"target_version"`
	CreatedBy     string           `json:"created_by,omitempty"`
	Artifacts     []fleet.Artifact `json:"artifacts,omitempty"`
}

// AgentUpgradeCampaignAdvanced records every state change, including the halt.
//
// Reason is not decoration: "halted" alone sends an operator to read logs, and
// the whole point of an automatic halt is that it explains itself.
type AgentUpgradeCampaignAdvanced struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	CurrentRing  string `json:"current_ring,omitempty"`
	HaltedAtRing string `json:"halted_at_ring,omitempty"`
	Reason       string `json:"reason"`
}

// AgentUpgradeRingAssigned places an agent in a rollout ring. Empty ring means
// UNASSIGNED and is never read as "broad".
type AgentUpgradeRingAssigned struct {
	AgentID string `json:"agent_id"`
	Ring    string `json:"ring"`
}

// AgentUpgradeRingDispatched records one ring's dispatch: which agents were
// handed an agent.upgrade job, under which round (A5).
//
// The job keys are IN the event because the outbox rows are enqueued in the
// same transaction this event projects in (AN-6), keyed deterministically —
// replaying the event re-derives exactly the same rows, so a crash between
// append and enqueue heals without dispatching anything twice.
type AgentUpgradeRingDispatched struct {
	CampaignID    string           `json:"campaign_id"`
	Ring          string           `json:"ring"`
	Round         int              `json:"round"`
	TargetVersion string           `json:"target_version"`
	Artifacts     []fleet.Artifact `json:"artifacts,omitempty"`
	Jobs          []UpgradeJobRef  `json:"jobs"`
}

// UpgradeJobRef names one dispatched agent and its outbox idempotency key.
type UpgradeJobRef struct {
	AgentID string `json:"agent_id"`
	JobKey  string `json:"job_key"`
}

// OwnershipConflictResolved is the payload of ownership.conflict.resolved (I2).
//
// Resolution is required and free-text on purpose: "resolved" with no reason
// tells the next reader nothing about which side was right, and a queue whose
// closed entries explain nothing is one people stop trusting.
type OwnershipConflictResolved struct {
	ID         string    `json:"id"`
	ResolvedBy string    `json:"resolved_by"`
	Resolution string    `json:"resolution"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// MDMDeviceCorrelated is the payload of an mdm.device.correlated event (I5).
//
// InstallState is 'ok' | 'failed' | 'unknown' and UNKNOWN IS NOT FAILED: an MDM
// we could not reach tells us nothing about the device, and recording that as a
// failure would send somebody to re-push a profile that is already installed.
type MDMDeviceCorrelated struct {
	MDM           string     `json:"mdm"`
	MDMDeviceID   string     `json:"mdm_device_id"`
	DeviceName    string     `json:"device_name,omitempty"`
	SerialNumber  string     `json:"serial_number,omitempty"`
	TransactionID string     `json:"transaction_id,omitempty"`
	IdentityID    string     `json:"identity_id,omitempty"`
	InstallState  string     `json:"install_state"`
	InstallDetail string     `json:"install_detail,omitempty"`
	ObservedAt    *time.Time `json:"observed_at,omitempty"`
}

// MDMPollConfigured is the payload of mdm.poll.configured (I5). TokenRef is a
// REFERENCE such as secret://mdm/graph-token; a token value in an event is a
// token value in every backup and replica of the log.
type MDMPollConfigured struct {
	MDM               string   `json:"mdm"`
	BaseURL           string   `json:"base_url"`
	TokenRef          string   `json:"token_ref"`
	Filter            string   `json:"filter,omitempty"`
	IntervalSeconds   int      `json:"interval_seconds"`
	Enabled           bool     `json:"enabled"`
	AllowPrivate      bool     `json:"allow_private_endpoint,omitempty"`
	PrivateCIDRs      []string `json:"private_egress_cidrs,omitempty"`
	Execution         string   `json:"execution,omitempty"`
	RenewalWindowDays int      `json:"renewal_window_days,omitempty"`
}

// IssuanceRequestOpened is the payload of an issuance.request.opened event (I3).
//
// CSRPEM carries a certificate signing request — public material by
// construction. It must never carry a private key, and nothing in this system
// puts one here: the requester keeps the key.
type IssuanceRequestOpened struct {
	ID            string    `json:"id"`
	Subject       string    `json:"subject"`
	Profile       string    `json:"profile,omitempty"`
	CSRPEM        string    `json:"csr_pem,omitempty"`
	Requester     string    `json:"requester"`
	Justification string    `json:"justification,omitempty"`
	Origin        string    `json:"origin,omitempty"`
	TicketRef     string    `json:"ticket_ref,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// TicketIntakeConfigured is the payload of ticket.intake.configured (I3).
// TokenRef is a REFERENCE, never a token value.
type TicketIntakeConfigured struct {
	System             string   `json:"system"`
	InstanceURL        string   `json:"instance_url"`
	TokenRef           string   `json:"token_ref"`
	SNTable            string   `json:"sn_table"`
	Query              string   `json:"query,omitempty"`
	SubjectField       string   `json:"subject_field"`
	ProfileField       string   `json:"profile_field"`
	RequesterField     string   `json:"requester_field,omitempty"`
	JustificationField string   `json:"justification_field,omitempty"`
	IntervalSeconds    int      `json:"interval_seconds"`
	Enabled            bool     `json:"enabled"`
	AllowPrivate       bool     `json:"allow_private_endpoint,omitempty"`
	PrivateCIDRs       []string `json:"private_egress_cidrs,omitempty"`
}

// ADCSDatabaseIngested is the payload of adcs.ca_database.ingested (F4): the
// per-disposition summary of one CA-database sweep. The counts are the whole
// point — a single "certificates found" number would hide that half are
// pending approval, which is the one thing an operator ingesting the database
// needs to see.
type ADCSDatabaseIngested struct {
	CAConfig     string `json:"ca_config"`
	Issued       int    `json:"issued"`
	Pending      int    `json:"pending"`
	Revoked      int    `json:"revoked"`
	Denied       int    `json:"denied"`
	Failed       int    `json:"failed"`
	Unknown      int    `json:"unknown"`
	Unparsed     int    `json:"unparsed"`
	Total        int    `json:"total"`
	RowsRead     int    `json:"rows_read"`
	RowsRejected int    `json:"rows_rejected"`
	Source       string `json:"source,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}

// EdgeSegmentPolicySet is the payload of edge.segment.policy_set (B6).
type EdgeSegmentPolicySet struct {
	SegmentID           string   `json:"segment_id"`
	Enabled             bool     `json:"enabled"`
	AttestationRootsPEM []string `json:"attestation_roots_pem,omitempty"`
	PermittedDNSDomains []string `json:"permitted_dns_domains,omitempty"`
	ExcludedDNSDomains  []string `json:"excluded_dns_domains,omitempty"`
	SetBy               string   `json:"set_by,omitempty"`
}

// EdgeDelegationIssued is the payload of edge.delegation.issued (B6).
type EdgeDelegationIssued struct {
	ID                    string    `json:"id"`
	SegmentID             string    `json:"segment_id"`
	CAID                  string    `json:"ca_id"`
	Host                  string    `json:"host"`
	CommonName            string    `json:"common_name"`
	Serial                string    `json:"serial"`
	CertificatePEM        string    `json:"certificate_pem"`
	PermittedDNSDomains   []string  `json:"permitted_dns_domains"`
	ExcludedDNSDomains    []string  `json:"excluded_dns_domains,omitempty"`
	AttestedKeySHA256     string    `json:"attested_key_sha256"`
	AttestationCertSHA256 string    `json:"attestation_cert_sha256"`
	NotBefore             time.Time `json:"not_before"`
	NotAfter              time.Time `json:"not_after"`
}

// EdgeDelegationRevoked is the payload of edge.delegation.revoked (B6).
type EdgeDelegationRevoked struct {
	ID        string    `json:"id"`
	CAID      string    `json:"ca_id"`
	Serial    string    `json:"serial"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// EdgeIssuanceReconciled is the payload of edge.issuance.reconciled (B6): one
// leaf a delegated CA issued while its host had no path to the brain, verified
// on receipt (signature chains to the delegated CA; names checked against its
// constraints). WithinConstraints=false is a recorded VIOLATION, not a
// rejection — refusing the report would leave the shadow issuance invisible.
type EdgeIssuanceReconciled struct {
	DelegationID      string    `json:"delegation_id"`
	Host              string    `json:"host"`
	Serial            string    `json:"serial"`
	Subject           string    `json:"subject"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	IssuedAt          time.Time `json:"issued_at"`
	CertificateDER    []byte    `json:"certificate_der"`
	CertificatePEM    string    `json:"certificate_pem"`
	Fingerprint       string    `json:"fingerprint"`
	WithinConstraints bool      `json:"within_constraints"`
	Violation         string    `json:"violation,omitempty"`
}

// IssuanceRequestDecided is the payload of an issuance.request.decided event.
//
// DecidedBy is EMPTY for an expiry, and that is load-bearing: nobody decided,
// and attributing an expiry to a person would put a decision in the audit trail
// that no human ever made.
type IssuanceRequestDecided struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	DecidedBy  string    `json:"decided_by,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	IdentityID string    `json:"identity_id,omitempty"`
	DecidedAt  time.Time `json:"decided_at"`
}

// EnrollmentDiagnosticObserved is the immutable, secret-free diagnosis emitted
// at a protocol refusal boundary (I4). Tenant and observation time live in the
// event envelope so a producer cannot smuggle a different tenant into payload.
type EnrollmentDiagnosticObserved struct {
	Protocol    string `json:"protocol"`
	Step        string `json:"step"`
	Cause       string `json:"cause"`
	Summary     string `json:"summary"`
	Remediation string `json:"remediation,omitempty"`
}

// OwnershipReconciled is the payload of an ownership.reconciled event (I2).
type OwnershipReconciled struct {
	OwnerID string `json:"owner_id"`
	// Source is where the claim came from: "csv-import" or "cmdb". Never
	// "manual" — a reconcile is by definition not a human answering.
	Source     string                    `json:"source"`
	SourceRef  string                    `json:"source_ref"`
	ObservedAt time.Time                 `json:"observed_at"`
	Applied    []OwnershipFieldChange    `json:"applied,omitempty"`
	Conflicts  []OwnershipConflictRecord `json:"conflicts,omitempty"`
}

// OwnershipFieldChange is one field a reconcile set.
type OwnershipFieldChange struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// OwnershipConflictRecord is one disagreement a reconcile recorded. CurrentAttested
// says why: a refused change had an attested value on the stored side.
type OwnershipConflictRecord struct {
	Field           string `json:"field"`
	CurrentValue    string `json:"current_value"`
	CurrentSource   string `json:"current_source"`
	IncomingValue   string `json:"incoming_value"`
	IncomingSource  string `json:"incoming_source"`
	IncomingRef     string `json:"incoming_ref"`
	CurrentAttested bool   `json:"current_attested"`
}

// OwnershipReconciledFrom builds the event from a reconcile plan.
//
// ONE definition, called by both ingest paths (the CSV import and the CMDB
// scheduler). Two constructors for the same fact would drift, and a replay
// could then reconstruct one ingest path's history and not the other's.
func OwnershipReconciledFrom(ownerID, source, ref string, observed time.Time, plan ownership.Plan) OwnershipReconciled {
	ev := OwnershipReconciled{OwnerID: ownerID, Source: source, SourceRef: ref, ObservedAt: observed}
	for _, u := range plan.Apply {
		ev.Applied = append(ev.Applied, OwnershipFieldChange{Field: u.Field, Value: u.Value})
	}
	for _, c := range plan.Conflicts {
		ev.Conflicts = append(ev.Conflicts, OwnershipConflictRecord{
			Field: c.Field, CurrentValue: c.CurrentValue, CurrentSource: string(c.CurrentSource),
			IncomingValue: c.IncomingValue, IncomingSource: string(c.IncomingSource),
			IncomingRef: c.IncomingRef, CurrentAttested: c.CurrentAttested,
		})
	}
	return ev
}

// CMDBScheduleConfigured is the payload of a cmdb.schedule.configured event (I2).
// TokenRef is a REFERENCE such as env:TRSTCTL_SERVICENOW_TOKEN; a token value in
// an event is a token value in every backup and every replica of the log.
type CMDBScheduleConfigured struct {
	InstanceURL          string `json:"instance_url"`
	TokenRef             string `json:"token_ref"`
	CIQuery              string `json:"ci_query"`
	AllowPrivateEndpoint bool   `json:"allow_private_endpoint"`
	IntervalSeconds      int    `json:"interval_seconds"`
	Enabled              bool   `json:"enabled"`
	// Execution is the sync vantage (I2): "" / "control_plane", or "relay" to
	// dispatch the read to a network relay inside the segment. Absent on old
	// events, which decodes to "" — the control-plane behaviour they had.
	Execution string `json:"execution,omitempty"`
}

// OwnerDeleted is the payload of an owner.deleted event.
type OwnerDeleted struct {
	ID string `json:"id"`
}

// IssuerCreated is the payload of an issuer.created event.
type IssuerCreated struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Chain     []string `json:"chain"`
	PublicKey string   `json:"public_key"`
	Internal  bool     `json:"internal"`
}

// IdentityCreated is the payload of an identity.created event.
type IdentityCreated struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	OwnerID    string          `json:"owner_id"`
	IssuerID   *string         `json:"issuer_id"`
	Attributes json.RawMessage `json:"attributes"`
}

// CertificateRecorded is the payload of a certificate.recorded event.
//
// ReplacesID is optional (omitted on a first issuance, set when this certificate
// is the successor produced by a renewal/rotation, CORRECT-002): carrying the
// predecessor link in the event keeps the successor's replaces_id reconstructable
// from the log on a Rebuild(). Its projection also supersedes the predecessor in
// the same transaction as the successor insert. Adding this optional field is
// backward-compatible — older v1 events without it decode to nil — so the schema
// version is unchanged.
type CertificateRecorded struct {
	ID                     string     `json:"id"`
	CAID                   string     `json:"ca_id,omitempty"`
	OwnerID                *string    `json:"owner_id"`
	Subject                string     `json:"subject"`
	SANs                   []string   `json:"sans"`
	Issuer                 string     `json:"issuer"`
	Serial                 string     `json:"serial"`
	Fingerprint            string     `json:"fingerprint"`
	KeyAlgorithm           string     `json:"key_algorithm"`
	NotBefore              *time.Time `json:"not_before"`
	NotAfter               *time.Time `json:"not_after"`
	DeploymentLocation     string     `json:"deployment_location"`
	Source                 string     `json:"source"`
	ReplacesID             *string    `json:"replaces_id,omitempty"`
	CertificateDER         []byte     `json:"certificate_der,omitempty"`
	CertificatePEM         []byte     `json:"certificate_pem,omitempty"`
	IssuanceResponse       []byte     `json:"issuance_response,omitempty"`
	IssuanceIdempotencyKey string     `json:"issuance_idempotency_key,omitempty"`
	IssuanceRequestBinding string     `json:"issuance_request_binding,omitempty"`
	// Approval and ApprovalBinding are present only on schema v3. The projector
	// recomputes the binding from the public certificate before consuming the
	// exact request/digest in the same PostgreSQL transaction as the row.
	Approval        *store.OperationApprovalUse   `json:"approval,omitempty"`
	ApprovalBinding *ephemerallib.ApprovalBinding `json:"approval_binding,omitempty"`
	// KeyOrigin records whose process generated this certificate's private key
	// (epic B5's vocabulary, internal/custody).
	//
	// It travels in the EVENT, not merely on the struct the issuing code built.
	// It was previously absent here, so every issuing path that set
	// Certificate.KeyOrigin — the CSR-first mint, and B2's host-generated
	// renewal — had the value silently dropped at the projection boundary and
	// wrote an empty column. The custody claim existed in the code and in the
	// documentation and nowhere an auditor could read it.
	//
	// Event-sourced state means a Rebuild() must reproduce it too, which is the
	// other reason it belongs on the event rather than being written directly.
	KeyOrigin string `json:"key_origin,omitempty"`
	// KeyStorage, KeyExportable and KeyGeneratedBy are the rest of the custody
	// record (B5).
	//
	// They were added to the schema and to the issuing code and to the served
	// API, and never to this event — so every one of them projected as empty
	// while three layers of the system agreed they had been recorded. The
	// key_origin half of the same bug was found while implementing B2; these
	// three were found by going back and looking, which is the only way this
	// class of defect ever is.
	KeyStorage     string `json:"key_storage,omitempty"`
	KeyExportable  string `json:"key_exportable,omitempty"`
	KeyGeneratedBy string `json:"key_generated_by,omitempty"`
}

// CertificateApprovalEventID is the only target-event identity allowed to
// spend one approved certificate command. It is derived from the request and
// intent digest, so a second retained event cannot choose another identity to
// reuse the same capability.
func CertificateApprovalEventID(tenantID string, approval store.OperationApprovalUse) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("approved-certificate-event\x00"+tenantID+"\x00"+
		approval.RequestID+"\x00"+approval.IntentDigest)).String()
}

// CertificateApprovalRowID gives the approved command one stable inventory row
// across request retries, tail replay, and a cold rebuild.
func CertificateApprovalRowID(tenantID string, approval store.OperationApprovalUse) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("approved-certificate-row\x00"+tenantID+"\x00"+
		approval.RequestID+"\x00"+approval.IntentDigest)).String()
}

// ValidateApprovedCertificatePayload performs the command-side-safe half of the
// v3 projection checks. Producers call it before appending, and the projector
// repeats it for retained events and cold rebuilds.
func ValidateApprovedCertificatePayload(event events.Event, payload CertificateRecorded) error {
	use := payload.Approval
	binding := payload.ApprovalBinding
	if use == nil || binding == nil {
		return fmt.Errorf("%w: approved certificate has no exact authority", store.ErrApprovalNotReady)
	}
	if use.ResourceKind != "ephemeral" || use.Action != "issue" ||
		use.FromState != "attested" || use.TargetVersion != 0 ||
		!strings.HasPrefix(use.ResourceID, "ephemeral:") ||
		strings.TrimPrefix(use.ResourceID, "ephemeral:") == "" {
		return fmt.Errorf("%w: approved certificate resource is not an ephemeral issuance", store.ErrApprovalDrifted)
	}
	toState, err := binding.ToState()
	if err != nil {
		return fmt.Errorf("%w: %v", store.ErrApprovalDrifted, err)
	}
	if use.ToState != toState || event.ID != CertificateApprovalEventID(event.TenantID, *use) ||
		payload.ID != CertificateApprovalRowID(event.TenantID, *use) ||
		payload.IssuanceIdempotencyKey != "ephemeral-issue:"+use.RequestID ||
		payload.CAID != binding.CAID {
		return fmt.Errorf("%w: approved certificate command identity changed", store.ErrApprovalDrifted)
	}
	info, err := binding.ValidateCertificate(payload.CertificateDER, payload.Source, event.Time)
	if err != nil {
		if errors.Is(err, ephemerallib.ErrApprovalCertificateLifetime) {
			return fmt.Errorf("%w: %w", store.ErrApprovalDrifted, err)
		}
		return fmt.Errorf("%w: %v", store.ErrApprovalDrifted, err)
	}
	if payload.Fingerprint != info.SHA256Fingerprint || payload.Serial != info.SerialNumber ||
		payload.KeyAlgorithm != info.KeyAlgorithm || payload.NotBefore == nil || payload.NotAfter == nil ||
		!payload.NotBefore.Equal(info.NotBefore) || !payload.NotAfter.Equal(info.NotAfter) {
		return fmt.Errorf("%w: approved certificate projection metadata differs from DER", store.ErrApprovalDrifted)
	}
	if !approvedCertificateTextMetadataMatches(event.TenantID, payload, info) {
		return fmt.Errorf("%w: approved certificate subject, issuer, or SAN metadata differs from DER", store.ErrApprovalDrifted)
	}
	if payload.OwnerID != nil || payload.DeploymentLocation != "" || payload.ReplacesID != nil ||
		len(payload.CertificatePEM) != 0 || len(payload.IssuanceResponse) != 0 ||
		payload.IssuanceRequestBinding != "" || payload.KeyOrigin != string(custody.OriginRequester) ||
		payload.KeyStorage != "" || payload.KeyExportable != "" || payload.KeyGeneratedBy != "" {
		return fmt.Errorf("%w: approved ephemeral certificate carries unsupported projection metadata", store.ErrApprovalDrifted)
	}
	return nil
}

// ApprovedCertificateSemanticDigest is the immutable target-event identity kept
// beside the first-command fence. It includes the DER and every non-erasable
// envelope/payload field. Requester and certificate text columns are normalized:
// privacy erasure may pseudonymize those spellings, while the DER, approval
// command digest, public key, CA, lifetime, and event time remain unchanged.
func ApprovedCertificateSemanticDigest(event events.Event, payload CertificateRecorded) (string, error) {
	if payload.Approval == nil || payload.ApprovalBinding == nil {
		return "", errors.New("projections: approved certificate semantic digest lacks authority")
	}
	info, err := payload.ApprovalBinding.ValidateCertificate(payload.CertificateDER, payload.Source, event.Time)
	if err != nil {
		return "", err
	}
	normalized := payload
	if payload.Approval != nil {
		use := *payload.Approval
		use.Requester = ""
		use.Reason = ""
		use.EvidenceRefs = nil
		normalized.Approval = &use
	}
	normalized.Subject = info.Subject
	normalized.Issuer = info.Issuer
	normalized.SANs = certificateInfoSANs(info)
	var actor *events.Actor
	if event.Actor != nil {
		copyActor := *event.Actor
		copyActor.Subject = ""
		copyActor.Roles = append([]string(nil), event.Actor.Roles...)
		actor = &copyActor
	}
	basis := struct {
		ID            string              `json:"id"`
		Type          string              `json:"type"`
		TenantID      string              `json:"tenant_id"`
		Time          time.Time           `json:"time"`
		SchemaVersion int                 `json:"schema_version"`
		Actor         *events.Actor       `json:"actor,omitempty"`
		Payload       CertificateRecorded `json:"payload"`
	}{event.ID, event.Type, event.TenantID, event.Time.UTC(), schemaVersionOf(event), actor, normalized}
	raw, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	return cryptoboundary.SHA256Hex(append([]byte("trstctl:approved-certificate-event:v1\x00"), raw...)), nil
}

func certificateInfoSANs(info certinfo.Info) []string {
	sans := make([]string, 0, len(info.DNSNames)+len(info.IPAddresses)+len(info.EmailAddresses)+len(info.URIs))
	sans = append(sans, info.DNSNames...)
	sans = append(sans, info.IPAddresses...)
	sans = append(sans, info.EmailAddresses...)
	sans = append(sans, info.URIs...)
	return sans
}

func (p *Projector) validateApprovedCertificateTx(ctx context.Context, tx pgx.Tx, event events.Event, payload CertificateRecorded) error {
	if err := ValidateApprovedCertificatePayload(event, payload); err != nil {
		return err
	}
	request, err := p.store.GetOperationApprovalForUpdateTx(ctx, tx, event.TenantID, payload.Approval.RequestID)
	if err != nil {
		return err
	}
	expectedEvidence, err := payload.ApprovalBinding.EvidenceRefs()
	if err != nil {
		return fmt.Errorf("%w: %v", store.ErrApprovalDrifted, err)
	}
	// A rewritten history may intentionally clear old evidence before a
	// zero-state rebuild sees this target. In that case ToState still carries the
	// same command digest checked against Binding + DER above. When evidence is
	// retained, require exact parity as an additional corruption check.
	if len(request.EvidenceRefs) != 0 && !sameCertificateApprovalStrings(request.EvidenceRefs, expectedEvidence) {
		return fmt.Errorf("%w: approved certificate evidence changed", store.ErrApprovalDrifted)
	}
	return nil
}

func (p *Projector) resolveApprovedCertificateFenceUseTx(
	ctx context.Context,
	tx pgx.Tx,
	event events.Event,
	payload *CertificateRecorded,
) error {
	fence, currentUse, privacyRewritten, err := p.store.LockApprovedTargetFenceTx(ctx, tx,
		event.TenantID, store.ApprovedTargetEphemeralCertificate,
		payload.ApprovalBinding.ClientRequestIDSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	semantic, err := ApprovedCertificateSemanticDigest(event, *payload)
	if err != nil || semantic != fence.SemanticDigest {
		if err == nil {
			err = store.ErrIdempotencyConflict
		}
		return fmt.Errorf("%w: retained approved certificate differs from durable fence", err)
	}
	if !privacyRewritten {
		if !reflect.DeepEqual(event.Actor, fence.Actor) {
			return fmt.Errorf("%w: retained approved certificate actor differs from durable fence", store.ErrIdempotencyConflict)
		}
		return nil
	}
	if err := store.ValidateApprovedTargetActorPrivacyRewrite(event.TenantID,
		fence.Actor, currentUse.Requester, event.Actor); err != nil {
		return fmt.Errorf("%w: approved certificate actor privacy recovery differs", err)
	}
	var original CertificateRecorded
	if err := json.Unmarshal(fence.Payload, &original); err != nil {
		return fmt.Errorf("projections: decode approved certificate fence: %w", err)
	}
	if original.Approval == nil || payload.Approval == nil {
		return fmt.Errorf("%w: approved certificate privacy recovery lacks authority", store.ErrApprovalDrifted)
	}
	if err := store.ValidateApprovedTargetPrivacyRewrite(event.TenantID,
		*original.Approval, currentUse, *payload.Approval); err != nil {
		return fmt.Errorf("%w: approved certificate privacy recovery differs", err)
	}
	payload.Approval = &currentUse
	return nil
}

func approvedCertificateTextMetadataMatches(tenantID string, payload CertificateRecorded, info certinfo.Info) bool {
	wantSANs := certificateInfoSANs(info)
	if payload.Subject == info.Subject && payload.Issuer == info.Issuer &&
		sameCertificateApprovalStrings(payload.SANs, wantSANs) {
		return true
	}
	if len(info.URIs) != 1 {
		return false
	}
	subject, err := ephemerallib.SubjectFromSPIFFEID(info.URIs[0])
	if err != nil {
		return false
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef(tenantID, subject))
	redact := func(value string) string { return strings.ReplaceAll(value, subject, placeholder) }
	redactedSANs := make([]string, len(wantSANs))
	for i := range wantSANs {
		redactedSANs[i] = redact(wantSANs[i])
	}
	return payload.Subject == redact(info.Subject) && payload.Issuer == redact(info.Issuer) &&
		sameCertificateApprovalStrings(payload.SANs, redactedSANs)
}

func sameCertificateApprovalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// CertificateRevoked is the payload of a certificate.revoked event. The
// inventoried certificate is keyed by fingerprint; the projector sets its status
// to revoked with the reason and time. Driving the status change through an event
// (rather than a direct read-table UPDATE) keeps it reconstructable from the log
// on a Rebuild() (AN-2).
type CertificateRevoked struct {
	Fingerprint string    `json:"fingerprint"`
	CAID        string    `json:"ca_id,omitempty"`
	Serial      string    `json:"serial"`
	Reason      string    `json:"reason"`
	ReasonCode  int       `json:"reason_code,omitempty"`
	RevokedAt   time.Time `json:"revoked_at"`
}

// PrivacySubjectErased is the payload of a privacy.subject.erased event. It
// carries only tenant-bound subject references and stable row selectors, never
// the raw subject value being erased.
type PrivacySubjectErased struct {
	OperationID           string                                           `json:"operation_id,omitempty"`
	RequestBinding        string                                           `json:"request_binding,omitempty"`
	SubjectRef            string                                           `json:"subject_ref"`
	RequestedByRef        string                                           `json:"requested_by_ref,omitempty"`
	Reason                string                                           `json:"reason,omitempty"`
	Selectors             store.PrivacyErasureSelectors                    `json:"selectors"`
	Counts                map[string]int                                   `json:"counts,omitempty"`
	RecoveryFences        []store.PrivacyRecoveryFenceDisposition          `json:"recovery_fences"`
	SchedulerDispositions []store.SecretRotationSchedulePrivacyDisposition `json:"scheduler_dispositions"`
}

// ValidatePrivacySubjectErasedPayload applies the versioned privacy payload
// contract before any projection or idempotent recovery trusts its selectors.
// v1/v2 remain replayable; every newly emitted v3 payload is restricted to
// schema-proven row keys, bounded count labels, and closed fence evidence.
func ValidatePrivacySubjectErasedPayload(e events.Event, payload PrivacySubjectErased) error {
	version := schemaVersionOf(e)
	if version >= PrivacySubjectErasedEventSchemaVersion {
		if !store.IsPrivacyReference(payload.SubjectRef) {
			return fmt.Errorf("projections: %s v%d requires a one-way subject_ref", e.Type, version)
		}
		if payload.RequestedByRef != "" && !store.IsPrivacyReference(payload.RequestedByRef) {
			return fmt.Errorf("projections: %s v%d requested_by_ref is not a one-way reference", e.Type, version)
		}
	} else if payload.SubjectRef == "" {
		return fmt.Errorf("projections: %s requires subject_ref", e.Type)
	}
	if version >= PrivacySubjectErasedOperationEventSchemaVersion &&
		(payload.OperationID == "" || payload.RequestBinding == "") {
		return fmt.Errorf("projections: %s v%d requires operation_id and request_binding", e.Type, version)
	}
	if version < PrivacySubjectErasedEventSchemaVersion {
		return nil
	}
	if payload.RecoveryFences == nil {
		return fmt.Errorf("projections: %s v%d requires recovery_fences", e.Type, version)
	}
	if payload.SchedulerDispositions == nil {
		return fmt.Errorf("projections: %s v%d requires scheduler_dispositions", e.Type, version)
	}
	if err := store.ValidatePrivacyErasureSelectorsV3(payload.Selectors); err != nil {
		return fmt.Errorf("projections: %s v%d selectors: %w", e.Type, version, err)
	}
	if err := store.ValidatePrivacyErasureCountsV3(payload.Counts); err != nil {
		return fmt.Errorf("projections: %s v%d counts: %w", e.Type, version, err)
	}
	if err := store.ValidatePrivacyRecoveryFenceDispositionsV3(payload.RecoveryFences); err != nil {
		return fmt.Errorf("projections: %s v%d recovery fences: %w", e.Type, version, err)
	}
	if err := store.ValidateSecretRotationSchedulePrivacyEvidenceV3(
		payload.Counts, payload.SchedulerDispositions,
	); err != nil {
		return fmt.Errorf("projections: %s v%d scheduler dispositions: %w", e.Type, version, err)
	}
	return nil
}

// PrivacyRetentionEnforced is the payload of a privacy.retention.enforced event.
// It carries policy cutoffs and counts, not the personal values being removed.
type PrivacyRetentionEnforced struct {
	RunID          string                        `json:"run_id"`
	RequestedByRef string                        `json:"requested_by_ref,omitempty"`
	Cutoffs        store.PrivacyRetentionCutoffs `json:"cutoffs"`
	Counts         map[string]int                `json:"counts,omitempty"`
}

// PrivacyArchiveErasureAttested is the payload of a
// privacy.archive_erasure.attested event. It carries subject_ref and operator
// evidence refs for backups/archives, never the raw erased subject.
type PrivacyArchiveErasureAttested struct {
	AttestationID  string     `json:"attestation_id"`
	SubjectRef     string     `json:"subject_ref"`
	RequestedByRef string     `json:"requested_by_ref,omitempty"`
	ArtifactType   string     `json:"artifact_type"`
	ArtifactURI    string     `json:"artifact_uri,omitempty"`
	Action         string     `json:"action"`
	Reason         string     `json:"reason,omitempty"`
	EvidenceRefs   []string   `json:"evidence_refs,omitempty"`
	HeldUntil      *time.Time `json:"held_until,omitempty"`
}

// NHIAccessReviewCampaignStarted is the payload of
// nhi.access_review.campaign.started. It carries non-secret NHI/resource/
// entitlement facts so the campaign read model rebuilds from the log.
type NHIAccessReviewCampaignStarted struct {
	ID              string                `json:"id"`
	Name            string                `json:"name"`
	Scope           string                `json:"scope"`
	ReviewerSubject string                `json:"reviewer_subject"`
	RequestedBy     string                `json:"requested_by"`
	DueAt           *time.Time            `json:"due_at,omitempty"`
	Items           []NHIAccessReviewItem `json:"items"`
}

// NHIAccessReviewItem is one campaign item in
// nhi.access_review.campaign.started.
type NHIAccessReviewItem struct {
	ItemID       string   `json:"item_id"`
	NHIID        string   `json:"nhi_id"`
	NHIKind      string   `json:"nhi_kind"`
	DisplayName  string   `json:"display_name"`
	OwnerRef     string   `json:"owner_ref,omitempty"`
	Resource     string   `json:"resource"`
	Entitlement  string   `json:"entitlement"`
	Risk         string   `json:"risk,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

// NHIAccessReviewItemDecided is the payload of
// nhi.access_review.item.decided.
type NHIAccessReviewItemDecided struct {
	CampaignID           string    `json:"campaign_id"`
	ItemID               string    `json:"item_id"`
	Decision             string    `json:"decision"`
	ReviewerSubject      string    `json:"reviewer_subject"`
	Reason               string    `json:"reason,omitempty"`
	DecisionEvidenceRefs []string  `json:"decision_evidence_refs,omitempty"`
	DecidedAt            time.Time `json:"decided_at,omitempty"`
}

// PQCMigrationCampaignStarted is the full rebuildable snapshot of a core
// campaign over CBOM findings. It tracks work; it never invokes the licensed
// fleet execution engine.
type PQCMigrationCampaignStarted struct {
	ID                string                        `json:"id"`
	Name              string                        `json:"name"`
	OwnerRef          string                        `json:"owner_ref"`
	Deadline          time.Time                     `json:"deadline"`
	Wave              string                        `json:"wave"`
	ReadinessCriteria []string                      `json:"readiness_criteria"`
	Findings          []PQCMigrationCampaignFinding `json:"findings"`
}

type PQCMigrationCampaignFinding struct {
	FindingID     string `json:"finding_id"`
	FindingDigest string `json:"finding_digest"`
	Kind          string `json:"kind"`
	Location      string `json:"location"`
	Algorithm     string `json:"algorithm,omitempty"`
	KeyBits       int    `json:"key_bits,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Cipher        string `json:"cipher,omitempty"`
}

type PQCMigrationCampaignUpdated struct {
	CampaignID            string    `json:"campaign_id"`
	OwnerRef              string    `json:"owner_ref"`
	Deadline              time.Time `json:"deadline"`
	Wave                  string    `json:"wave"`
	ReadinessCriteria     []string  `json:"readiness_criteria"`
	ReadinessStatus       string    `json:"readiness_status"`
	ReadinessEvidenceRefs []string  `json:"readiness_evidence_refs,omitempty"`
	UpdatedAt             time.Time `json:"updated_at,omitempty"`
}

type PQCMigrationCampaignFindingDispositioned struct {
	CampaignID        string    `json:"campaign_id"`
	FindingID         string    `json:"finding_id"`
	Disposition       string    `json:"disposition"`
	RemediationMethod string    `json:"remediation_method"`
	Reason            string    `json:"reason"`
	EvidenceRefs      []string  `json:"evidence_refs"`
	EvidenceDigests   []string  `json:"evidence_digests"`
	DispositionedAt   time.Time `json:"dispositioned_at,omitempty"`
}

type PQCMigrationCampaignClosed struct {
	CampaignID string          `json:"campaign_id"`
	SignedJWS  string          `json:"signed_jws"`
	PublicJWKS json.RawMessage `json:"public_jwks"`
	ClosedBy   string          `json:"closed_by"`
	ClosedAt   time.Time       `json:"closed_at,omitempty"`
}

// TenantKeyDomainSnapshot is the one complete payload contract shared by every
// tenant.key_domain.* lifecycle event. Each event carries the wrapped domain KEK
// as bytes plus all resumable state required to rebuild tenant_key_domains from
// an empty PostgreSQL database. A missing record is not represented here: it is
// the explicit legacy deployment-KEK mode synthesized by the service/API.
type TenantKeyDomainSnapshot struct {
	DomainID              string     `json:"domain_id"`
	Generation            int64      `json:"generation"`
	ProtectionMode        string     `json:"protection_mode"`
	State                 string     `json:"state"`
	WrapperKind           string     `json:"wrapper_kind"`
	WrapperID             string     `json:"wrapper_id"`
	WrappedDomainKEK      []byte     `json:"wrapped_domain_kek"`
	OperationID           *string    `json:"operation_id,omitempty"`
	OperationKind         string     `json:"operation_kind"`
	OperationStatus       string     `json:"operation_status"`
	MigrationStage        string     `json:"migration_stage,omitempty"`
	ProgressCompleted     int64      `json:"progress_completed"`
	ProgressTotal         int64      `json:"progress_total"`
	ProgressCursor        string     `json:"progress_cursor,omitempty"`
	Retryable             bool       `json:"retryable"`
	LastErrorCode         string     `json:"last_error_code,omitempty"`
	LastError             string     `json:"last_error,omitempty"`
	LegacyHistoryExposure string     `json:"legacy_history_exposure"`
	MigrationStartedAt    *time.Time `json:"migration_started_at,omitempty"`
	MigrationCompletedAt  *time.Time `json:"migration_completed_at,omitempty"`
	SealedAt              *time.Time `json:"sealed_at,omitempty"`
	UnsealedAt            *time.Time `json:"unsealed_at,omitempty"`
	// SealIdempotencyKey and SealRequestBinding exist only on
	// tenant.key_domain.seal_requested. They let exact event replay rebuild the
	// derived bounded-worker command after a projection/outbox crash. Neither is
	// key material; RequestBinding is already a non-secret digest.
	SealIdempotencyKey     string    `json:"seal_idempotency_key,omitempty"`
	SealRequestBinding     string    `json:"seal_request_binding,omitempty"`
	TransitionEvidenceRefs []string  `json:"transition_evidence_refs,omitempty"`
	CreatedAt              time.Time `json:"created_at,omitempty"`
	UpdatedAt              time.Time `json:"updated_at,omitempty"`
}

// AccessChangeRequestCreated is the payload of
// access.change_request.created. It carries only non-secret request metadata,
// PR/change references, and evidence refs.
type AccessChangeRequestCreated struct {
	ID                string   `json:"id"`
	RequestedAction   string   `json:"requested_action"`
	RequesterSubject  string   `json:"requester_subject"`
	NHIID             string   `json:"nhi_id"`
	NHIKind           string   `json:"nhi_kind"`
	DisplayName       string   `json:"display_name"`
	OwnerRef          string   `json:"owner_ref,omitempty"`
	Resource          string   `json:"resource"`
	Entitlement       string   `json:"entitlement"`
	ChangeRef         string   `json:"change_ref"`
	ChangeSystem      string   `json:"change_system,omitempty"`
	ChangeURL         string   `json:"change_url,omitempty"`
	Risk              string   `json:"risk,omitempty"`
	Reason            string   `json:"reason"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	RequiredApprovals int      `json:"required_approvals,omitempty"`
}

// AccessChangeRequestDecided is the payload of
// access.change_request.decided.
type AccessChangeRequestDecided struct {
	RequestID            string    `json:"request_id"`
	Decision             string    `json:"decision"`
	ApproverSubject      string    `json:"approver_subject"`
	Reason               string    `json:"reason,omitempty"`
	DecisionEvidenceRefs []string  `json:"decision_evidence_refs,omitempty"`
	DecidedAt            time.Time `json:"decided_at,omitempty"`
}

// CAIssuedCertificate is a responder-only issued-serial event. It is used by
// issuance surfaces that do not create an inventory certificate row (for example
// dynamic PKI secrets) but still need OCSP/CRL to answer from the event log.
type CAIssuedCertificate struct {
	CAID     string    `json:"ca_id"`
	Serial   string    `json:"serial"`
	IssuedAt time.Time `json:"issued_at,omitempty"`
	Source   string    `json:"source,omitempty"`
}

// CACertificateRevoked is a responder-only revocation event. Reason is kept for
// legacy v1 emitters that used {"reason": <int>}; ReasonCode is the canonical RFC
// 5280 code for new emitters.
type CACertificateRevoked struct {
	CAID       string    `json:"ca_id"`
	Serial     string    `json:"serial"`
	Reason     int       `json:"reason,omitempty"`
	ReasonCode int       `json:"reason_code,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	Source     string    `json:"source,omitempty"`
}

func (r CACertificateRevoked) code() int {
	if r.ReasonCode != 0 {
		return r.ReasonCode
	}
	return r.Reason
}

// CACeremonyStarted is the payload of ca.ceremony.started. The ceremony id is
// generated before append so the event log alone can rebuild the ceremony row.
type CACeremonyStarted struct {
	CeremonyID string `json:"ceremony_id"`
	Purpose    string `json:"purpose"`
	Threshold  int    `json:"threshold"`
	Opener     string `json:"opener,omitempty"`
}

// CACeremonyApproved is the payload of ca.ceremony.approved. The immutable event
// id/sequence are intentionally envelope fields, not payload fields; the projector
// binds them into the approval row as quorum evidence.
type CACeremonyApproved struct {
	CeremonyID string `json:"ceremony_id"`
	Custodian  string `json:"custodian"`
	Approvals  int    `json:"approvals,omitempty"`
}

// BreakglassCeremonyCompleted is the projector-owned portion shared by online
// issue, CA rotation, and CA cross-sign events. The full event retains the public
// certificate evidence; this minimal shape consumes the exact ceremony on replay.
type BreakglassCeremonyCompleted struct {
	CeremonyID string `json:"ceremony_id"`
}

// CAAuthorityCreated is the v2 payload shared by ca.root.created,
// ca.intermediate.created, and ca.authority.imported. It carries the complete
// authority row plus the consumed ceremony id, so replay can rebuild both the CA
// read model and the governance gate from immutable events.
type CAAuthorityCreated struct {
	CAID              string    `json:"ca_id"`
	ParentID          *string   `json:"parent_id,omitempty"`
	CommonName        string    `json:"common_name"`
	Kind              string    `json:"kind"`
	CertificatePEM    string    `json:"certificate_pem"`
	SignerHandle      string    `json:"signer_handle,omitempty"`
	Serial            string    `json:"serial"`
	NotAfter          time.Time `json:"not_after"`
	MaxPathLen        int       `json:"max_path_len"`
	PermittedDNSNames []string  `json:"permitted_dns_names,omitempty"`
	EKUs              []string  `json:"extended_key_usages,omitempty"`
	CeremonyID        string    `json:"ceremony_id"`
	OfflineRoot       bool      `json:"offline_root,omitempty"`
	ChainSHA256       string    `json:"chain_sha256,omitempty"`
}

// CAAuthorityRotated is the payload of ca.authority.rotated. It carries the
// predecessor/successor link the projector needs to keep the old issue URL
// routable while the active signer advances to the successor CA.
type CAAuthorityRotated struct {
	PredecessorCAID string `json:"predecessor_ca_id"`
	SuccessorCAID   string `json:"successor_ca_id"`
	Reason          string `json:"reason,omitempty"`
	IssuePath       string `json:"issue_path,omitempty"`
	ActiveIssuePath string `json:"active_issue_path,omitempty"`
}

// CAAuthorityRekeyed is the payload of ca.authority.rekeyed. It carries the full
// successor authority row so event replay creates the same id/certificate/signing
// handle and then supersedes the predecessor in one projection step.
type CAAuthorityRekeyed struct {
	ID                     string    `json:"id"`
	PredecessorCAID        string    `json:"predecessor_ca_id"`
	ParentID               *string   `json:"parent_id,omitempty"`
	CommonName             string    `json:"common_name"`
	Kind                   string    `json:"kind"`
	CertificatePEM         string    `json:"certificate_pem"`
	SignerHandle           string    `json:"signer_handle"`
	Serial                 string    `json:"serial"`
	NotAfter               time.Time `json:"not_after"`
	MaxPathLen             int       `json:"max_path_len"`
	PermittedDNSNames      []string  `json:"permitted_dns_names,omitempty"`
	EKUs                   []string  `json:"extended_key_usages,omitempty"`
	CeremonyID             string    `json:"ceremony_id"`
	Reason                 string    `json:"reason,omitempty"`
	IssuePath              string    `json:"issue_path,omitempty"`
	ActiveIssuePath        string    `json:"active_issue_path,omitempty"`
	OfflineRoot            bool      `json:"offline_root,omitempty"`
	NewSignedByPreviousDER []byte    `json:"new_signed_by_previous_der,omitempty"`
	PreviousSignedByNewDER []byte    `json:"previous_signed_by_new_der,omitempty"`
}

// CRLPublished is the payload of a ca.crl.published event. V2 carries the full DER
// bytes, so ca_crls is a projection instead of independent PostgreSQL state.
type CRLPublished struct {
	CAID            string    `json:"ca_id"`
	Number          int64     `json:"crl_number"`
	DER             []byte    `json:"crl_der,omitempty"`
	ThisUpdate      time.Time `json:"this_update,omitempty"`
	NextUpdate      time.Time `json:"next_update,omitempty"`
	RevokedCount    int       `json:"revoked_count,omitempty"`
	Kind            string    `json:"kind,omitempty"`
	ShardIndex      int       `json:"shard_index,omitempty"`
	ShardCount      int       `json:"shard_count,omitempty"`
	DeltaBaseNumber *int64    `json:"delta_base_number,omitempty"`
	ParentNumber    *int64    `json:"parent_crl_number,omitempty"`
}

// OCSPResponderRotated is the payload of ca.ocsp_responder.rotated. It carries
// the full responder certificate so the active responder read model rebuilds from
// the event log rather than from independent PostgreSQL state.
type OCSPResponderRotated struct {
	CAID              string    `json:"ca_id"`
	Serial            string    `json:"serial"`
	CertDER           []byte    `json:"cert_der"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	RotatedFromSerial string    `json:"rotated_from_serial,omitempty"`
}

// CertificateSuperseded is the payload of a certificate.superseded event
// (CORRECT-002): a certificate retired because a renewal/rotation produced a
// successor. The inventoried certificate is keyed by fingerprint; the projector
// sets its status to superseded and stamps renewed_at. Driving the supersession
// through an event (rather than a direct read-table UPDATE) keeps it
// reconstructable from the log on a Rebuild() (AN-2), exactly like the revoked
// transition.
type CertificateSuperseded struct {
	Fingerprint  string    `json:"fingerprint"`
	Serial       string    `json:"serial"`
	SupersededBy string    `json:"superseded_by,omitempty"` // successor serial, for the audit trail
	RenewedAt    time.Time `json:"renewed_at"`
}

// AgentHeartbeat is the payload of an agent.heartbeat event. The event carries
// the deterministic agents.id, so replay does not depend on server-package helper
// code to reconstruct the row.
type AgentHeartbeat struct {
	ID         string `json:"id"`
	Agent      string `json:"agent"`
	Version    string `json:"version"`
	Status     string `json:"status"`
	CertSerial string `json:"cert_serial,omitempty"`
	// Roles is the capability grant read off the certificate the agent presented
	// on this call (epic A2), so the fleet view reflects what the agent actually
	// holds rather than what it was granted at some earlier enrollment. It is
	// carried on the event so a replay reconstructs the same row.
	Roles []string `json:"roles,omitempty"`
	// WorkloadAPIServed and WorkloadAPISVIDs are this host's SPIFFE Workload API
	// posture (epic B3), carried on the event so a replay reconstructs the row.
	//
	// A POINTER for the boolean, because three states matter: serving, not
	// serving, and never reported. An older agent that does not know about this
	// feature sends nothing, and rendering that as "not serving" would tell an
	// operator their host declined to serve when it simply cannot say.
	WorkloadAPIServed *bool  `json:"workload_api_served,omitempty"`
	WorkloadAPISVIDs  *int64 `json:"workload_api_svids,omitempty"`
}

// AgentCertRenewed is the payload of an agent.cert.renewed event. The projector
// uses it as a liveness touch; certificate inventory itself is represented by the
// public renewal event and the renewed cert returned to the agent.
type AgentCertRenewed struct {
	ID        string `json:"id"`
	Agent     string `json:"agent"`
	OldSerial string `json:"old_serial"`
	NewSerial string `json:"new_serial"`
}

// AgentCertRevoked is the payload of an agent.cert.revoked event. It projects a
// tenant-scoped deny-list selector for an agent mTLS certificate; either Serial or
// Fingerprint (or both) must be present. The agent channel derives both values
// from the verified TLS leaf before it does RPC work.
type AgentCertRevoked struct {
	ID          string    `json:"id"`
	Agent       string    `json:"agent,omitempty"`
	Serial      string    `json:"serial,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	RevokedAt   time.Time `json:"revoked_at"`
}

// AgentOffboarded is the payload of an agent.offboarded event. It leaves a
// tombstone in the agent inventory and makes the served mTLS channel reject the
// agent identity before heartbeat, renewal, or inventory work.
type AgentOffboarded struct {
	ID           string `json:"id"`
	Agent        string `json:"agent,omitempty"`
	Reason       string `json:"reason,omitempty"`
	OffboardedBy string `json:"offboarded_by,omitempty"`
}

// ProfileVersioned is the schema-v2 payload of profile.created/profile.updated.
// Version 1 of those events carried only name/version as an audit breadcrumb and
// cannot rebuild certificate_profiles. Version 2 carries the full read-model row so
// profiles are a pure projection of the event log.
type ProfileVersioned struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Version   int             `json:"version"`
	Spec      json.RawMessage `json:"spec"`
	Active    bool            `json:"active"`
	CreatedBy string          `json:"created_by"`
}

// DiscoverySourceUpserted is the payload of discovery.source.upserted.
type DiscoverySourceUpserted struct {
	ID     string          `json:"id"`
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

// DiscoverySegmentUpserted is the operator-declared scan denominator. Sweep
// observations are separate completion events, so editing a boundary cannot
// make it look freshly observed.
type DiscoverySegmentUpserted struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Ranges          []string `json:"ranges"`
	StalenessHours  int      `json:"staleness_hours"`
	Excluded        bool     `json:"excluded"`
	ExclusionReason string   `json:"exclusion_reason,omitempty"`
}

// DiscoveryScheduleUpserted is the payload of discovery.schedule.upserted.
type DiscoveryScheduleUpserted struct {
	ID              string `json:"id"`
	SourceID        string `json:"source_id"`
	Name            string `json:"name"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
}

// DiscoveryRunQueued is the payload of discovery.run.queued. Network and SSH
// rows carry the resolved relay command; other source kinds leave those fields
// empty and execute on the control plane.
type DiscoveryRunQueued = segmentscan.Intent

// RevocationProbeQueued and RevocationHealthObserved use the same bounded
// public contract at producer, relay, ingestion, and replay boundaries.
type RevocationProbeQueued = revocationhealth.Intent
type RevocationHealthObserved = revocationhealth.Observed

// MigrationRunRecorded is a complete aggregate snapshot plus only the newly
// licensed effects. The snapshot rebuilds operator state; Actions bridge the
// append-before-SQL crash window through outbox reconciliation.
type MigrationRunRecorded struct {
	Run     migration.Run      `json:"run"`
	Actions []migration.Action `json:"actions"`
}

// DiscoveryRunStarted is the payload of discovery.run.started.
type DiscoveryRunStarted struct {
	ID string `json:"id"`
}

// DiscoveryFindingRecorded is the payload of discovery.finding.recorded.
type DiscoveryFindingRecorded struct {
	ID          string          `json:"id"`
	RunID       string          `json:"run_id"`
	SourceID    string          `json:"source_id"`
	Kind        string          `json:"kind"`
	Ref         string          `json:"ref"`
	Provenance  string          `json:"provenance"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	RiskScore   int             `json:"risk_score,omitempty"`
	Metadata    json.RawMessage `json:"metadata"`
}

// DiscoveryFindingTriageChanged is the payload of discovery.finding.triage_changed.
type DiscoveryFindingTriageChanged struct {
	ID                string          `json:"id"`
	Status            string          `json:"status"`
	ManagedIdentityID *string         `json:"managed_identity_id,omitempty"`
	Actor             string          `json:"actor,omitempty"`
	Reason            string          `json:"reason,omitempty"`
	MetadataPatch     json.RawMessage `json:"metadata_patch,omitempty"`
}

// DiscoveryRunCompleted is the payload of discovery.run.completed.
type DiscoveryRunCompleted struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	Targets           int    `json:"targets"`
	Discovered        int    `json:"discovered"`
	Failed            int    `json:"failed"`
	Rejected          int    `json:"rejected"`
	Blocked           int    `json:"blocked,omitempty"`
	Error             string `json:"error,omitempty"`
	Segment           string `json:"segment,omitempty"`
	ExecutedByAgentID string `json:"executed_by_agent_id,omitempty"`
}

// ACMEDNS01ProviderConfigUpserted is the payload of
// acme.dns01.provider_config.upserted. It carries only provider metadata and
// secret references; raw provider credentials must never appear in this event.
type ACMEDNS01ProviderConfigUpserted struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Provider         string          `json:"provider"`
	Zone             string          `json:"zone,omitempty"`
	ChallengeDomain  string          `json:"challenge_domain,omitempty"`
	DelegationTarget string          `json:"delegation_target,omitempty"`
	CredentialRefs   json.RawMessage `json:"credential_refs"`
	Config           json.RawMessage `json:"config"`
	CAAIssuerDomain  string          `json:"caa_issuer_domain,omitempty"`
	AllowedMethods   []string        `json:"allowed_methods,omitempty"`
	AllowWildcards   bool            `json:"allow_wildcards,omitempty"`
	// AllowUpstreamDV is additive at schema v1 and omitempty: an event written
	// before epic B7 replays as false, which is the correct default — an
	// operator who configured this before upstream DV existed cannot have
	// consented to it.
	AllowUpstreamDV bool `json:"allow_upstream_dv,omitempty"`
}

// ACMEDNS01ProviderConfigDeleted is the payload of
// acme.dns01.provider_config.deleted.
type ACMEDNS01ProviderConfigDeleted struct {
	ID string `json:"id"`
}

// ACMEUpstreamAuthorizationObserved is the payload of
// acme.dns01.upstream.authorization.observed (epic B7).
//
// Reused is the field this event exists for. An authority that already
// considers an identifier authorized issues without a challenge, which is
// normal and also the thing that hides a validation path that has quietly
// stopped working: nothing fails until the reuse window closes, and then it
// fails for every identifier at once, because they were all authorized in the
// same original burst.
type ACMEUpstreamAuthorizationObserved struct {
	Identifier string `json:"identifier"`
	// Issuer is the authority. The same name authorized at two CAs has two
	// independent reuse windows, and reporting their union would hide whichever
	// one is about to lapse.
	Issuer string `json:"issuer"`
	// ChallengeType is empty when the authorization was reused. The emptiness
	// is the signal, not a missing field.
	ChallengeType string    `json:"challenge_type,omitempty"`
	Reused        bool      `json:"reused"`
	ExpiresAt     time.Time `json:"expires_at,omitzero"`
}

// EndpointVerificationObserved is the payload of endpoint.verification.observed
// (epic D2).
//
// It is an OBSERVATION, so every field describes what a handshake established
// rather than what the platform intended. Reached is the load-bearing one: when
// it is false nothing below it means anything, and the projector refuses a
// payload that claims otherwise — an endpoint nobody could connect to must
// never become a verified one.
type EndpointVerificationObserved struct {
	EndpointID string `json:"endpoint_id"`
	Address    string `json:"address"`
	// Vantage is "local" or "relay". The two are never merged: a local pass
	// means the serving host thinks it is fine, a relay pass means a client
	// could actually get it, and an appliance has only the second.
	Vantage             string `json:"vantage"`
	Reached             bool   `json:"reached"`
	Mismatch            string `json:"mismatch,omitempty"`
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
	ObservedFingerprint string `json:"observed_fingerprint,omitempty"`
	CheckedSANs         bool   `json:"checked_sans,omitempty"`
	CheckedChain        bool   `json:"checked_chain,omitempty"`
	// NotBefore/NotAfter are the SERVED validity window, which is not
	// necessarily the issued certificate's — that difference is the point.
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	Detail    string    `json:"detail,omitempty"`
	// EvidenceDigest is the probe transcript digest carried inside the agent's
	// signed receipt.
	EvidenceDigest  string    `json:"evidence_digest,omitempty"`
	AgentCommonName string    `json:"agent_common_name,omitempty"`
	ObservedAt      time.Time `json:"observed_at,omitzero"`
}

// ACMEDNS01Preflighted is the payload of acme.dns01.preflighted. It records the
// served readiness/policy decision without storing provider credentials or raw
// DNS-provider tokens.
type ACMEDNS01Preflighted struct {
	ConfigID       string   `json:"config_id,omitempty"`
	Domain         string   `json:"domain"`
	RecordName     string   `json:"record_name"`
	SelectedMethod string   `json:"selected_method,omitempty"`
	Ready          bool     `json:"ready"`
	FailedChecks   []string `json:"failed_checks,omitempty"`
}

// ACMEDNS01RecordChanged is the audit payload for order-time DNS-01 publish and
// cleanup. It intentionally omits the TXT value and all credential references.
type ACMEDNS01RecordChanged struct {
	ConfigID   string `json:"config_id"`
	Provider   string `json:"provider"`
	Domain     string `json:"domain"`
	RecordName string `json:"record_name"`
	OutboxID   int64  `json:"outbox_id"`
}

// MDMSCEPPolicyUpserted is the payload of mdm.scep_policy.upserted. It carries
// enrollment policy metadata and reference names only; raw MDM connector secrets
// and SCEP challenge values must never appear in this event.
type MDMSCEPPolicyUpserted struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Provider         string          `json:"provider"`
	SCEPProfile      string          `json:"scep_profile"`
	SCEPEndpoint     string          `json:"scep_endpoint"`
	ExpectedAudience string          `json:"expected_audience,omitempty"`
	ChallengeMode    string          `json:"challenge_mode"`
	TrustAnchorRefs  json.RawMessage `json:"trust_anchor_refs"`
	ProfileGuidance  json.RawMessage `json:"profile_guidance"`
	Enabled          bool            `json:"enabled"`
	RotationVersion  int             `json:"rotation_version,omitempty"`
}

// MDMSCEPPolicyDeleted is the payload of mdm.scep_policy.deleted.
type MDMSCEPPolicyDeleted struct {
	ID string `json:"id"`
}

// MDMSCEPChallengeRotated is the payload of mdm.scep_challenge.rotated. It records
// a policy rotation version, not a raw challenge or signing credential.
type MDMSCEPChallengeRotated struct {
	ID              string `json:"id"`
	RotationVersion int    `json:"rotation_version"`
}

// WorkloadAttesterTrustSourceUpserted is the payload of
// workload.attester_trust_source.upserted. It carries public trust material and
// policy metadata only; private keys, bearer tokens, and cloud credentials must
// never appear in this event.
type WorkloadAttesterTrustSourceUpserted struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Method              string          `json:"method"`
	Issuer              string          `json:"issuer,omitempty"`
	Audience            string          `json:"audience,omitempty"`
	JWKS                json.RawMessage `json:"jwks"`
	RootCertsPEM        []string        `json:"root_certs_pem,omitempty"`
	ExpectedNonceBase64 string          `json:"expected_nonce_base64,omitempty"`
	Enabled             bool            `json:"enabled"`
	RotationVersion     int             `json:"rotation_version,omitempty"`
}

// WorkloadAttesterTrustSourceRotated is the payload of
// workload.attester_trust_source.rotated. It replaces the public trust material
// for an existing source and records the next rotation version.
type WorkloadAttesterTrustSourceRotated struct {
	ID                  string          `json:"id"`
	Issuer              string          `json:"issuer,omitempty"`
	Audience            string          `json:"audience,omitempty"`
	JWKS                json.RawMessage `json:"jwks"`
	RootCertsPEM        []string        `json:"root_certs_pem,omitempty"`
	ExpectedNonceBase64 string          `json:"expected_nonce_base64,omitempty"`
	RotationVersion     int             `json:"rotation_version"`
	Reason              string          `json:"reason,omitempty"`
}

// WorkloadAttesterTrustSourceRevoked is the payload of
// workload.attester_trust_source.revoked.
type WorkloadAttesterTrustSourceRevoked struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

// WorkloadAttesterTrustSourceDeleted is the payload of
// workload.attester_trust_source.deleted.
type WorkloadAttesterTrustSourceDeleted struct {
	ID string `json:"id"`
}

// ComplianceReportScheduleUpserted is the payload of
// compliance.report_schedule.upserted.
type ComplianceReportScheduleUpserted struct {
	ID              string `json:"id"`
	Framework       string `json:"framework"`
	Name            string `json:"name"`
	ReportType      string `json:"report_type"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
	Delivery        string `json:"delivery"`
	RecipientRef    string `json:"recipient_ref,omitempty"`
}

// SecretRotationScheduleUpserted is the payload of
// secret.rotation_schedule.upserted. It carries references only; generated
// credential material remains inside the configured rotator/provider.
type SecretRotationScheduleUpserted struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Provider        string    `json:"provider"`
	Key             string    `json:"key"`
	OldRef          string    `json:"old_ref"`
	IntervalSeconds int       `json:"interval_seconds"`
	Enabled         bool      `json:"enabled"`
	NextRunAt       time.Time `json:"next_run_at,omitempty"`
}

// SecretRotationScheduleRanEventSchemaVersion adds the exact immutable due-edge
// tuple. Version 1 used event wall time as cadence authority and remains readable
// only for pre-command-table history.
const SecretRotationScheduleRanEventSchemaVersion = rotationcommand.EventSchemaVersion

// SecretRotationScheduleRan is the payload of secret.rotation_schedule.ran.
// Version 2 records the exact due edge. Version 3 also names the canonical
// tenant.registered event so a reused tenant UUID has a disjoint command history.
type SecretRotationScheduleRan struct {
	ScheduleID                      string    `json:"schedule_id"`
	RunID                           string    `json:"run_id"`
	TenantRegistrationEventID       string    `json:"tenant_registration_event_id,omitempty"`
	TenantRegistrationEventSequence uint64    `json:"tenant_registration_event_sequence,omitempty"`
	DueAt                           time.Time `json:"due_at,omitempty"`
	Provider                        string    `json:"provider,omitempty"`
	Key                             string    `json:"key,omitempty"`
	OldRef                          string    `json:"old_ref,omitempty"`
	IntervalSeconds                 int       `json:"interval_seconds,omitempty"`
	ConfigEventSequence             uint64    `json:"config_event_sequence,omitempty"`
	CommandKey                      string    `json:"command_key,omitempty"`
	RequestBinding                  string    `json:"request_binding,omitempty"`
	Status                          string    `json:"status"`
	NewRef                          string    `json:"new_ref,omitempty"`
	Error                           string    `json:"error,omitempty"`
}

// NotificationThresholdDelivered is the payload of
// notification.threshold.delivered.
type NotificationThresholdDelivered struct {
	Subject       string    `json:"subject"`
	ThresholdDays int       `json:"threshold_days"`
	Channel       string    `json:"channel"`
	SentAt        time.Time `json:"sent_at,omitempty"`
}

// NotificationTestQueued is the immutable authenticated command for an
// operator-requested channel test. Payload is the exact credential-free Alert
// placed on the outbox; the projector creates the durable operation and intent
// atomically.
type NotificationTestQueued struct {
	ID                   string          `json:"id"`
	RequestBinding       string          `json:"request_binding"`
	ChannelID            string          `json:"channel_id"`
	Destination          string          `json:"destination"`
	EffectLane           string          `json:"effect_lane"`
	CredentialConfigured bool            `json:"credential_configured"`
	Payload              json.RawMessage `json:"payload"`
}

// NotificationDeliveryRecorded is one successful notification receiver effect.
// It stores only deterministic routing/payload digests, never the raw
// Idempotency-Key, alert body, endpoint, or channel credential.
type NotificationDeliveryRecorded struct {
	ID                    string    `json:"id"`
	Destination           string    `json:"destination"`
	NotificationKeyDigest string    `json:"notification_key_digest"`
	PayloadDigest         string    `json:"payload_digest"`
	Channel               string    `json:"channel"`
	OutboxID              *int64    `json:"outbox_id,omitempty"`
	Attempts              int       `json:"attempts,omitempty"`
	DeliveredAt           time.Time `json:"delivered_at,omitempty"`
}

// NotificationChannelUpserted is the payload of notification.channel.upserted.
// It stores delivery metadata plus a credential reference, never credential
// values.
type NotificationChannelUpserted struct {
	ID            string `json:"id"`
	ChannelType   string `json:"channel_type"`
	Label         string `json:"label"`
	EndpointURL   string `json:"endpoint_url,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	Enabled       bool   `json:"enabled"`
}

// NotificationChannelDeleted is the payload of notification.channel.deleted.
type NotificationChannelDeleted struct {
	ID string `json:"id"`
}

// NotificationRoutingPolicyUpserted is the payload of
// notification.routing_policy.upserted. It stores channel names and operator
// metadata only; channel credentials stay in configured notifier backends.
type NotificationRoutingPolicyUpserted struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	ChannelsBySeverity map[string][]string `json:"channels_by_severity"`
	DefaultChannels    []string            `json:"default_channels"`
	OwnerRef           string              `json:"owner_ref,omitempty"`
	OwnerEmail         string              `json:"owner_email,omitempty"`
	DigestInterval     int                 `json:"digest_interval_seconds,omitempty"`
	DigestTimezone     string              `json:"digest_timezone,omitempty"`
}

// NotificationRoutingPolicyDeleted is the payload of
// notification.routing_policy.deleted.
type NotificationRoutingPolicyDeleted struct {
	ID string `json:"id"`
}

// NotificationRead is the payload of notification.read. It marks one notification
// outbox item as read by an operator. The outbox row remains the delivery source
// of truth; this projection only records inbox read state.
type NotificationRead struct {
	OutboxID int64     `json:"outbox_id"`
	ReadAt   time.Time `json:"read_at,omitempty"`
}

// CBOMAssetObserved is the payload of cbom.asset.observed. It contains only
// observed public cryptographic facts and classification labels, never key
// material. The projector rebuilds crypto_assets from these events.
type CBOMAssetObserved struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"`
	Location          string   `json:"location"`
	Algorithm         string   `json:"algorithm,omitempty"`
	KeyBits           int      `json:"key_bits,omitempty"`
	Protocol          string   `json:"protocol,omitempty"`
	Cipher            string   `json:"cipher,omitempty"`
	Library           string   `json:"library,omitempty"`
	Strength          string   `json:"strength"`
	QuantumVulnerable bool     `json:"quantum_vulnerable"`
	OutOfPolicy       bool     `json:"out_of_policy"`
	Reasons           []string `json:"reasons,omitempty"`
}

// LicensedCryptoMigrationStarted records the tenant-scoped operator intent to
// re-issue CBOM assets toward a proprietary crypto target. The side effect
// itself is still an outbox row; this event is the immutable request fact.
type LicensedCryptoMigrationStarted struct {
	RunID              string                              `json:"run_id"`
	AssetIDs           []string                            `json:"asset_ids"`
	TargetAlgorithm    string                              `json:"target_algorithm"`
	EffectiveAlgorithm string                              `json:"effective_algorithm"`
	Protocol           string                              `json:"protocol"`
	RollbackOnFailure  bool                                `json:"rollback_on_failure"`
	Queued             int                                 `json:"queued"`
	Reissues           []LicensedCryptoMigrationReissue    `json:"reissues,omitempty"`
	TLSPostures        []LicensedCryptoMigrationTLSPosture `json:"tls_postures,omitempty"`
}

// LicensedCryptoMigrationTLSPosture is the replayable external-mutation binding
// for one selected CBOM protocol/cipher finding. TargetConfig is populated only
// while constructing the sealed outbox plaintext and is cleared before an
// event is appended. Events retain the public immutable target revision plus
// SealedOutboxPayload, so reconciliation reproduces exact ciphertext without
// exposing redirect-capable connector configuration.
type LicensedCryptoMigrationTLSPosture struct {
	RunID               string               `json:"run_id"`
	AssetID             string               `json:"asset_id"`
	Kind                string               `json:"kind"`
	FindingKind         string               `json:"finding_kind"`
	Location            string               `json:"location"`
	Algorithm           string               `json:"algorithm,omitempty"`
	KeyBits             int                  `json:"key_bits,omitempty"`
	AssetProtocol       string               `json:"asset_protocol,omitempty"`
	Cipher              string               `json:"cipher,omitempty"`
	Library             string               `json:"library,omitempty"`
	Strength            string               `json:"strength"`
	QuantumVulnerable   bool                 `json:"quantum_vulnerable"`
	OutOfPolicy         bool                 `json:"out_of_policy"`
	Reasons             []string             `json:"reasons,omitempty"`
	TargetID            string               `json:"target_id"`
	TargetRevision      string               `json:"target_revision"`
	Connector           string               `json:"connector"`
	Target              string               `json:"target"`
	TargetConfig        json.RawMessage      `json:"target_config,omitempty"`
	Desired             connector.TLSPosture `json:"desired"`
	RollbackOnFailure   bool                 `json:"rollback_on_failure"`
	SealedOutboxPayload json.RawMessage      `json:"sealed_outbox_payload,omitempty"`
}

// LicensedCryptoMigrationReissue is the replayable side-effect payload for a migration
// started event. If the process crashes after appending licensed_crypto.migration.started but
// before committing the outbox rows, the boot reconciler can recreate the exact
// tenant-scoped reissue intents from these public CBOM facts.
type LicensedCryptoMigrationReissue struct {
	RunID              string   `json:"run_id"`
	AssetID            string   `json:"asset_id"`
	Kind               string   `json:"kind"`
	Location           string   `json:"location"`
	Algorithm          string   `json:"algorithm"`
	KeyBits            int      `json:"key_bits,omitempty"`
	AssetProtocol      string   `json:"asset_protocol,omitempty"`
	Cipher             string   `json:"cipher,omitempty"`
	Library            string   `json:"library,omitempty"`
	Strength           string   `json:"strength"`
	QuantumVulnerable  bool     `json:"quantum_vulnerable"`
	OutOfPolicy        bool     `json:"out_of_policy"`
	Reasons            []string `json:"reasons,omitempty"`
	TargetAlgorithm    string   `json:"target_algorithm"`
	EffectiveAlgorithm string   `json:"effective_algorithm"`
	Protocol           string   `json:"protocol"`
	RollbackOnFailure  bool     `json:"rollback_on_failure"`
}

// LicensedCryptoMigrationAssetCompleted projects a migrated CBOM row after the outbox worker
// has minted the replacement certificate through the served protocol path.
type LicensedCryptoMigrationAssetCompleted struct {
	RunID                     string   `json:"run_id"`
	AssetID                   string   `json:"asset_id"`
	Kind                      string   `json:"kind"`
	Location                  string   `json:"location"`
	OriginalAlgorithm         string   `json:"original_algorithm"`
	OriginalKeyBits           int      `json:"original_key_bits,omitempty"`
	OriginalProtocol          string   `json:"original_protocol,omitempty"`
	OriginalCipher            string   `json:"original_cipher,omitempty"`
	OriginalLibrary           string   `json:"original_library,omitempty"`
	OriginalStrength          string   `json:"original_strength"`
	OriginalQuantumVulnerable bool     `json:"original_quantum_vulnerable"`
	OriginalOutOfPolicy       bool     `json:"original_out_of_policy"`
	OriginalReasons           []string `json:"original_reasons,omitempty"`
	TargetAlgorithm           string   `json:"target_algorithm"`
	EffectiveAlgorithm        string   `json:"effective_algorithm"`
	EffectiveKeyBits          int      `json:"effective_key_bits,omitempty"`
	Protocol                  string   `json:"protocol"`
	CertificateFingerprint    string   `json:"certificate_fingerprint"`
	RollbackRef               string   `json:"rollback_ref"`
}

// LicensedCryptoMigrationRollbackCompleted projects the original CBOM row back after an
// operator rollback drill or break-glass rollback.
type LicensedCryptoMigrationRollbackCompleted struct {
	RunID             string   `json:"run_id"`
	AssetID           string   `json:"asset_id"`
	Kind              string   `json:"kind"`
	Location          string   `json:"location"`
	Algorithm         string   `json:"algorithm"`
	KeyBits           int      `json:"key_bits,omitempty"`
	Protocol          string   `json:"protocol,omitempty"`
	Cipher            string   `json:"cipher,omitempty"`
	Library           string   `json:"library,omitempty"`
	Strength          string   `json:"strength"`
	QuantumVulnerable bool     `json:"quantum_vulnerable"`
	OutOfPolicy       bool     `json:"out_of_policy"`
	Reasons           []string `json:"reasons,omitempty"`
	Reason            string   `json:"reason,omitempty"`
}

// ConnectorDeliveryRecorded is the payload of connector.delivery.recorded.
// It is delivery evidence only: no certificate PEM, key PEM, token, or secret
// bytes may appear here.
type ConnectorDeliveryRecorded struct {
	ID               string  `json:"id"`
	OutboxID         *int64  `json:"outbox_id,omitempty"`
	IdentityID       *string `json:"identity_id,omitempty"`
	RemediationRunID string  `json:"remediation_run_id,omitempty"`
	Destination      string  `json:"destination"`
	Connector        string  `json:"connector"`
	Target           string  `json:"target"`
	Fingerprint      string  `json:"fingerprint,omitempty"`
	Status           string  `json:"status"`
	Attempts         int     `json:"attempts,omitempty"`
	Reason           string  `json:"reason,omitempty"`
	Detail           string  `json:"detail,omitempty"`
	RollbackRef      string  `json:"rollback_ref,omitempty"`
	IdempotencyKey   string  `json:"idempotency_key,omitempty"`
}

// DeploymentTargetUpserted is the payload of deployment_target.upserted.
type DeploymentTargetUpserted struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Connector string          `json:"connector"`
	Config    json.RawMessage `json:"config"`
}

// DeploymentTargetDeleted is the payload of deployment_target.deleted.
type DeploymentTargetDeleted struct {
	ID string `json:"id"`
}

// IdentityConnectorTargetBound is the payload of identity.connector_target_bound.
type IdentityConnectorTargetBound struct {
	IdentityID string `json:"identity_id"`
	TargetID   string `json:"target_id"`
	Connector  string `json:"connector"`
	Target     string `json:"target"`
	Route      string `json:"route,omitempty"`
}

// LifecycleRotationRecorded is the payload of lifecycle.rotation.recorded.
type LifecycleRotationRecorded struct {
	ID                     string     `json:"id"`
	IdentityID             string     `json:"identity_id"`
	OutboxID               *int64     `json:"outbox_id,omitempty"`
	Status                 string     `json:"status"`
	Trigger                string     `json:"trigger"`
	Reason                 string     `json:"reason,omitempty"`
	PredecessorFingerprint string     `json:"predecessor_fingerprint,omitempty"`
	SuccessorFingerprint   string     `json:"successor_fingerprint,omitempty"`
	RollbackRef            string     `json:"rollback_ref,omitempty"`
	Error                  string     `json:"error,omitempty"`
	IdempotencyKey         string     `json:"idempotency_key,omitempty"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
}

// OutboxReconciliationConflictRecorded is fail-closed recovery evidence. The
// original command remains in outbox and the refused candidate remains in its
// source event; this event binds their identities and digests without creating a
// second executable command.
type OutboxReconciliationConflictRecorded struct {
	SourceEventID              string `json:"source_event_id"`
	SourceEventSequence        uint64 `json:"source_event_sequence"`
	SourceEventType            string `json:"source_event_type"`
	IdempotencyKey             string `json:"idempotency_key"`
	ExistingOutboxID           int64  `json:"existing_outbox_id"`
	ExistingDestination        string `json:"existing_destination"`
	ExistingEffectLane         string `json:"existing_effect_lane"`
	ExistingPayloadSHA256      string `json:"existing_payload_sha256"`
	ExistingRequiredAgentRole  string `json:"existing_required_agent_role,omitempty"`
	ExistingRequiredAgentID    string `json:"existing_required_agent_id,omitempty"`
	CandidateDestination       string `json:"candidate_destination"`
	CandidateEffectLane        string `json:"candidate_effect_lane"`
	CandidatePayloadSHA256     string `json:"candidate_payload_sha256"`
	CandidateRequiredAgentRole string `json:"candidate_required_agent_role,omitempty"`
	CandidateRequiredAgentID   string `json:"candidate_required_agent_id,omitempty"`
	Reason                     string `json:"reason"`
	Status                     string `json:"status"`
}

// IncidentExecutionRecorded is the payload of incident.execution.recorded. It is
// operational evidence only: identities, graph impact, delivery receipt ids,
// rollback references, failed targets, and a signed audit bundle reference.
type IncidentExecutionRecorded struct {
	ID                    string          `json:"id"`
	CompromisedIdentityID string          `json:"compromised_identity_id"`
	ReplacementIdentityID *string         `json:"replacement_identity_id,omitempty"`
	ConnectorDeliveryID   *string         `json:"connector_delivery_id,omitempty"`
	Status                string          `json:"status"`
	Phase                 string          `json:"phase"`
	Reason                string          `json:"reason,omitempty"`
	BlastRadius           json.RawMessage `json:"blast_radius"`
	RevocationStatus      string          `json:"revocation_status,omitempty"`
	EvidenceBundleFormat  string          `json:"evidence_bundle_format,omitempty"`
	EvidenceBundle        string          `json:"evidence_bundle,omitempty"`
	FailedTargets         []string        `json:"failed_targets,omitempty"`
	RollbackRefs          []string        `json:"rollback_refs,omitempty"`
	IdempotencyKey        string          `json:"idempotency_key,omitempty"`
	CreatedBy             string          `json:"created_by,omitempty"`
}

// FleetReissuanceHealthGate is one recorded health gate in a compromised-issuer
// fleet run.
type FleetReissuanceHealthGate struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// FleetReissuanceBatch is one batch processed by a compromised-issuer fleet run.
type FleetReissuanceBatch struct {
	Index                  int      `json:"index"`
	Status                 string   `json:"status"`
	IdentityIDs            []string `json:"identity_ids"`
	ReplacementIdentityIDs []string `json:"replacement_identity_ids"`
	HealthGate             string   `json:"health_gate,omitempty"`
}

// IncidentFleetReissuanceRecorded is the payload of
// incident.fleet_reissuance.recorded. It is operational evidence only: issuer and
// identity ids, graph impact, batch metadata, delivery receipt ids, rollback
// references, failed targets, and a signed audit bundle reference.
type IncidentFleetReissuanceRecorded struct {
	ID                     string                      `json:"id"`
	IssuerID               string                      `json:"issuer_id"`
	MigrationRunID         string                      `json:"migration_run_id,omitempty"`
	ReplacementAuthorityID string                      `json:"replacement_authority_id,omitempty"`
	Mode                   string                      `json:"mode,omitempty"`
	PlanDigest             string                      `json:"plan_digest,omitempty"`
	ExactTrustStoreIDs     []string                    `json:"exact_trust_store_ids,omitempty"`
	ExactTrustHosts        []string                    `json:"exact_trust_hosts,omitempty"`
	CandidateTrustStoreIDs []string                    `json:"candidate_trust_store_ids,omitempty"`
	CandidateTrustHosts    []string                    `json:"candidate_trust_hosts,omitempty"`
	Status                 string                      `json:"status"`
	Phase                  string                      `json:"phase"`
	Reason                 string                      `json:"reason,omitempty"`
	BatchSize              int                         `json:"batch_size,omitempty"`
	NextBatchIndex         int                         `json:"next_batch_index,omitempty"`
	HaltedReason           string                      `json:"halted_reason,omitempty"`
	Connector              string                      `json:"connector,omitempty"`
	Target                 string                      `json:"target,omitempty"`
	GraphImpact            json.RawMessage             `json:"graph_impact"`
	AffectedIdentityIDs    []string                    `json:"affected_identity_ids,omitempty"`
	ReplacementIdentityIDs []string                    `json:"replacement_identity_ids,omitempty"`
	RevokedIdentityIDs     []string                    `json:"revoked_identity_ids,omitempty"`
	ConnectorDeliveryIDs   []string                    `json:"connector_delivery_ids,omitempty"`
	Batches                []FleetReissuanceBatch      `json:"batches,omitempty"`
	HealthGates            []FleetReissuanceHealthGate `json:"health_gates,omitempty"`
	FailedTargets          []string                    `json:"failed_targets,omitempty"`
	RollbackRefs           []string                    `json:"rollback_refs,omitempty"`
	EvidenceBundleFormat   string                      `json:"evidence_bundle_format,omitempty"`
	EvidenceBundle         string                      `json:"evidence_bundle,omitempty"`
	IdempotencyKey         string                      `json:"idempotency_key,omitempty"`
	CreatedBy              string                      `json:"created_by,omitempty"`
}

// RemediationPlaybookRunRecorded is the payload of
// remediation.playbook_run.recorded. It is operational evidence only: target ids,
// action phase, scope delta, outbox/connector evidence ids, rollback references,
// and the operator/idempotency metadata needed to audit a served remediation run.
type RemediationPlaybookRunRecorded struct {
	ID                   string          `json:"id"`
	PlaybookID           string          `json:"playbook_id"`
	TargetIdentityID     string          `json:"target_identity_id,omitempty"`
	InventoryID          string          `json:"inventory_id,omitempty"`
	Status               string          `json:"status"`
	Phase                string          `json:"phase"`
	Action               string          `json:"action"`
	Reason               string          `json:"reason,omitempty"`
	Connector            string          `json:"connector,omitempty"`
	Target               string          `json:"target,omitempty"`
	OutboxID             *int64          `json:"outbox_id,omitempty"`
	ConnectorDeliveryID  *string         `json:"connector_delivery_id,omitempty"`
	ScopeDelta           json.RawMessage `json:"scope_delta"`
	EvidenceRefs         []string        `json:"evidence_refs,omitempty"`
	RollbackRefs         []string        `json:"rollback_refs,omitempty"`
	IdempotencyKey       string          `json:"idempotency_key,omitempty"`
	RequestBinding       string          `json:"request_binding,omitempty"`
	InitialHTTPStatus    int             `json:"initial_http_status,omitempty"`
	InitialResponse      json.RawMessage `json:"initial_response,omitempty"`
	TerminalReason       string          `json:"terminal_reason,omitempty"`
	OutboxIdempotencyKey string          `json:"outbox_idempotency_key,omitempty"`
	CreatedBy            string          `json:"created_by,omitempty"`
}

// ResponseIntegrationDispatched is the payload of response.integration.dispatched.
// It is an event-sourced audit fact for CAP-REM-03; delivery state lives in outbox
// rows keyed from the event id.
type ResponseIntegrationDispatched struct {
	ID               string                                     `json:"id"`
	IncidentID       string                                     `json:"incident_id,omitempty"`
	RemediationRunID string                                     `json:"remediation_run_id,omitempty"`
	Title            string                                     `json:"title"`
	Summary          string                                     `json:"summary,omitempty"`
	Severity         string                                     `json:"severity,omitempty"`
	CorrelationID    string                                     `json:"correlation_id,omitempty"`
	EvidenceRefs     []string                                   `json:"evidence_refs,omitempty"`
	Destinations     []ResponseIntegrationDispatchedDestination `json:"destinations"`
	RequestedBy      string                                     `json:"requested_by,omitempty"`
}

type ResponseIntegrationDispatchedDestination struct {
	ID                   string `json:"id,omitempty"`
	Provider             string `json:"provider"`
	EndpointURL          string `json:"endpoint_url,omitempty"`
	InstanceURL          string `json:"instance_url,omitempty"`
	TokenRef             string `json:"token_ref,omitempty"`
	ProjectKey           string `json:"project_key,omitempty"`
	IssueType            string `json:"issue_type,omitempty"`
	Table                string `json:"table,omitempty"`
	Channel              string `json:"channel,omitempty"`
	AllowPrivateEndpoint bool   `json:"allow_private_endpoint,omitempty"`
}

// RestoreDrillAttestationKind is the immutable evidence projection discriminator.
// It is not credential-issuance attestation data even though it shares the
// generic append-only evidence table.
const RestoreDrillAttestationKind = "backup.restore_drill"

type RestoreDrillAlertReason = backup.DrillAlertReason

const (
	RestoreDrillAlertFailed   = backup.DrillAlertFailed
	RestoreDrillAlertSkipped  = backup.DrillAlertSkipped
	RestoreDrillAlertOverRPO  = backup.DrillAlertOverRPO
	RestoreDrillAlertOverRTO  = backup.DrillAlertOverRTO
	RestoreDrillAlertOverBoth = backup.DrillAlertOverBoth
)

// RestoreDrillRecorded is the v1 immutable event payload. The tenant lives in
// the envelope; the signed evidence is deployment-scoped because one physical
// recovery exercise proves the shared control plane and is projected once into
// each tenant's isolated operational history.
type RestoreDrillRecorded struct {
	AttestationID string                     `json:"attestation_id"`
	Evidence      backup.SignedDrillEvidence `json:"evidence"`
}

var restoreDrillAttestationNamespace = uuid.MustParse("0aa27380-373f-5e0f-97a7-ef3027281c36")

// RestoreDrillAttestationID binds one deployment drill to exactly one history
// row per tenant. The signed DrillID supplies the immutable command identity;
// deriving the row ID prevents replaying the same proof under arbitrary IDs to
// manufacture duplicate history or notification intents.
func RestoreDrillAttestationID(tenantID, drillID string) string {
	return uuid.NewSHA1(restoreDrillAttestationNamespace, []byte(tenantID+"\x1f"+drillID)).String()
}

// identityTransition decodes the orchestrator's lifecycle event payload. The
// projector applies the new status to the identity row AND appends the full
// transition to the identity_transitions read model (SPINE-001), so History/State
// read an indexed, tenant-scoped projection instead of replaying the whole log.
// (The contract is the JSON, so the projector does not import the orchestrator.)
type identityTransition struct {
	IdentityID         string                                  `json:"identity_id"`
	From               string                                  `json:"from"`
	To                 string                                  `json:"to"`
	Reason             string                                  `json:"reason,omitempty"`
	IdempotencyKey     string                                  `json:"idempotency_key,omitempty"`
	SubjectCSRPEM      string                                  `json:"subject_csr_pem,omitempty"`
	SideEffect         *identityTransitionEffect               `json:"side_effect,omitempty"`
	Approval           *store.OperationApprovalUse             `json:"approval,omitempty"`
	Issuance           *store.OperationApprovalIssuanceBinding `json:"issuance,omitempty"`
	OwnershipReadiness *store.OwnershipReadinessEvidence       `json:"ownership_readiness,omitempty"`
}

// identityTransitionEffect mirrors the lifecycle event's durable AN-6 intent
// without importing the orchestrator package (which already imports projections).
// Approval schema v4 deliberately carries no nested Payload: its outbox body is
// derived by removing SideEffect from the one canonical outer event.
type identityTransitionEffect struct {
	Destination       string `json:"destination"`
	IdempotencyKey    string `json:"idempotency_key"`
	Payload           []byte `json:"payload,omitempty"`
	RequiredAgentRole string `json:"required_agent_role,omitempty"`
}

// Projector derives PostgreSQL read models from the event stream (AN-2). The
// read model is always a projection of the log; nothing writes the served
// domain read model except through here.
type Projector struct {
	store                            *store.Store
	eventProjections                 []EventProjection
	allowSecretSyncRecoveryBootstrap bool
	ownershipAttestationCadence      time.Duration
	restoreDrillVerificationKeys     *jose.JWKSet
}

// Option customizes the generic projector without coupling MPL core to any
// edition package.
type Option func(*Projector)

// EventProjection is a feature-neutral registration seam for derived projections
// that consume the AN-2 event stream but own their own materialization. Edition
// packages can register one through the tagged attach path; core only calls the
// interface and does not know the projection's domain.
type EventProjection interface {
	Name() string
	Reset(context.Context) error
	Apply(context.Context, eventspec.Event) error
}

// WatermarkedEventProjection lets the generic projector skip at-least-once tail
// duplicates that were already covered by a full replay during boot.
type WatermarkedEventProjection interface {
	ReplayWatermark() uint64
}

// TransactionalEventProjection lets a persistent edition projection join the
// SAME PostgreSQL transaction as an explicit full read-model rebuild. Without
// this seam an extension's Reset/Apply would commit on another connection; a
// later malformed event could roll core back while leaving the edition view
// truncated or partially replayed. Core knows only this feature-neutral
// interface and never imports an edition package (AN-9).
type TransactionalEventProjection interface {
	EventProjection
	ResetTx(context.Context, pgx.Tx) error
	ApplyTx(context.Context, pgx.Tx, eventspec.Event) error
}

// TransactionalTenantLifecycleProjection is the explicit opt-in for an
// extension that materializes tenant.registered or tenant.offboarded. Those two
// events change whether the tenant exists, so their extension state must join
// the SAME short lifecycle-fenced transaction as the core tenants row. ApplyTx
// must therefore be rollback-safe: it may change state through tx, but it must
// not advance an in-memory watermark (or expose any other irreversible state)
// before the caller commits.
//
// Boot catch-up is different: extension state is rebuilt from sequence zero
// while the durable core read model may already be at a later checkpoint.
// ReplayTenantLifecycleTx is that explicit extension-only replay path. It must
// derive only the extension's state from event and tx; it must not inspect or
// mutate core tables as though they represented this historical sequence.
// Keeping the methods separate prevents a historical registration from being
// handed to live ApplyTx while the core tenants row still represents a later
// offboard or re-registration.
//
// Extensions that do not implement this marker never receive tenant lifecycle
// events from the live command path. In particular, they are not called through
// Apply after the lifecycle fence has been released.
type TransactionalTenantLifecycleProjection interface {
	TransactionalEventProjection
	ProjectsTenantLifecycle()
	ReplayTenantLifecycleTx(context.Context, pgx.Tx, eventspec.Event) error
}

// WithEventProjection registers an additional event-stream projection. Nil
// projections are ignored so callers can assemble optional licensed components
// without branching in core.
func WithEventProjection(proj EventProjection) Option {
	return func(p *Projector) {
		if proj != nil {
			p.eventProjections = append(p.eventProjections, proj)
		}
	}
}

// WithSecretSyncRecoveryBootstrap permits only the offline restore coordinator
// to rebuild projections while the durable secret-sync receiver fence is red.
// It also lets that destructive rebuild discard the temporary job/outbox joins
// created between the event and PostgreSQL phases; the rebuilt result still runs
// the complete retained-history validation. It never authorizes receiver I/O;
// the store repeats that check immediately before every external-call start.
// Ordinary startup must not use this option.
func WithSecretSyncRecoveryBootstrap() Option {
	return func(p *Projector) {
		p.allowSecretSyncRecoveryBootstrap = true
	}
}

// WithOwnershipAttestationCadence supplies the same validated cadence used by
// the command side. It lets v6 steady-state events verify their immutable proof
// during live projection, restart catch-up, and zero-state rebuild.
func WithOwnershipAttestationCadence(cadence time.Duration) Option {
	return func(p *Projector) {
		if cadence > 0 {
			p.ownershipAttestationCadence = cadence
		}
	}
}

// WithRestoreDrillVerificationKeys supplies deployment-trusted public keys for
// immutable restore-drill evidence. Embedded record keys remain portability
// material and can never choose projection authority.
func WithRestoreDrillVerificationKeys(keys *jose.JWKSet) Option {
	return func(p *Projector) { p.restoreDrillVerificationKeys = keys }
}

// New returns a Projector that writes into s.
func New(s *store.Store, opts ...Option) *Projector {
	p := &Projector{store: s}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	return p
}

type tenantRegistered struct {
	Name string `json:"name"`
}

// tenantOffboarded is the payload of a tenant.offboarded event (TENANT-002). It
// carries no secret material — only the count of rows the command-side erase
// removed — so a replay does not need it to reproduce state (the projector
// re-runs the deterministic erase); it is retained for the audit trail. The
// tenant id is the event envelope's TenantID.
type tenantOffboarded struct {
	RowsDeleted int `json:"rows_deleted"`
}

// TenantMemberUpserted is the payload of a tenant.member.upserted event.
type TenantMemberUpserted struct {
	Subject     string   `json:"subject"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Source      string   `json:"source,omitempty"`
}

// TenantMemberOffboarded is the payload of a tenant.member.offboarded event.
type TenantMemberOffboarded struct {
	Subject           string `json:"subject"`
	Reason            string `json:"reason,omitempty"`
	OffboardedBy      string `json:"offboarded_by,omitempty"`
	RevokedTokenCount int    `json:"revoked_token_count"`
}

// APITokenCreated is the payload of an api_token.created event. It carries the
// token hash and metadata only; the raw bearer token is reveal-once response
// material and is never stored in the event log.
type APITokenCreated struct {
	ID        string     `json:"id"`
	TokenHash string     `json:"token_hash"`
	Subject   string     `json:"subject"`
	Scopes    []string   `json:"scopes,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// APITokenRevoked is the payload of an api_token.revoked event.
type APITokenRevoked struct {
	ID        string `json:"id"`
	Reason    string `json:"reason,omitempty"`
	RevokedBy string `json:"revoked_by,omitempty"`
}

// PAMSessionStarted is the payload of pam.session.started. It carries only
// session metadata and backend revoke handles; the one-time credential bytes/DSN
// returned to the caller are intentionally omitted.
type PAMSessionStarted struct {
	ID             string          `json:"id"`
	TargetType     string          `json:"target_type"`
	TargetID       string          `json:"target_id"`
	Role           string          `json:"role"`
	Status         string          `json:"status"`
	Subject        string          `json:"subject"`
	RequestedBy    string          `json:"requested_by"`
	Reason         string          `json:"reason,omitempty"`
	AttestationID  string          `json:"attestation_id,omitempty"`
	BackendRef     string          `json:"backend_ref,omitempty"`
	SSHKeyID       string          `json:"ssh_key_id,omitempty"`
	SSHSerial      uint64          `json:"ssh_serial,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	Audit          json.RawMessage `json:"audit,omitempty"`
	StartedAt      time.Time       `json:"started_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
}

// PAMSessionExpired is the payload of pam.session.expired.
type PAMSessionExpired struct {
	ID      string    `json:"id"`
	EndedAt time.Time `json:"ended_at"`
	Reason  string    `json:"reason,omitempty"`
}

// MachineSessionStarted is the payload of secrets.session.started (C-S3,
// DA-02). It carries session metadata only — never the exchanged credential
// or any token material (AN-8).
type MachineSessionStarted struct {
	ID        string    `json:"id"`
	Principal string    `json:"principal"`
	Method    string    `json:"method"`
	Scopes    []string  `json:"scopes,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MachineSessionRevoked is the payload of secrets.session.revoked.
type MachineSessionRevoked struct {
	ID        string    `json:"id"`
	RevokedBy string    `json:"revoked_by,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
}

// MachineAuthMethodOverride is the payload of secrets.auth_method.disabled and
// secrets.auth_method.enabled: the tenant-level overlay on the config-declared
// machine-auth method set. The event type carries the direction.
type MachineAuthMethodOverride struct {
	Name      string `json:"name"`
	UpdatedBy string `json:"updated_by,omitempty"`
}

// Apply applies a single event to the read model in its own tenant-scoped
// transaction. It is exported so the command side can project an event live,
// right after appending it, using the same logic a rebuild uses.
func (p *Projector) Apply(ctx context.Context, e events.Event) error {
	if isTenantLifecycleEventType(e.Type) && len(p.eventProjections) != 0 {
		return fmt.Errorf(
			"projections: %s requires transactional tenant lifecycle dispatch",
			e.Type,
		)
	}
	if err := p.applyCore(ctx, e); err != nil {
		return err
	}
	return p.applyEventProjections(ctx, e)
}

func (p *Projector) applyCore(ctx context.Context, e events.Event) error {
	if e.Type == EventTenantRegistered {
		if err := ValidateSchemaVersion(e); err != nil {
			return err
		}
		var payload tenantRegistered
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return p.store.UpsertTenant(ctx, store.Tenant{
			TenantID: e.TenantID, Name: payload.Name, EventSeq: e.Sequence,
		})
	}
	if e.Type == EventTenantOffboarded {
		if err := ValidateSchemaVersion(e); err != nil {
			return err
		}
		// Validate the payload shape (the event contract) before acting; the projector
		// does not need its fields to reproduce state, but a malformed payload signals a
		// producer bug we want to surface rather than silently ignore.
		var payload tenantOffboarded
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		// Tenant offboarding (TENANT-002, AN-2): the event is the source of truth, so
		// the projector erases the tenant's rows by re-running the same RLS-scoped,
		// fail-closed deletion the command side ran. This makes a Rebuild honest — a
		// rebuilt read model does not resurrect a tenant whose deletion is recorded in
		// the log. OffboardTenant is idempotent on an already-erased tenant (every
		// per-table count is 0 and the verify pass still passes), so replaying the
		// event after the rows are gone is a safe no-op.
		if _, err := p.store.ProjectTenantOffboard(ctx, e.TenantID); err != nil {
			return fmt.Errorf("projections: apply %s: %w", e.Type, err)
		}
		return nil
	}
	if e.Type == EventSecretSyncDelivered || e.Type == EventSecretSyncFailed ||
		e.Type == EventSecretRotationScheduleRan {
		return p.store.WithTenantProjection(ctx, e.TenantID, func(tx pgx.Tx) error {
			return p.ApplyTx(ctx, tx, e)
		})
	}
	// Domain entity events apply under the tenant's RLS context.
	return p.store.WithTenant(ctx, e.TenantID, func(tx pgx.Tx) error {
		return p.ApplyTx(ctx, tx, e)
	})
}

func (p *Projector) applyEventProjections(ctx context.Context, e events.Event) error {
	for _, proj := range p.eventProjections {
		if proj == nil {
			continue
		}
		if watermarked, ok := proj.(WatermarkedEventProjection); ok && e.Sequence != 0 && e.Sequence <= watermarked.ReplayWatermark() {
			continue
		}
		if err := proj.Apply(ctx, e); err != nil {
			return fmt.Errorf("projections: apply extension %s seq %d: %w", proj.Name(), e.Sequence, err)
		}
	}
	return nil
}

// ApplyEventProjections applies only the configured non-core projections. Tenant
// lifecycle command paths must use ApplyTenantLifecycleTx instead: dispatching a
// registration or offboard here would let a late extension resurrect or erase a
// newer lifecycle after the exclusive fence was released.
func (p *Projector) ApplyEventProjections(ctx context.Context, e events.Event) error {
	if isTenantLifecycleEventType(e.Type) {
		return fmt.Errorf("projections: %s extensions require ApplyTenantLifecycleTx", e.Type)
	}
	return p.applyEventProjections(ctx, e)
}

func isTenantLifecycleEventType(eventType string) bool {
	return eventType == EventTenantRegistered || eventType == EventTenantOffboarded
}

// ApplyTenantLifecycleTx applies the core tenant existence change and every
// explicitly lifecycle-aware extension on the caller's one transaction. It is
// the only live projection entry point for tenant.registered/offboarded.
func (p *Projector) ApplyTenantLifecycleTx(
	ctx context.Context,
	tx pgx.Tx,
	event events.Event,
) error {
	if p == nil || tx == nil || !isTenantLifecycleEventType(event.Type) {
		return errors.New("projections: transactional tenant lifecycle projection is incomplete")
	}
	if err := p.ApplyTx(ctx, tx, event); err != nil {
		return err
	}
	return p.applyTenantLifecycleEventProjectionsTx(ctx, tx, event)
}

func (p *Projector) applyTenantLifecycleEventProjectionsTx(
	ctx context.Context,
	tx pgx.Tx,
	event events.Event,
) error {
	for _, proj := range p.eventProjections {
		lifecycle, ok := proj.(TransactionalTenantLifecycleProjection)
		if !ok || lifecycle == nil {
			continue
		}
		if err := lifecycle.ApplyTx(ctx, tx, event); err != nil {
			return fmt.Errorf(
				"projections: transactionally apply tenant lifecycle extension %s seq %d: %w",
				proj.Name(), event.Sequence, err,
			)
		}
	}
	return nil
}

func (p *Projector) replayRetainedTenantLifecycleEventProjections(
	ctx context.Context,
	event events.Event,
) error {
	if p == nil || p.store == nil || !isTenantLifecycleEventType(event.Type) {
		return errors.New("projections: retained tenant lifecycle extension replay is incomplete")
	}
	return p.store.WithTenantRegistrationFence(ctx, event.TenantID, func(tx pgx.Tx) error {
		for _, proj := range p.eventProjections {
			lifecycle, ok := proj.(TransactionalTenantLifecycleProjection)
			if !ok || lifecycle == nil {
				continue
			}
			if err := lifecycle.ReplayTenantLifecycleTx(ctx, tx, event); err != nil {
				return fmt.Errorf(
					"projections: replay tenant lifecycle extension %s seq %d: %w",
					proj.Name(), event.Sequence, err,
				)
			}
		}
		return nil
	})
}

// ApplyRetainedTenantLifecycle is the replay/tail entry point for a lifecycle
// event already fixed by a history read. It opens one short tenant transaction;
// core and explicitly opted-in extensions commit or roll back together while the
// missing-row-capable lifecycle fence is held.
func (p *Projector) ApplyRetainedTenantLifecycle(ctx context.Context, event events.Event) error {
	if p == nil || p.store == nil || !isTenantLifecycleEventType(event.Type) {
		return errors.New("projections: retained tenant lifecycle projection is incomplete")
	}
	if event.Type == EventTenantRegistered {
		return p.store.WithTenantRegistrationFence(ctx, event.TenantID, func(tx pgx.Tx) error {
			return p.ApplyTenantLifecycleTx(ctx, tx, event)
		})
	}
	return p.store.WithTenant(ctx, event.TenantID, func(tx pgx.Tx) error {
		return p.ApplyTenantLifecycleTx(ctx, tx, event)
	})
}

func (p *Projector) resetEventProjections(ctx context.Context) error {
	for _, proj := range p.eventProjections {
		if proj == nil {
			continue
		}
		if err := proj.Reset(ctx); err != nil {
			return fmt.Errorf("projections: reset extension %s: %w", proj.Name(), err)
		}
	}
	return nil
}

func (p *Projector) resetEventProjectionsTx(ctx context.Context, tx pgx.Tx) error {
	for _, proj := range p.eventProjections {
		if proj == nil {
			continue
		}
		if transactional, ok := proj.(TransactionalEventProjection); ok {
			if err := transactional.ResetTx(ctx, tx); err != nil {
				return fmt.Errorf("projections: transactionally reset extension %s: %w", proj.Name(), err)
			}
			continue
		}
		if err := proj.Reset(ctx); err != nil {
			return fmt.Errorf("projections: reset extension %s: %w", proj.Name(), err)
		}
	}
	return nil
}

func (p *Projector) applyEventProjectionsTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	if isTenantLifecycleEventType(event.Type) {
		return p.applyTenantLifecycleEventProjectionsTx(ctx, tx, event)
	}
	for _, proj := range p.eventProjections {
		if proj == nil {
			continue
		}
		if transactional, ok := proj.(TransactionalEventProjection); ok {
			if err := transactional.ApplyTx(ctx, tx, event); err != nil {
				return fmt.Errorf("projections: transactionally apply extension %s seq %d: %w", proj.Name(), event.Sequence, err)
			}
			continue
		}
		if err := proj.Apply(ctx, event); err != nil {
			return fmt.Errorf("projections: apply extension %s seq %d: %w", proj.Name(), event.Sequence, err)
		}
	}
	return nil
}

func (p *Projector) rebuildEventProjectionsThrough(
	ctx context.Context,
	log *events.Log,
	replayHead uint64,
) error {
	if len(p.eventProjections) == 0 {
		return nil
	}
	if err := p.resetEventProjections(ctx); err != nil {
		return err
	}
	if replayHead == 0 {
		return nil
	}
	return log.ReplayThrough(ctx, 0, replayHead, func(e events.Event) error {
		if isTenantLifecycleEventType(e.Type) {
			return p.replayRetainedTenantLifecycleEventProjections(ctx, e)
		}
		for _, proj := range p.eventProjections {
			if proj == nil {
				continue
			}
			if err := proj.Apply(ctx, e); err != nil {
				return fmt.Errorf("projections: replay extension %s seq %d: %w", proj.Name(), e.Sequence, err)
			}
		}
		return nil
	})
}

// knownSchemaVersions records, per event type the projector decodes, the set of
// payload-shape versions it knows how to apply (SCHEMA-001). A *known* type that
// arrives with a version not in its set is rejected rather than decoded with the
// wrong shape — the failure mode the version field exists to prevent on a replay
// or rebuild. Adding a new payload shape for an existing type means adding its
// version here together with a decoder branch that handles it.
//
// An event type absent from this map is not version-gated: it is an unknown type
// (ignored, keeping projections forward-compatible to new types). Only types with
// an explicit decoder are gated, because only they would mis-project silently.
var knownSchemaVersions = map[string]map[int]bool{
	audit.EventTypeArchived:                       {audit.ArchivedEventSchemaVersion: true},
	EventTenantRegistered:                         {1: true},
	EventTenantOffboarded:                         {1: true},
	EventRestoreDrillRecorded:                     {1: true},
	EventOwnerCreated:                             {1: true, OwnerDepthEventSchemaVersion: true},
	EventOwnerUpdated:                             {1: true, OwnerDepthEventSchemaVersion: true},
	EventOwnershipAttested:                        {1: true},
	EventOwnerReattestationRequested:              {1: true},
	EventOwnershipExceptionGranted:                {1: true},
	EventOwnershipExceptionRevoked:                {1: true},
	EventOwnershipReconciled:                      {1: true},
	EventCMDBScheduleConfigured:                   {1: true},
	EventIssuanceRequestOpened:                    {1: true},
	EventIssuanceRequestDecided:                   {1: true},
	EventApprovalRequested:                        {1: true},
	EventApprovalDecisionRecorded:                 {1: true},
	EventApprovalStatusChanged:                    {1: true},
	EventTicketIntakeConfigured:                   {1: true},
	EventEnrollmentDiagnosticObserved:             {1: true},
	EventMDMDeviceCorrelated:                      {1: true},
	EventMDMPollConfigured:                        {1: true},
	EventEdgeSegmentPolicySet:                     {1: true},
	EventEdgeDelegationIssued:                     {1: true},
	EventEdgeDelegationRevoked:                    {1: true},
	EventEdgeIssuanceReconciled:                   {1: true},
	EventADCSDatabaseIngested:                     {1: true},
	EventOwnershipConflictResolved:                {1: true},
	EventAgentUpgradeCampaignOpened:               {1: true},
	EventAgentUpgradeCampaignAdvanced:             {1: true},
	EventAgentUpgradeRingAssigned:                 {1: true},
	EventAgentUpgradeRingDispatched:               {1: true},
	EventOwnerDeleted:                             {1: true},
	EventIssuerCreated:                            {1: true},
	EventIdentityCreated:                          {1: true},
	EventIdentityIssued:                           {1: true, LifecycleEventSchemaVersion: true, LifecycleSideEffectEventSchemaVersion: true, LifecycleApprovalEventSchemaVersion: true, LifecycleIssuanceEventSchemaVersion: true},
	EventIdentityDeployed:                         {1: true, LifecycleEventSchemaVersion: true, LifecycleSideEffectEventSchemaVersion: true, LifecycleApprovalEventSchemaVersion: true, LifecycleOwnershipReadinessEventSchemaVersion: true},
	EventIdentityRevoked:                          {1: true, LifecycleEventSchemaVersion: true, LifecycleSideEffectEventSchemaVersion: true, LifecycleApprovalEventSchemaVersion: true},
	EventIdentityRenewing:                         {1: true, LifecycleEventSchemaVersion: true, LifecycleSideEffectEventSchemaVersion: true, LifecycleApprovalEventSchemaVersion: true},
	EventIdentityRenewed:                          {1: true, LifecycleEventSchemaVersion: true, LifecycleSideEffectEventSchemaVersion: true, LifecycleApprovalEventSchemaVersion: true, LifecycleOwnershipReadinessEventSchemaVersion: true},
	EventIdentityRetired:                          {1: true, LifecycleEventSchemaVersion: true, LifecycleSideEffectEventSchemaVersion: true, LifecycleApprovalEventSchemaVersion: true},
	EventCertificateRecorded:                      {1: true, CertificateApprovalEventSchemaVersion: true},
	EventCertificateRevoked:                       {1: true},
	EventCertificateSuperseded:                    {1: true},
	EventCAIssuedCertificate:                      {1: true},
	EventCACertificateRevoked:                     {1: true},
	EventCACeremonyStarted:                        {1: true},
	EventCACeremonyApproved:                       {1: true},
	EventCARootCreated:                            {1: true, CAAuthorityCreatedEventSchemaVersion: true},
	EventCAAuthorityImported:                      {1: true, CAAuthorityCreatedEventSchemaVersion: true},
	EventCAIntermediateCreated:                    {1: true, CAAuthorityCreatedEventSchemaVersion: true},
	EventCAEndEntityIssued:                        {1: true},
	EventCAAuthorityRotated:                       {1: true},
	EventCAAuthorityRekeyed:                       {1: true},
	EventCACrossSigned:                            {1: true},
	EventBreakglassIssued:                         {1: true},
	EventBreakglassCARotated:                      {1: true},
	EventBreakglassCACrossSigned:                  {1: true},
	EventCRLPublished:                             {1: true, 2: true, 3: true},
	EventOCSPResponderRotated:                     {1: true},
	EventAgentHeartbeat:                           {1: true},
	EventAgentCertRenewed:                         {1: true},
	EventAgentCertRevoked:                         {1: true},
	EventAgentOffboarded:                          {1: true},
	EventKubernetesControllerPostureReported:      {1: true},
	EventProfileCreated:                           {1: true, 2: true},
	EventProfileUpdated:                           {1: true, 2: true},
	EventDiscoverySegmentUpserted:                 {1: true},
	EventDiscoverySourceUpserted:                  {1: true},
	EventDiscoveryScheduleUpserted:                {1: true},
	EventDiscoveryRunQueued:                       {1: true},
	EventDiscoveryRunStarted:                      {1: true},
	EventDiscoveryFindingRecorded:                 {1: true},
	EventDiscoveryFindingTriageChanged:            {1: true},
	EventDiscoveryRunCompleted:                    {1: true},
	EventADCSInventoryObserved:                    {1: true},
	EventRevocationProbeQueued:                    {1: true},
	EventRevocationHealthObserved:                 {1: true},
	EventMigrationRunRecorded:                     {1: true},
	EventACMEDNS01ProviderConfigUpserted:          {1: true},
	EventACMEDNS01ProviderConfigDeleted:           {1: true},
	EventACMEDNS01Preflighted:                     {1: true},
	EventACMEDNS01RecordPresented:                 {1: true},
	EventACMEDNS01RecordCleaned:                   {1: true},
	EventACMEUpstreamAuthorizationObserved:        {1: true},
	EventEndpointVerified:                         {1: true},
	EventMDMSCEPPolicyUpserted:                    {1: true},
	EventMDMSCEPPolicyDeleted:                     {1: true},
	EventMDMSCEPChallengeRotated:                  {1: true},
	EventWorkloadAttesterTrustSourceUpserted:      {1: true},
	EventWorkloadAttesterTrustSourceRotated:       {1: true},
	EventWorkloadAttesterTrustSourceRevoked:       {1: true},
	EventWorkloadAttesterTrustSourceDeleted:       {1: true},
	EventComplianceReportScheduleUpserted:         {1: true},
	EventSecretRotationScheduleUpserted:           {1: true},
	EventSecretRotationScheduleRan:                {1: true, rotationcommand.LegacyBoundEventSchemaVersion: true, SecretRotationScheduleRanEventSchemaVersion: true},
	EventNotificationRead:                         {1: true},
	EventNotificationChannelUpserted:              {1: true},
	EventNotificationChannelDeleted:               {1: true},
	EventNotificationRoutingPolicyUpserted:        {1: true},
	EventNotificationRoutingPolicyDeleted:         {1: true},
	EventNotificationThresholdDelivered:           {1: true},
	EventNotificationTestQueued:                   {1: true},
	EventNotificationDeliveryRecorded:             {1: true},
	EventCBOMAssetObserved:                        {1: true},
	EventDeploymentTargetUpserted:                 {1: true},
	EventDeploymentTargetDeleted:                  {1: true},
	EventIdentityConnectorTargetBound:             {1: true},
	EventConnectorDeliveryRecorded:                {1: true},
	EventLifecycleRotationRecorded:                {1: true},
	EventOutboxReconciliationConflictRecorded:     {1: true},
	EventIncidentExecutionRecorded:                {1: true},
	EventIncidentFleetReissuanceRecorded:          {1: true},
	EventRemediationPlaybookRunRecorded:           {1: true},
	EventResponseIntegrationDispatched:            {1: true},
	EventPrivacySubjectErased:                     {1: true, PrivacySubjectErasedOperationEventSchemaVersion: true, PrivacySubjectErasedEventSchemaVersion: true},
	EventHistoryTenantDataRewriteContinuity:       {1: true},
	EventPrivacyRetentionEnforced:                 {1: true},
	EventPrivacyArchiveErasureAttested:            {1: true},
	EventTenantMemberUpserted:                     {1: true},
	EventTenantMemberOffboarded:                   {1: true},
	EventAPITokenCreated:                          {1: true},
	EventAPITokenRevoked:                          {1: true},
	EventPAMSessionStarted:                        {1: true},
	EventMachineSessionStarted:                    {1: true},
	EventMachineSessionRevoked:                    {1: true},
	EventMachineAuthMethodDisabled:                {1: true},
	EventMachineAuthMethodEnabled:                 {1: true},
	EventPAMSessionExpired:                        {1: true},
	EventNHIAccessReviewCampaignStarted:           {1: true},
	EventNHIAccessReviewItemDecided:               {1: true},
	EventPQCMigrationCampaignStarted:              {1: true},
	EventPQCMigrationCampaignUpdated:              {1: true},
	EventPQCMigrationCampaignFindingDispositioned: {1: true},
	EventPQCMigrationCampaignClosed:               {1: true},
	EventAccessChangeRequestCreated:               {1: true},
	EventAccessChangeRequestDecided:               {1: true},
	EventTenantKeyDomainMigrationStarted:          {1: true},
	EventTenantKeyDomainMigrationProgressed:       {1: true},
	EventTenantKeyDomainMigrationCompleted:        {1: true},
	EventTenantKeyDomainMigrationFailed:           {1: true},
	EventTenantKeyDomainSealRequested:             {1: true},
	EventTenantKeyDomainSealFailed:                {1: true},
	EventTenantKeyDomainSealed:                    {1: true},
	EventTenantKeyDomainUnsealRequested:           {1: true},
	EventTenantKeyDomainUnsealed:                  {1: true},
}

func init() {
	knownSchemaVersions[EventLicensedCryptoMigrationStarted] = map[int]bool{1: true}
	knownSchemaVersions[EventLicensedCryptoMigrationAssetCompleted] = map[int]bool{1: true}
	knownSchemaVersions[EventLicensedCryptoMigrationRollbackCompleted] = map[int]bool{1: true}
}

var lifecycleEventTypes = map[string]bool{
	EventIdentityIssued:   true,
	EventIdentityDeployed: true,
	EventIdentityRevoked:  true,
	EventIdentityRenewing: true,
	EventIdentityRenewed:  true,
	EventIdentityRetired:  true,
}

// ErrUnknownSchemaVersion is returned by ApplyTx when a known event type carries
// a schema version the projector does not understand (SCHEMA-001). Failing here —
// rather than decoding the wrong shape — keeps a rebuild correct across schema
// evolution: a forgotten projector update surfaces as a hard error on replay, not
// a silently wrong read model.
var ErrUnknownSchemaVersion = errors.New("projections: unknown event schema version")

// schemaVersionOf normalizes the envelope version: a legacy/zero version is the
// baseline (DefaultSchemaVersion), matching how the event log reconstructs it.
func schemaVersionOf(e events.Event) int {
	if e.SchemaVersion == 0 {
		return events.DefaultSchemaVersion
	}
	return e.SchemaVersion
}

// ValidateSchemaVersion checks the envelope version for event types the projector
// knows how to decode. Unknown event types stay forward-compatible and are ignored
// by old projectors; known types at unknown versions fail closed (SCHEMA-001/002).
func ValidateSchemaVersion(e events.Event) error {
	if versions, gated := knownSchemaVersions[e.Type]; gated {
		if v := schemaVersionOf(e); !versions[v] {
			return fmt.Errorf("%w: type %q v%d (seq %d)", ErrUnknownSchemaVersion, e.Type, v, e.Sequence)
		}
	}
	return nil
}

// isLifecycleEvent reports whether eventType is one of the current identity
// lifecycle transition events. It intentionally does not match every "identity.*"
// string: a new future lifecycle event must be registered before this projector
// attempts to decode it.
func isLifecycleEvent(eventType string) bool {
	return lifecycleEventTypes[eventType]
}

// ApplyTx applies a single domain event to the read model on the caller's
// transaction. The orchestrator uses it to project a lifecycle transition in the
// same transaction as the outbox enqueue (AN-6). Unknown event types are
// ignored, so projections are forward-compatible to *new* types; a *known* type
// carrying an unknown schema version is rejected (SCHEMA-001), so a payload-shape
// change to an existing type cannot silently mis-project on replay/rebuild.
func (p *Projector) ApplyTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	// Version gate (SCHEMA-001): for a type this projector decodes, the envelope's
	// schema version must be one it knows. An unrecognized version fails closed
	// rather than being decoded against the wrong struct.
	if err := ValidateSchemaVersion(e); err != nil {
		return err
	}
	switch e.Type {
	case EventTenantRegistered:
		var payload tenantRegistered
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return p.store.RegisterTenantTx(ctx, tx, store.Tenant{
			TenantID: e.TenantID, Name: payload.Name, EventSeq: e.Sequence,
		})
	case EventTenantOffboarded:
		var payload tenantOffboarded
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if _, err := p.store.OffboardTenantTx(ctx, tx, e.TenantID); err != nil {
			return fmt.Errorf("projections: apply %s: %w", e.Type, err)
		}
		return nil
	case EventRestoreDrillRecorded:
		return p.applyRestoreDrillRecordedTx(ctx, tx, e)
	}
	if handled, err := p.applyOperationApprovalTx(ctx, tx, e); handled {
		return err
	}
	if handled, err := p.applyApplicationSecretTx(ctx, tx, e); handled {
		return err
	}
	if handled, err := p.applySecretIntegrationTx(ctx, tx, e); handled {
		return err
	}
	if handled, err := p.applyManagedKeyTx(ctx, tx, e); handled {
		return err
	}
	if handled, err := p.applyCodeSigningTx(ctx, tx, e); handled {
		return err
	}
	if handled, err := p.applyKubernetesPostureTx(ctx, tx, e); handled {
		return err
	}
	switch e.Type {
	case audit.EventTypeArchived:
		var pl audit.ArchivedEvent
		if err := decode(e, &pl); err != nil {
			return err
		}
		if !pl.SourceHistoryRetained {
			return errors.New("projections: audit.archived does not attest retained AN-2 source history")
		}
		return p.store.ApplyAuditCheckpointTx(ctx, tx, audit.Checkpoint{
			TenantID: e.TenantID, BoundarySeq: pl.BoundarySeq,
			BoundaryHash: pl.BoundaryHash, RecordCount: pl.Count,
			ArchiveURI: pl.ArchiveURI,
		})
	case EventOwnerCreated:
		var pl OwnerCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		escalation, err := json.Marshal(pl.EscalationChain)
		if err != nil {
			return err
		}
		return p.store.ApplyOwnerCreatedTx(ctx, tx, store.Owner{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.OwnerKind(pl.Kind),
			Name: pl.Name, Email: pl.Email, ApplicationID: pl.ApplicationID,
			Service: pl.Service, BusinessUnit: pl.BusinessUnit, Environment: pl.Environment,
			EscalationChain: escalation, CreatedAt: e.Time,
		})
	case EventOwnerUpdated:
		var pl OwnerUpdated
		if err := decode(e, &pl); err != nil {
			return err
		}
		owner := store.Owner{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.OwnerKind(pl.Kind), Name: pl.Name, Email: pl.Email,
		}
		if schemaVersionOf(e) == 1 {
			return p.store.ApplyOwnerUpdatedLegacyTx(ctx, tx, owner)
		}
		escalation, err := json.Marshal(pl.EscalationChain)
		if err != nil {
			return err
		}
		owner.ApplicationID, owner.Service = pl.ApplicationID, pl.Service
		owner.BusinessUnit, owner.Environment = pl.BusinessUnit, pl.Environment
		owner.EscalationChain = escalation
		return p.store.ApplyOwnerUpdatedTx(ctx, tx, owner)
	case EventOwnershipAttested:
		var pl OwnershipAttested
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.OwnerID == "" || pl.AttestedBy == "" || pl.ModelDigest == "" || pl.AttestedAt.IsZero() || !pl.AttestedAt.Equal(e.Time) {
			return fmt.Errorf("projections: %s requires owner, authenticated attestor, event time, and model digest", e.Type)
		}
		return p.store.ApplyOwnershipAttestedTx(ctx, tx, e.TenantID, pl.OwnerID, pl.AttestedBy, pl.ModelDigest, pl.AttestedAt)
	case EventOwnerReattestationRequested:
		var pl OwnerReattestationRequested
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.OwnerID == "" || pl.RequestedAt.IsZero() || !pl.RequestedAt.Equal(e.Time) || pl.CadenceSeconds <= 0 {
			return fmt.Errorf("projections: %s requires owner, event time, and positive cadence", e.Type)
		}
		return p.store.ApplyOwnerReattestationRequestedTx(
			ctx, tx, e.TenantID, pl.OwnerID, pl.VerifiedFor, pl.DueAt, pl.RequestedAt,
			time.Duration(pl.CadenceSeconds)*time.Second,
		)
	case EventOwnershipExceptionGranted:
		var pl OwnershipExceptionGranted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.IdentityID == "" || strings.TrimSpace(pl.Reason) == "" || strings.TrimSpace(pl.GrantedBy) == "" ||
			pl.GrantedAt.IsZero() || !pl.GrantedAt.Equal(e.Time) || !pl.ExpiresAt.After(pl.GrantedAt) {
			return fmt.Errorf("projections: %s requires identity, attributed reason, event time, and future expiry", e.Type)
		}
		return p.store.ApplyOwnershipExceptionGrantedTx(ctx, tx, store.OwnershipException{
			ID: pl.ID, TenantID: e.TenantID, IdentityID: pl.IdentityID, Reason: pl.Reason,
			GrantedBy: pl.GrantedBy, GrantedAt: pl.GrantedAt, ExpiresAt: pl.ExpiresAt,
			CreatedEventID: e.ID, LastEventSeq: e.Sequence,
		})
	case EventOwnershipExceptionRevoked:
		var pl OwnershipExceptionRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || strings.TrimSpace(pl.RevokedBy) == "" || strings.TrimSpace(pl.Reason) == "" ||
			pl.RevokedAt.IsZero() || !pl.RevokedAt.Equal(e.Time) {
			return fmt.Errorf("projections: %s requires exception, attributed reason, and event time", e.Type)
		}
		return p.store.ApplyOwnershipExceptionRevokedTx(ctx, tx, e.TenantID, pl.ID, pl.RevokedBy, pl.Reason, pl.RevokedAt, e.Sequence)
	case EventAgentUpgradeCampaignOpened:
		var pl AgentUpgradeCampaignOpened
		if err := decode(e, &pl); err != nil {
			return err
		}
		artifacts, err := fleet.EncodeArtifacts(pl.Artifacts)
		if err != nil {
			return err
		}
		return p.store.ApplyAgentUpgradeCampaignOpenedTx(ctx, tx, e.TenantID, pl.ID, pl.TargetVersion, pl.CreatedBy, artifacts, e.Time)
	case EventAgentUpgradeRingDispatched:
		var pl AgentUpgradeRingDispatched
		if err := decode(e, &pl); err != nil {
			return err
		}
		jobs := make([]store.UpgradeDispatchJob, 0, len(pl.Jobs))
		for _, j := range pl.Jobs {
			jobs = append(jobs, store.UpgradeDispatchJob{AgentID: j.AgentID, JobKey: j.JobKey})
		}
		return p.store.ApplyAgentUpgradeRingDispatchedTx(ctx, tx, e.TenantID, pl.CampaignID, pl.Ring, pl.Round, jobs, e.Time)
	case EventAgentUpgradeCampaignAdvanced:
		var pl AgentUpgradeCampaignAdvanced
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyAgentUpgradeCampaignAdvancedTx(ctx, tx, e.TenantID, pl.ID, pl.Status, pl.CurrentRing, pl.HaltedAtRing, pl.Reason)
	case EventAgentUpgradeRingAssigned:
		var pl AgentUpgradeRingAssigned
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyAgentUpgradeRingAssignedTx(ctx, tx, e.TenantID, pl.AgentID, pl.Ring)
	case EventOwnershipConflictResolved:
		var pl OwnershipConflictResolved
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyOwnershipConflictResolvedTx(ctx, tx, e.TenantID, pl.ID, pl.ResolvedBy, pl.Resolution, pl.ResolvedAt)
	case EventTicketIntakeConfigured:
		var pl TicketIntakeConfigured
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyTicketIntakeConfiguredTx(ctx, tx, e.TenantID, store.TicketIntakeSchedule{
			System: pl.System, InstanceURL: pl.InstanceURL, TokenRef: pl.TokenRef,
			SNTable: pl.SNTable, Query: pl.Query,
			SubjectField: pl.SubjectField, ProfileField: pl.ProfileField,
			RequesterField: pl.RequesterField, JustificationField: pl.JustificationField,
			IntervalSeconds: pl.IntervalSeconds, Enabled: pl.Enabled,
			AllowPrivateEndpoint: pl.AllowPrivate, PrivateEgressCIDRs: pl.PrivateCIDRs,
		})
	case EventEnrollmentDiagnosticObserved:
		var pl EnrollmentDiagnosticObserved
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := validateEnrollmentDiagnosticObserved(pl); err != nil {
			return err
		}
		return p.store.ApplyEnrollmentDiagnosticObservedTx(ctx, tx, store.EnrollmentDiagnostic{
			TenantID: e.TenantID, Protocol: pl.Protocol, Step: pl.Step, Cause: pl.Cause,
			Summary: pl.Summary, Remediation: pl.Remediation,
			Actionable: pl.Cause != "unknown" && strings.TrimSpace(pl.Remediation) != "",
			ObservedAt: e.Time, SourceEventID: e.ID, EventSequence: e.Sequence,
		})
	case EventADCSDatabaseIngested:
		var pl ADCSDatabaseIngested
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyADCSDatabaseIngestedTx(ctx, tx, store.ADCSDatabaseSummary{
			TenantID: e.TenantID, CAConfig: pl.CAConfig,
			Issued: pl.Issued, Pending: pl.Pending, Revoked: pl.Revoked,
			Denied: pl.Denied, Failed: pl.Failed, Unknown: pl.Unknown,
			Unparsed: pl.Unparsed, Total: pl.Total,
			RowsRead: pl.RowsRead, RowsRejected: pl.RowsRejected,
			Source: pl.Source, LastError: pl.LastError, IngestedAt: e.Time,
		}, e.Sequence)
	case EventEdgeSegmentPolicySet:
		var pl EdgeSegmentPolicySet
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyEdgeSegmentPolicyTx(ctx, tx, store.EdgeSegmentPolicy{
			TenantID: e.TenantID, SegmentID: pl.SegmentID, Enabled: pl.Enabled,
			AttestationRootsPEM: pl.AttestationRootsPEM,
			PermittedDNSDomains: pl.PermittedDNSDomains,
			ExcludedDNSDomains:  pl.ExcludedDNSDomains,
			UpdatedAt:           e.Time,
		}, e.Sequence)
	case EventEdgeDelegationIssued:
		var pl EdgeDelegationIssued
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := p.store.ApplyEdgeDelegationIssuedTx(ctx, tx, store.EdgeDelegation{
			TenantID: e.TenantID, ID: pl.ID, SegmentID: pl.SegmentID, CAID: pl.CAID,
			Host: pl.Host, CommonName: pl.CommonName, Serial: pl.Serial,
			CertificatePEM:      pl.CertificatePEM,
			PermittedDNSDomains: pl.PermittedDNSDomains,
			ExcludedDNSDomains:  pl.ExcludedDNSDomains,
			AttestedKeySHA256:   pl.AttestedKeySHA256, AttestationCertSHA256: pl.AttestationCertSHA256,
			NotBefore: pl.NotBefore, NotAfter: pl.NotAfter, CreatedAt: e.Time,
		}, e.Sequence); err != nil {
			return err
		}
		// The delegated CA's certificate is an issuance OF THE PARENT CA, so it
		// joins the parent's issued ledger: OCSP answers for it and revoking
		// the delegation from the brain rides the existing CRL machinery.
		return p.store.RecordIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, e.Time)
	case EventEdgeDelegationRevoked:
		var pl EdgeDelegationRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		revokedAt := pl.RevokedAt
		if revokedAt.IsZero() {
			revokedAt = e.Time
		}
		if err := p.store.ApplyEdgeDelegationRevokedTx(ctx, tx, e.TenantID, pl.ID, pl.Reason, revokedAt, e.Sequence); err != nil {
			return err
		}
		return p.store.RevokeIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, 0, revokedAt)
	case EventEdgeIssuanceReconciled:
		var pl EdgeIssuanceReconciled
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := p.store.ApplyEdgeIssuanceReconciledTx(ctx, tx, store.EdgeIssuance{
			TenantID: e.TenantID, DelegationID: pl.DelegationID, Serial: pl.Serial,
			Subject: pl.Subject, DNSNames: pl.DNSNames,
			NotBefore: pl.NotBefore, NotAfter: pl.NotAfter,
			IssuedAt: pl.IssuedAt, ReconciledAt: e.Time,
			WithinConstraints: pl.WithinConstraints, Violation: pl.Violation,
		}, e.Sequence); err != nil {
			return err
		}
		// The leaf exists in the world whether or not it honoured the
		// constraints, so it enters the inventory either way; hiding a
		// violating certificate from the estate would compound the violation
		// with invisibility. The row id derives from (tenant, fingerprint) so
		// replaying the event converges on the same row.
		notBefore, notAfter := pl.NotBefore, pl.NotAfter
		return p.store.ApplyCertificateRecordedTx(ctx, tx, store.Certificate{
			ID:       uuid.NewSHA1(edgeIssuanceCertNamespace, []byte(e.TenantID+"\x00"+pl.Fingerprint)).String(),
			TenantID: e.TenantID, Subject: pl.Subject, SANs: pl.DNSNames,
			Serial: pl.Serial, Fingerprint: pl.Fingerprint,
			NotBefore: &notBefore, NotAfter: &notAfter,
			Source:         "edge-delegation",
			CertificateDER: pl.CertificateDER, CertificatePEM: []byte(pl.CertificatePEM),
			CreatedAt:  e.Time,
			ObservedBy: pl.Host, ObservedKind: "edge-reconcile", LastSeenAt: &e.Time,
		})
	case EventMDMPollConfigured:
		var pl MDMPollConfigured
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyMDMPollConfiguredTx(ctx, tx, e.TenantID, store.MDMPollSchedule{
			MDM: pl.MDM, BaseURL: pl.BaseURL, TokenRef: pl.TokenRef, Filter: pl.Filter,
			IntervalSeconds: pl.IntervalSeconds, Enabled: pl.Enabled,
			AllowPrivateEndpoint: pl.AllowPrivate, PrivateEgressCIDRs: pl.PrivateCIDRs,
			Execution: pl.Execution, RenewalWindowDays: pl.RenewalWindowDays,
		})
	case EventMDMDeviceCorrelated:
		var pl MDMDeviceCorrelated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyMDMDeviceCorrelatedTx(ctx, tx, store.MDMDeviceCorrelation{
			TenantID: e.TenantID, MDM: pl.MDM, MDMDeviceID: pl.MDMDeviceID,
			DeviceName: pl.DeviceName, SerialNumber: pl.SerialNumber,
			TransactionID: pl.TransactionID, IdentityID: pl.IdentityID,
			InstallState: pl.InstallState, InstallDetail: pl.InstallDetail,
			ObservedAt: pl.ObservedAt,
		})
	case EventIssuanceRequestOpened:
		var pl IssuanceRequestOpened
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyIssuanceRequestOpenedTx(ctx, tx, store.IssuanceRequest{
			ID: pl.ID, TenantID: e.TenantID, Subject: pl.Subject, Profile: pl.Profile,
			CSRPEM: pl.CSRPEM, Requester: pl.Requester, Justification: pl.Justification,
			Origin: pl.Origin, TicketRef: pl.TicketRef, ExpiresAt: pl.ExpiresAt, CreatedAt: e.Time,
		})
	case EventIssuanceRequestDecided:
		var pl IssuanceRequestDecided
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyIssuanceRequestDecidedTx(ctx, tx, e.TenantID, pl.ID, pl.Status,
			pl.DecidedBy, pl.Reason, pl.IdentityID, pl.DecidedAt)
	case EventOwnershipReconciled:
		var pl OwnershipReconciled
		if err := decode(e, &pl); err != nil {
			return err
		}
		fields := make(map[string]string, len(pl.Applied))
		for _, c := range pl.Applied {
			fields[c.Field] = c.Value
		}
		conflicts := make([]store.OwnershipConflict, 0, len(pl.Conflicts))
		for _, c := range pl.Conflicts {
			conflicts = append(conflicts, store.OwnershipConflict{
				OwnerID: pl.OwnerID, Field: c.Field,
				CurrentValue: c.CurrentValue, CurrentSource: c.CurrentSource,
				IncomingValue: c.IncomingValue, IncomingSource: c.IncomingSource,
				IncomingRef: c.IncomingRef, CurrentAttested: c.CurrentAttested,
			})
		}
		return p.store.ApplyOwnershipReconciledTx(ctx, tx, e.TenantID, e.ID, pl.OwnerID,
			fields, pl.Source, pl.SourceRef, pl.ObservedAt, conflicts)
	case EventCMDBScheduleConfigured:
		var pl CMDBScheduleConfigured
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyCMDBScheduleConfiguredTx(ctx, tx, e.TenantID, store.CMDBReconcileSchedule{
			InstanceURL: pl.InstanceURL, TokenRef: pl.TokenRef, CIQuery: pl.CIQuery,
			AllowPrivateEndpoint: pl.AllowPrivateEndpoint,
			IntervalSeconds:      pl.IntervalSeconds, Enabled: pl.Enabled,
			Execution: pl.Execution,
		})
	case EventOwnerDeleted:
		var pl OwnerDeleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.DeleteOwnerTx(ctx, tx, e.TenantID, pl.ID)
	case EventIssuerCreated:
		var pl IssuerCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyIssuerCreatedTx(ctx, tx, store.Issuer{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.IssuerKind(pl.Kind), Name: pl.Name,
			Chain: pl.Chain, PublicKey: pl.PublicKey, Internal: pl.Internal, CreatedAt: e.Time,
		})
	case EventIdentityCreated:
		var pl IdentityCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyIdentityCreatedTx(ctx, tx, store.Identity{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.IdentityKind(pl.Kind), Name: pl.Name,
			OwnerID: pl.OwnerID, IssuerID: pl.IssuerID, Status: initialIdentityStatus,
			Attributes: pl.Attributes, CreatedAt: e.Time,
		})
	case EventCertificateRecorded:
		var pl CertificateRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		approvedSchema := schemaVersionOf(e) == CertificateApprovalEventSchemaVersion
		if (pl.Approval != nil) != approvedSchema || (pl.ApprovalBinding != nil) != approvedSchema {
			return fmt.Errorf("projections: %s approval payload/schema mismatch", e.Type)
		}
		if approvedSchema {
			if err := p.resolveApprovedCertificateFenceUseTx(ctx, tx, e, &pl); err != nil {
				return err
			}
			if err := p.validateApprovedCertificateTx(ctx, tx, e, pl); err != nil {
				return err
			}
			if err := p.store.ConsumeOperationApprovalTx(ctx, tx, e.TenantID, *pl.Approval, e.ID, e.Time); err != nil {
				return err
			}
		}
		if err := p.store.ApplyCertificateRecordedTx(ctx, tx, store.Certificate{
			ID: pl.ID, TenantID: e.TenantID, CAID: pl.CAID, OwnerID: pl.OwnerID, Subject: pl.Subject, SANs: pl.SANs,
			Issuer: pl.Issuer, Serial: pl.Serial, Fingerprint: pl.Fingerprint, KeyAlgorithm: pl.KeyAlgorithm,
			NotBefore: pl.NotBefore, NotAfter: pl.NotAfter, DeploymentLocation: pl.DeploymentLocation,
			Source: pl.Source, CertificateDER: pl.CertificateDER, CertificatePEM: pl.CertificatePEM,
			IssuanceResponse:       pl.IssuanceResponse,
			IssuanceIdempotencyKey: pl.IssuanceIdempotencyKey, IssuanceRequestBinding: pl.IssuanceRequestBinding,
			ReplacesID: pl.ReplacesID, CreatedAt: e.Time,
			// B5/B2: the custody claim is projected like any other field, so a
			// Rebuild() reproduces it. Without this the column stayed empty no
			// matter what the issuing path recorded.
			KeyOrigin:      pl.KeyOrigin,
			KeyStorage:     pl.KeyStorage,
			KeyExportable:  pl.KeyExportable,
			KeyGeneratedBy: pl.KeyGeneratedBy,
		}); err != nil {
			return err
		}
		if pl.CAID != "" && pl.Serial != "" {
			if err := p.store.RecordIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, e.Time); err != nil {
				return err
			}
		}
		if approvedSchema {
			semanticDigest, err := ApprovedCertificateSemanticDigest(e, pl)
			if err != nil {
				return err
			}
			return p.store.CompleteApprovedTargetFenceTx(ctx, tx, e.TenantID,
				store.ApprovedTargetEphemeralCertificate, pl.ApprovalBinding.ClientRequestIDSHA256,
				e.ID, e.Type, schemaVersionOf(e), e.Time, []byte(semanticDigest))
		}
		return nil
	case EventCertificateRevoked:
		var pl CertificateRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		revokedAt := pl.RevokedAt
		if revokedAt.IsZero() {
			revokedAt = e.Time
		}
		if err := p.store.SetCertificateRevokedTx(ctx, tx, e.TenantID, pl.Fingerprint, pl.Reason, revokedAt); err != nil {
			return err
		}
		if pl.CAID == "" || pl.Serial == "" {
			return nil
		}
		return p.store.RevokeIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, pl.ReasonCode, revokedAt)
	case EventCertificateSuperseded:
		var pl CertificateSuperseded
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.SetCertificateSupersededTx(ctx, tx, e.TenantID, pl.Fingerprint, pl.RenewedAt)
	case EventCAIssuedCertificate:
		var pl CAIssuedCertificate
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CAID == "" || pl.Serial == "" {
			return fmt.Errorf("projections: %s requires ca_id and serial", e.Type)
		}
		issuedAt := pl.IssuedAt
		if issuedAt.IsZero() {
			issuedAt = e.Time
		}
		return p.store.RecordIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, issuedAt)
	case EventCAEndEntityIssued:
		var pl CAIssuedCertificate
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CAID == "" || pl.Serial == "" {
			return fmt.Errorf("projections: %s requires ca_id and serial", e.Type)
		}
		issuedAt := pl.IssuedAt
		if issuedAt.IsZero() {
			issuedAt = e.Time
		}
		return p.store.RecordIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, issuedAt)
	case EventCACertificateRevoked:
		var pl CACertificateRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CAID == "" || pl.Serial == "" {
			return fmt.Errorf("projections: %s requires ca_id and serial", e.Type)
		}
		revokedAt := pl.RevokedAt
		if revokedAt.IsZero() {
			revokedAt = e.Time
		}
		return p.store.RevokeIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, pl.code(), revokedAt)
	case EventCACeremonyStarted:
		var pl CACeremonyStarted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CeremonyID == "" || pl.Purpose == "" || pl.Threshold < 1 {
			return fmt.Errorf("projections: %s requires ceremony_id, purpose, and positive threshold", e.Type)
		}
		return p.store.ApplyKeyCeremonyStartedTx(ctx, tx, store.KeyCeremony{
			ID: pl.CeremonyID, TenantID: e.TenantID, Purpose: pl.Purpose, Threshold: pl.Threshold,
			Status: "pending", Opener: pl.Opener, CreatedAt: e.Time,
		})
	case EventCACeremonyApproved:
		var pl CACeremonyApproved
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CeremonyID == "" || pl.Custodian == "" {
			return fmt.Errorf("projections: %s requires ceremony_id and custodian", e.Type)
		}
		return p.store.ApplyKeyCeremonyApprovedTx(ctx, tx, e.TenantID, pl.CeremonyID, pl.Custodian, e.ID, e.Sequence, e.Time)
	case EventCARootCreated, EventCAAuthorityImported, EventCAIntermediateCreated:
		if schemaVersionOf(e) == 1 {
			// Legacy v1 create/import events were audit-only breadcrumbs emitted
			// after the SQL commit. They do not carry certificate row material, so
			// they cannot safely rebuild ca_authorities.
			return nil
		}
		var pl CAAuthorityCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		kind := pl.Kind
		switch e.Type {
		case EventCARootCreated:
			if kind == "" {
				kind = "root"
			}
			if kind != "root" {
				return fmt.Errorf("projections: %s requires root kind", e.Type)
			}
		case EventCAIntermediateCreated:
			if kind == "" {
				kind = "intermediate"
			}
			if kind != "intermediate" {
				return fmt.Errorf("projections: %s requires intermediate kind", e.Type)
			}
			if pl.ParentID == nil || *pl.ParentID == "" {
				return fmt.Errorf("projections: %s requires parent_id", e.Type)
			}
		case EventCAAuthorityImported:
			if kind != "root" && kind != "intermediate" {
				return fmt.Errorf("projections: %s requires root or intermediate kind", e.Type)
			}
		}
		if pl.CAID == "" || pl.CommonName == "" || pl.CertificatePEM == "" ||
			pl.Serial == "" || pl.NotAfter.IsZero() || pl.CeremonyID == "" {
			return fmt.Errorf("projections: %s requires ca_id, common_name, certificate_pem, serial, not_after, and ceremony_id", e.Type)
		}
		if pl.SignerHandle == "" && (e.Type != EventCARootCreated || !pl.OfflineRoot) {
			return fmt.Errorf("projections: %s requires signer_handle unless offline_root is true", e.Type)
		}
		notAfter := pl.NotAfter
		return p.store.ApplyCAAuthorityCreatedTx(ctx, tx, store.CAAuthority{
			ID: pl.CAID, TenantID: e.TenantID, ParentID: pl.ParentID, CommonName: pl.CommonName,
			Kind: kind, Status: "active", CertificatePEM: pl.CertificatePEM, SignerHandle: pl.SignerHandle,
			Serial: pl.Serial, NotAfter: &notAfter, MaxPathLen: pl.MaxPathLen,
			PermittedDNSNames: pl.PermittedDNSNames, EKUs: pl.EKUs, CreatedAt: e.Time,
		}, pl.CeremonyID, e.Time)
	case EventCAAuthorityRotated:
		var pl CAAuthorityRotated
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.PredecessorCAID == "" || pl.SuccessorCAID == "" {
			return fmt.Errorf("projections: %s requires predecessor_ca_id and successor_ca_id", e.Type)
		}
		return p.store.ApplyCAAuthorityRotatedTx(ctx, tx, e.TenantID, pl.PredecessorCAID, pl.SuccessorCAID)
	case EventCAAuthorityRekeyed:
		var pl CAAuthorityRekeyed
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.PredecessorCAID == "" || pl.CommonName == "" || pl.Kind == "" ||
			pl.CertificatePEM == "" || (!pl.OfflineRoot && pl.SignerHandle == "") || pl.Serial == "" || pl.NotAfter.IsZero() {
			return fmt.Errorf("projections: %s requires a complete signer-backed or explicit offline-root successor authority", e.Type)
		}
		if pl.OfflineRoot && (pl.SignerHandle != "" || len(pl.NewSignedByPreviousDER) == 0 || len(pl.PreviousSignedByNewDER) == 0) {
			return fmt.Errorf("projections: %s offline-root successor requires no signer handle and both public cross-certificates", e.Type)
		}
		return p.store.ApplyCAAuthorityRekeyedTx(ctx, tx, store.CAAuthority{
			ID: pl.ID, TenantID: e.TenantID, ParentID: pl.ParentID, CommonName: pl.CommonName,
			Kind: pl.Kind, Status: "active", CertificatePEM: pl.CertificatePEM, SignerHandle: pl.SignerHandle,
			Serial: pl.Serial, NotAfter: &pl.NotAfter, MaxPathLen: pl.MaxPathLen,
			PermittedDNSNames: pl.PermittedDNSNames, EKUs: pl.EKUs, CreatedAt: e.Time,
		}, pl.PredecessorCAID, pl.CeremonyID)
	case EventCACrossSigned, EventBreakglassIssued, EventBreakglassCARotated, EventBreakglassCACrossSigned:
		var pl BreakglassCeremonyCompleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CeremonyID == "" && e.Type == EventBreakglassIssued {
			return nil // legacy/offline reconciled bundles have no online ceremony
		}
		if pl.CeremonyID == "" {
			return fmt.Errorf("projections: %s requires ceremony_id", e.Type)
		}
		return p.store.ApplyKeyCeremonyCompletedTx(ctx, tx, e.TenantID, pl.CeremonyID, e.Time)
	case EventCRLPublished:
		var pl CRLPublished
		if err := decode(e, &pl); err != nil {
			return err
		}
		if schemaVersionOf(e) == 1 && len(pl.DER) == 0 {
			// Legacy audit-only CRL metadata cannot rebuild ca_crls.
			return nil
		}
		if pl.CAID == "" || pl.Number == 0 || len(pl.DER) == 0 {
			return fmt.Errorf("projections: %s v%d requires ca_id, crl_number, and crl_der", e.Type, schemaVersionOf(e))
		}
		thisUpdate := pl.ThisUpdate
		if thisUpdate.IsZero() {
			thisUpdate = e.Time
		}
		nextUpdate := pl.NextUpdate
		if nextUpdate.IsZero() {
			return fmt.Errorf("projections: %s v%d requires next_update", e.Type, schemaVersionOf(e))
		}
		return p.store.InsertCRLTx(ctx, tx, store.CRL{
			TenantID: e.TenantID, CAID: pl.CAID, Number: pl.Number, DER: pl.DER,
			ThisUpdate: thisUpdate, NextUpdate: nextUpdate, CreatedAt: e.Time,
			Kind: pl.Kind, ShardIndex: pl.ShardIndex, ShardCount: pl.ShardCount,
			DeltaBaseNumber: pl.DeltaBaseNumber, ParentNumber: pl.ParentNumber,
			RevokedCount: pl.RevokedCount,
		})
	case EventOCSPResponderRotated:
		var pl OCSPResponderRotated
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CAID == "" || pl.Serial == "" || len(pl.CertDER) == 0 || pl.NotAfter.IsZero() {
			return fmt.Errorf("projections: %s requires ca_id, serial, cert_der, and not_after", e.Type)
		}
		notBefore := pl.NotBefore
		if notBefore.IsZero() {
			notBefore = e.Time
		}
		return p.store.UpsertOCSPResponderTx(ctx, tx, store.OCSPResponder{
			TenantID: e.TenantID, CAID: pl.CAID, Serial: pl.Serial, CertDER: pl.CertDER,
			NotBefore: notBefore, NotAfter: pl.NotAfter, RotatedFromSerial: pl.RotatedFromSerial,
			CreatedAt: e.Time,
		})
	case EventAgentHeartbeat:
		var pl AgentHeartbeat
		if err := decode(e, &pl); err != nil {
			return err
		}
		lastSeen := e.Time
		row := store.Agent{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Agent, Status: pl.Status,
			Version: pl.Version, Roles: pl.Roles, LastSeenAt: &lastSeen, CreatedAt: e.Time,
		}
		// B3: posture is written only when the beat carried it. A nil pointer
		// leaves ReportedAt nil, and the upsert reads that as "this beat says
		// nothing" rather than "this host is not serving".
		if pl.WorkloadAPIServed != nil {
			row.WorkloadAPIServed = *pl.WorkloadAPIServed
			if pl.WorkloadAPISVIDs != nil {
				row.WorkloadAPISVIDs = *pl.WorkloadAPISVIDs
			}
			reported := e.Time
			row.WorkloadAPIReportedAt = &reported
		}
		return p.store.ApplyAgentHeartbeatTx(ctx, tx, row)
	case EventAgentCertRenewed:
		var pl AgentCertRenewed
		if err := decode(e, &pl); err != nil {
			return err
		}
		lastSeen := e.Time
		return p.store.ApplyAgentCertRenewedTx(ctx, tx, store.Agent{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Agent, Status: "active",
			LastSeenAt: &lastSeen, CreatedAt: e.Time,
		})
	case EventAgentCertRevoked:
		var pl AgentCertRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || (pl.Serial == "" && pl.Fingerprint == "") {
			return fmt.Errorf("projections: %s requires id and serial or fingerprint", e.Type)
		}
		revokedAt := pl.RevokedAt
		if revokedAt.IsZero() {
			revokedAt = e.Time
		}
		if pl.Serial != "" {
			if err := p.store.ApplyAgentCertRevokedTx(ctx, tx, store.AgentCertRevocation{
				TenantID: e.TenantID, AgentID: pl.ID, AgentName: pl.Agent,
				SelectorType: store.AgentCertSelectorSerial, Selector: pl.Serial,
				Reason: pl.Reason, RevokedAt: revokedAt,
			}); err != nil {
				return err
			}
		}
		if pl.Fingerprint != "" {
			if err := p.store.ApplyAgentCertRevokedTx(ctx, tx, store.AgentCertRevocation{
				TenantID: e.TenantID, AgentID: pl.ID, AgentName: pl.Agent,
				SelectorType: store.AgentCertSelectorFingerprint, Selector: pl.Fingerprint,
				Reason: pl.Reason, RevokedAt: revokedAt,
			}); err != nil {
				return err
			}
		}
		return nil
	case EventAgentOffboarded:
		var pl AgentOffboarded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		offboardedAt := e.Time
		return p.store.ApplyAgentOffboardedTx(ctx, tx, store.Agent{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Agent, Status: "offboarded",
			CreatedAt: e.Time, OffboardedAt: &offboardedAt, OffboardedBy: pl.OffboardedBy, OffboardReason: pl.Reason,
		})
	case EventProfileCreated, EventProfileUpdated:
		if schemaVersionOf(e) == 1 {
			// Legacy profile audit events did not carry the spec or id. They are kept
			// readable for audit replay, but only v2 events can project profile state.
			return nil
		}
		var pl ProfileVersioned
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyProfileVersionTx(ctx, tx, store.ProfileRecord{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Name, Version: pl.Version,
			Spec: pl.Spec, Active: pl.Active, CreatedBy: pl.CreatedBy, CreatedAt: e.Time,
		})
	case EventDiscoverySegmentUpserted:
		var pl DiscoverySegmentUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		_, err := p.store.ApplyDiscoverySegmentUpsertedTx(ctx, tx, e.TenantID, store.DiscoverySegment{
			ID: pl.ID, Name: pl.Name, Ranges: pl.Ranges, StalenessHours: pl.StalenessHours,
			Excluded: pl.Excluded, ExclusionReason: pl.ExclusionReason, CreatedAt: e.Time,
		})
		return err
	case EventDiscoverySourceUpserted:
		var pl DiscoverySourceUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := p.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: pl.ID, TenantID: e.TenantID, Kind: pl.Kind, Name: pl.Name,
			Config: pl.Config, CreatedAt: e.Time, UpdatedAt: e.Time,
		}); err != nil {
			return err
		}
		// The coverage rollup projects from the same event (AN-2): one row per
		// source carrying the kind the envelope registry classifies at read time.
		return p.store.ApplyDiscoveryCoverageSourceTx(ctx, tx, store.DiscoveryCoverage{
			TenantID: e.TenantID, SourceID: pl.ID, SourceKind: pl.Kind,
			SourceName: pl.Name, EventSequence: e.Sequence,
		})
	case EventDiscoveryScheduleUpserted:
		var pl DiscoveryScheduleUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyDiscoveryScheduleUpsertedTx(ctx, tx, store.DiscoverySchedule{
			ID: pl.ID, TenantID: e.TenantID, SourceID: pl.SourceID, Name: pl.Name,
			IntervalSeconds: pl.IntervalSeconds, Enabled: pl.Enabled,
			CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventDiscoveryRunQueued:
		var pl DiscoveryRunQueued
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: pl.ID, TenantID: e.TenantID, SourceID: pl.SourceID, ScheduleID: pl.ScheduleID,
			Status: "queued", DryRun: pl.DryRun, RequestedBy: pl.RequestedBy,
			Execution: pl.Execution, Segment: pl.Segment, RequiredAgentRole: pl.RequiredAgentRole,
			RequiredAgentID: pl.RequiredAgentID, CreatedAt: e.Time,
		})
	case EventDiscoveryRunStarted:
		var pl DiscoveryRunStarted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyDiscoveryRunStartedTx(ctx, tx, e.TenantID, pl.ID, e.Time)
	case EventDiscoveryFindingRecorded:
		var pl DiscoveryFindingRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := p.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
			ID: pl.ID, TenantID: e.TenantID, RunID: pl.RunID, SourceID: pl.SourceID,
			Kind: pl.Kind, Ref: pl.Ref, Provenance: pl.Provenance, Fingerprint: pl.Fingerprint,
			RiskScore: pl.RiskScore, Metadata: pl.Metadata, DiscoveredAt: e.Time,
		}); err != nil {
			return err
		}
		if pl.Kind != "ssh_key" || pl.Fingerprint == "" {
			return nil
		}
		var meta struct {
			Source         string          `json:"source"`
			Location       string          `json:"location"`
			KeyType        string          `json:"key_type"`
			Comment        string          `json:"comment"`
			StandingAccess json.RawMessage `json:"standing_access"`
			Orphaned       json.RawMessage `json:"orphaned"`
		}
		if err := json.Unmarshal(pl.Metadata, &meta); err != nil {
			return fmt.Errorf("projections: decode SSH discovery metadata: %w", err)
		}
		if meta.Location == "" {
			meta.Location = pl.Ref
		}
		return p.store.ApplySSHKeyDiscoveredTx(ctx, tx, store.SSHKey{
			ID: pl.ID, TenantID: e.TenantID, Fingerprint: pl.Fingerprint,
			KeyType: meta.KeyType, Comment: meta.Comment, Source: meta.Source,
			Location: meta.Location, StandingAccess: discoveryMetadataBool(meta.StandingAccess),
			Orphaned:  discoveryMetadataBool(meta.Orphaned),
			CreatedAt: e.Time,
		})
	case EventDiscoveryFindingTriageChanged:
		var pl DiscoveryFindingTriageChanged
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyDiscoveryFindingTriageChangedTx(ctx, tx, store.DiscoveryFindingTriageChange{
			TenantID: e.TenantID, FindingID: pl.ID, Status: pl.Status,
			ManagedIdentityID: pl.ManagedIdentityID, Actor: pl.Actor, Reason: pl.Reason,
			ChangedAt: e.Time, MetadataPatch: pl.MetadataPatch,
		})
	case EventDiscoveryRunCompleted:
		var pl DiscoveryRunCompleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		completedAt := e.Time
		if err := p.store.ApplyDiscoveryRunCompletedTx(ctx, tx, store.DiscoveryRun{
			ID: pl.ID, TenantID: e.TenantID, Status: pl.Status, Targets: pl.Targets,
			Discovered: pl.Discovered, Failed: pl.Failed, Rejected: pl.Rejected,
			Blocked: pl.Blocked, Error: pl.Error, ExecutedByAgentID: pl.ExecutedByAgentID,
			CompletedAt: &completedAt,
		}); err != nil {
			return err
		}
		if pl.Segment != "" {
			if err := p.store.ApplyDiscoverySegmentSweepTx(ctx, tx, e.TenantID, pl.Segment,
				pl.ExecutedByAgentID, pl.Discovered, completedAt); err != nil {
				return err
			}
		}
		// Fold the completed run into its source's coverage rollup in the
		// same transaction; the run row just applied supplies the source
		// identity (AN-2, idempotent by event sequence).
		return p.store.ApplyDiscoveryCoverageRunTx(ctx, tx, e.TenantID, pl.ID, pl.Status, completedAt, e.Sequence)
	case EventADCSInventoryObserved:
		var pl adcsdiscovery.InventoryObserved
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.RunID == "" || pl.SourceID == "" || strings.TrimSpace(pl.Domain) == "" ||
			pl.AgentID == "" || strings.TrimSpace(pl.AgentName) == "" {
			return errors.New("projections: AD CS inventory observation is missing run/source/domain/agent authority")
		}
		if err := adcsdiscovery.ValidateInventoryReport(adcsdiscovery.InventoryIntent{
			ID: pl.RunID, SourceID: pl.SourceID, JobKind: adcsdiscovery.JobKind,
			Execution:         adcsdiscovery.ExecutionRelay,
			RequiredAgentRole: adcsdiscovery.RequiredRoleNetwork,
		}, adcsdiscovery.InventoryReport{
			Status: "succeeded", DirectoryVerified: pl.DirectoryVerified,
			Inventory: adcsdiscovery.Inventory{Templates: pl.Templates}, Findings: pl.Findings,
		}); err != nil {
			return fmt.Errorf("projections: validate AD CS inventory observation: %w", err)
		}
		byTemplate := make(map[string][]adcsdiscovery.Finding, len(pl.Templates))
		for _, finding := range pl.Findings {
			byTemplate[finding.Template] = append(byTemplate[finding.Template], finding)
		}
		rows := make([]store.ADCSTemplatePosture, 0, len(pl.Templates))
		for _, template := range pl.Templates {
			findings := byTemplate[template.Name]
			encodedFindings, err := json.Marshal(findings)
			if err != nil {
				return err
			}
			if findings == nil {
				encodedFindings = []byte("[]")
			}
			observedTemplate, err := json.Marshal(template)
			if err != nil {
				return err
			}
			rows = append(rows, store.ADCSTemplatePosture{
				TenantID: e.TenantID, Domain: pl.Domain, Template: template.Name,
				DisplayName: template.DisplayName, SchemaVersion: template.SchemaVersion,
				PublishedBy: template.PublishedBy, WorstSeverity: projectionADCSWorstSeverity(findings),
				FindingCount: len(findings), Findings: encodedFindings, ObservedTemplate: observedTemplate,
			})
		}
		return p.store.ApplyADCSTemplatePostureObservedTx(ctx, tx, e.TenantID, pl.Domain, pl.AgentName, rows, e.Time)
	case EventRevocationProbeQueued:
		var pl RevocationProbeQueued
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := revocationhealth.ValidateIntent(pl); err != nil {
			return fmt.Errorf("projections: validate revocation probe command: %w", err)
		}
		return nil
	case EventRevocationHealthObserved:
		var pl RevocationHealthObserved
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := revocationhealth.ValidateObserved(pl); err != nil {
			return fmt.Errorf("projections: validate revocation health observation: %w", err)
		}
		byTarget := make(map[string]revocationhealth.Target, len(pl.Targets))
		for _, target := range pl.Targets {
			byTarget[target.Key] = target
		}
		rows := make([]store.RevocationEndpointHealth, 0, len(pl.Findings))
		for _, finding := range pl.Findings {
			target := byTarget[finding.TargetKey]
			rows = append(rows, store.RevocationEndpointHealth{
				TenantID: e.TenantID, TargetKey: target.Key, Protocol: target.Protocol,
				Endpoint: target.Endpoint, IssuerSubject: target.IssuerSubject,
				IssuerFingerprint: target.IssuerFingerprint, CertificateID: target.CertificateID,
				CertificateSubject: target.CertificateSubject, CertificateFingerprint: target.CertificateFingerprint,
				CertificateSerial: target.CertificateSerial, Status: string(finding.Status),
				DetailCode: finding.DetailCode, LatencyMS: finding.LatencyMS,
				ThisUpdate: finding.ThisUpdate, NextUpdate: finding.NextUpdate,
				SignatureVerified: finding.SignatureVerified, RevokedCount: finding.RevokedCount,
				ResponseStatus: finding.ResponseStatus, ResponderSubject: finding.ResponderSubject,
				ProbeID: pl.ProbeID, Bucket: pl.Bucket, BatchIndex: pl.BatchIndex,
				BatchCount: pl.BatchCount, ObservedByAgentID: pl.AgentID,
				ObservedByAgentName: pl.AgentName, EvidenceDigest: pl.EvidenceDigest, ObservedAt: e.Time,
			})
		}
		return p.store.ApplyRevocationEndpointHealthObservedTx(ctx, tx, rows)
	case EventMigrationRunRecorded:
		var pl MigrationRunRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := migration.ValidateExecutableRun(pl.Run); err != nil {
			return fmt.Errorf("projections: validate migration run: %w", err)
		}
		if err := migration.ValidateActions(pl.Run, pl.Actions); err != nil {
			return fmt.Errorf("projections: validate migration actions: %w", err)
		}
		return p.store.ApplyMigrationRunRecordedTx(ctx, tx, e.TenantID, pl.Run, e.Sequence, e.Time)
	case EventACMEDNS01ProviderConfigUpserted:
		var pl ACMEDNS01ProviderConfigUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Name == "" || pl.Provider == "" {
			return fmt.Errorf("projections: %s requires id, name, and provider", e.Type)
		}
		return p.store.ApplyACMEDNS01ProviderConfigUpsertedTx(ctx, tx, store.ACMEDNS01ProviderConfig{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Name, Provider: pl.Provider,
			Zone: pl.Zone, ChallengeDomain: pl.ChallengeDomain, DelegationTarget: pl.DelegationTarget,
			CredentialRefs: pl.CredentialRefs, Config: pl.Config, CAAIssuerDomain: pl.CAAIssuerDomain,
			AllowedMethods: pl.AllowedMethods, AllowWildcards: pl.AllowWildcards,
			AllowUpstreamDV: pl.AllowUpstreamDV,
			CreatedAt:       e.Time, UpdatedAt: e.Time,
		})
	case EventACMEDNS01ProviderConfigDeleted:
		var pl ACMEDNS01ProviderConfigDeleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		return p.store.ApplyACMEDNS01ProviderConfigDeletedTx(ctx, tx, e.TenantID, pl.ID)
	case EventEndpointVerified:
		var pl EndpointVerificationObserved
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.EndpointID == "" || pl.Address == "" || pl.Vantage == "" {
			return fmt.Errorf("projections: %s requires endpoint_id, address and vantage", e.Type)
		}
		// The honesty rule, restated where a malformed producer cannot bypass
		// it: a probe that never reached the listener cannot have compared
		// anything, so a payload claiming otherwise is refused rather than
		// stored. The database CHECK constraint says the same thing; this says
		// it earlier, with the event type in the error.
		if !pl.Reached && (pl.Mismatch != "" || pl.CheckedSANs || pl.CheckedChain || pl.ObservedFingerprint != "") {
			return fmt.Errorf("projections: %s reports an unreached probe that claims an observation", e.Type)
		}
		observedAt := pl.ObservedAt
		if observedAt.IsZero() {
			observedAt = e.Time
		}
		return p.store.ApplyEndpointVerificationTx(ctx, tx, store.EndpointVerification{
			TenantID: e.TenantID, EndpointID: pl.EndpointID, Address: pl.Address,
			Vantage: pl.Vantage, Reached: pl.Reached, Mismatch: pl.Mismatch,
			ExpectedFingerprint: pl.ExpectedFingerprint, ObservedFingerprint: pl.ObservedFingerprint,
			CheckedSANs: pl.CheckedSANs, CheckedChain: pl.CheckedChain,
			NotBefore: pl.NotBefore, NotAfter: pl.NotAfter,
			Detail: pl.Detail, EvidenceDigest: pl.EvidenceDigest,
			AgentCommonName: pl.AgentCommonName,
			LastCheckedAt:   observedAt,
			EventSequence:   e.Sequence,
		})
	case EventACMEUpstreamAuthorizationObserved:
		var pl ACMEUpstreamAuthorizationObserved
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.Identifier == "" || pl.Issuer == "" {
			return fmt.Errorf("projections: %s requires identifier and issuer", e.Type)
		}
		// A reuse and a validation update different columns on purpose: the
		// gap between "last issued" and "last actually validated" is the number
		// an operator needs, and folding them into one timestamp erases it.
		return p.store.ApplyACMEUpstreamAuthorizationObservedTx(ctx, tx, store.ACMEUpstreamAuthorization{
			TenantID: e.TenantID, Identifier: pl.Identifier, Issuer: pl.Issuer,
			ChallengeType: pl.ChallengeType, Reused: pl.Reused,
			ExpiresAt: pl.ExpiresAt, EventSequence: e.Sequence, ObservedAt: e.Time,
		})
	case EventACMEDNS01Preflighted:
		var pl ACMEDNS01Preflighted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.Domain == "" || pl.RecordName == "" {
			return fmt.Errorf("projections: %s requires domain and record_name", e.Type)
		}
		return nil
	case EventACMEDNS01RecordPresented, EventACMEDNS01RecordCleaned:
		var pl ACMEDNS01RecordChanged
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ConfigID == "" || pl.Provider == "" || pl.Domain == "" || pl.RecordName == "" || pl.OutboxID == 0 {
			return fmt.Errorf("projections: %s requires config_id, provider, domain, record_name, and outbox_id", e.Type)
		}
		return nil
	case EventMDMSCEPPolicyUpserted:
		var pl MDMSCEPPolicyUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Name == "" || pl.Provider == "" || pl.SCEPProfile == "" || pl.SCEPEndpoint == "" {
			return fmt.Errorf("projections: %s requires id, name, provider, scep_profile, and scep_endpoint", e.Type)
		}
		return p.store.ApplyMDMSCEPPolicyUpsertedTx(ctx, tx, store.MDMSCEPPolicy{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Name, Provider: pl.Provider,
			SCEPProfile: pl.SCEPProfile, SCEPEndpoint: pl.SCEPEndpoint, ExpectedAudience: pl.ExpectedAudience,
			ChallengeMode: pl.ChallengeMode, TrustAnchorRefs: pl.TrustAnchorRefs,
			ProfileGuidance: pl.ProfileGuidance, Enabled: pl.Enabled, RotationVersion: pl.RotationVersion,
			CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventMDMSCEPPolicyDeleted:
		var pl MDMSCEPPolicyDeleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		return p.store.ApplyMDMSCEPPolicyDeletedTx(ctx, tx, e.TenantID, pl.ID)
	case EventMDMSCEPChallengeRotated:
		var pl MDMSCEPChallengeRotated
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.RotationVersion <= 0 {
			return fmt.Errorf("projections: %s requires id and positive rotation_version", e.Type)
		}
		return p.store.ApplyMDMSCEPChallengeRotatedTx(ctx, tx, e.TenantID, pl.ID, pl.RotationVersion, e.Time)
	case EventWorkloadAttesterTrustSourceUpserted:
		var pl WorkloadAttesterTrustSourceUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Name == "" || pl.Method == "" {
			return fmt.Errorf("projections: %s requires id, name, and method", e.Type)
		}
		return p.store.ApplyWorkloadAttesterTrustSourceUpsertedTx(ctx, tx, store.WorkloadAttesterTrustSource{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Name, Method: pl.Method,
			Issuer: pl.Issuer, Audience: pl.Audience, JWKS: pl.JWKS,
			RootCertsPEM: pl.RootCertsPEM, ExpectedNonceBase64: pl.ExpectedNonceBase64,
			Enabled: pl.Enabled, RotationVersion: pl.RotationVersion, CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventWorkloadAttesterTrustSourceRotated:
		var pl WorkloadAttesterTrustSourceRotated
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.RotationVersion <= 0 {
			return fmt.Errorf("projections: %s requires id and positive rotation_version", e.Type)
		}
		return p.store.ApplyWorkloadAttesterTrustSourceRotatedTx(ctx, tx, store.WorkloadAttesterTrustSource{
			ID: pl.ID, TenantID: e.TenantID, Issuer: pl.Issuer, Audience: pl.Audience,
			JWKS: pl.JWKS, RootCertsPEM: pl.RootCertsPEM, ExpectedNonceBase64: pl.ExpectedNonceBase64,
			RotationVersion: pl.RotationVersion,
		}, e.Time)
	case EventWorkloadAttesterTrustSourceRevoked:
		var pl WorkloadAttesterTrustSourceRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		return p.store.ApplyWorkloadAttesterTrustSourceRevokedTx(ctx, tx, e.TenantID, pl.ID, pl.Reason, e.Time)
	case EventWorkloadAttesterTrustSourceDeleted:
		var pl WorkloadAttesterTrustSourceDeleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		return p.store.ApplyWorkloadAttesterTrustSourceDeletedTx(ctx, tx, e.TenantID, pl.ID)
	case EventComplianceReportScheduleUpserted:
		var pl ComplianceReportScheduleUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Framework == "" || pl.Name == "" || pl.ReportType == "" || pl.IntervalSeconds <= 0 {
			return fmt.Errorf("projections: %s requires id, framework, name, report_type, and positive interval_seconds", e.Type)
		}
		delivery := pl.Delivery
		if delivery == "" {
			delivery = "audit_export"
		}
		return p.store.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, store.ComplianceReportSchedule{
			ID: pl.ID, TenantID: e.TenantID, Framework: pl.Framework, Name: pl.Name,
			ReportType: pl.ReportType, IntervalSeconds: pl.IntervalSeconds, Enabled: pl.Enabled,
			Delivery: delivery, RecipientRef: pl.RecipientRef,
			NextRunAt: e.Time.Add(time.Duration(pl.IntervalSeconds) * time.Second),
			CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventSecretRotationScheduleUpserted:
		var pl SecretRotationScheduleUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Name == "" || pl.Provider == "" || pl.Key == "" || pl.OldRef == "" || pl.IntervalSeconds <= 0 {
			return fmt.Errorf("projections: %s requires id, name, provider, key, old_ref, and positive interval_seconds", e.Type)
		}
		nextRunAt := pl.NextRunAt
		if nextRunAt.IsZero() {
			nextRunAt = e.Time.Add(time.Duration(pl.IntervalSeconds) * time.Second)
		}
		return p.store.ApplySecretRotationScheduleUpsertedTx(ctx, tx, store.SecretRotationSchedule{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Name, Provider: pl.Provider,
			Key: pl.Key, OldRef: pl.OldRef, IntervalSeconds: pl.IntervalSeconds,
			ConfigEventSequence: e.Sequence, Enabled: pl.Enabled, NextRunAt: nextRunAt,
			CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventSecretRotationScheduleRan:
		var pl SecretRotationScheduleRan
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ScheduleID == "" || pl.RunID == "" || pl.Status == "" {
			return fmt.Errorf("projections: %s requires schedule_id, run_id, and status", e.Type)
		}
		switch schemaVersionOf(e) {
		case rotationcommand.LegacyBoundEventSchemaVersion:
			if pl.Provider == "" || pl.Key == "" || pl.OldRef == "" || pl.IntervalSeconds <= 0 ||
				pl.ConfigEventSequence == 0 || pl.RequestBinding == "" ||
				e.Actor == nil || e.Actor.Subject != "secret-rotation-schedule:"+pl.ScheduleID ||
				!rotationcommand.LegacyMatches(e.TenantID, pl.ScheduleID, pl.RunID,
					pl.DueAt, pl.CommandKey, e.ID) {
				return fmt.Errorf("projections: %s v%d requires one exact deterministic due-edge tuple", e.Type, schemaVersionOf(e))
			}
		case SecretRotationScheduleRanEventSchemaVersion:
			if pl.Provider == "" || pl.Key == "" || pl.OldRef == "" || pl.IntervalSeconds <= 0 ||
				pl.ConfigEventSequence == 0 || pl.RequestBinding == "" ||
				pl.TenantRegistrationEventID == "" || pl.TenantRegistrationEventSequence == 0 ||
				e.Actor == nil || e.Actor.Subject != "secret-rotation-schedule:"+pl.ScheduleID ||
				!rotationcommand.Matches(e.TenantID, pl.TenantRegistrationEventSequence,
					pl.ScheduleID, pl.RunID, pl.DueAt, pl.CommandKey, e.ID) {
				return fmt.Errorf("projections: %s v%d requires one exact deterministic due-edge tuple", e.Type, schemaVersionOf(e))
			}
		}
		return p.store.ApplySecretRotationScheduleRunTx(ctx, tx, store.SecretRotationScheduleRun{
			TenantID: e.TenantID, IdentityVersion: schemaVersionOf(e),
			TenantRegistrationEventID:       pl.TenantRegistrationEventID,
			TenantRegistrationEventSequence: pl.TenantRegistrationEventSequence,
			ScheduleID:                      pl.ScheduleID, RunID: pl.RunID,
			SchemaVersion: schemaVersionOf(e), DueAt: pl.DueAt, Provider: pl.Provider,
			Key: pl.Key, OldRef: pl.OldRef, IntervalSeconds: pl.IntervalSeconds,
			ConfigEventSequence: pl.ConfigEventSequence, CommandKey: pl.CommandKey,
			RequestBinding: pl.RequestBinding, Status: pl.Status,
			NewRef: pl.NewRef, Error: pl.Error, RanAt: e.Time,
			EventID: e.ID, EventType: e.Type, EventSequence: e.Sequence,
			EventDigest: cryptoboundary.SHA256Hex(e.Data),
		})
	case EventNotificationTestQueued:
		var pl NotificationTestQueued
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.RequestBinding == "" || pl.ChannelID == "" ||
			pl.Destination == "" || pl.EffectLane == "" || len(pl.Payload) == 0 {
			return fmt.Errorf("projections: %s requires id, request binding, channel, destination, effect lane, and payload", e.Type)
		}
		return p.store.ApplyNotificationTestQueuedTx(ctx, tx, store.NotificationTestOperation{
			TenantID: e.TenantID, ID: pl.ID, RequestBinding: pl.RequestBinding,
			ChannelID: pl.ChannelID, Destination: pl.Destination,
			CredentialConfigured: pl.CredentialConfigured, QueuedAt: e.Time,
		}, pl.EffectLane, pl.Payload)
	case EventNotificationDeliveryRecorded:
		var pl NotificationDeliveryRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		deliveredAt := pl.DeliveredAt
		if deliveredAt.IsZero() {
			deliveredAt = e.Time
		}
		return p.store.ApplyNotificationDeliveryRecordedTx(ctx, tx, store.NotificationDeliveryReceipt{
			TenantID: e.TenantID, ID: pl.ID, Destination: pl.Destination,
			NotificationKeyDigest: pl.NotificationKeyDigest, PayloadDigest: pl.PayloadDigest,
			Channel: pl.Channel, OutboxID: pl.OutboxID, Attempts: pl.Attempts,
			DeliveredAt: deliveredAt,
		})
	case EventNotificationThresholdDelivered:
		var pl NotificationThresholdDelivered
		if err := decode(e, &pl); err != nil {
			return err
		}
		sentAt := pl.SentAt
		if sentAt.IsZero() {
			sentAt = e.Time
		}
		return p.store.ApplyNotificationThresholdDeliveredTx(ctx, tx, store.NotificationThresholdDelivery{
			TenantID: e.TenantID, Subject: pl.Subject, ThresholdDays: pl.ThresholdDays,
			Channel: pl.Channel, SentAt: sentAt,
		})
	case EventNotificationChannelUpserted:
		var pl NotificationChannelUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyNotificationChannelUpsertedTx(ctx, tx, store.NotificationChannel{
			TenantID:      e.TenantID,
			ID:            pl.ID,
			ChannelType:   pl.ChannelType,
			Label:         pl.Label,
			EndpointURL:   pl.EndpointURL,
			CredentialRef: pl.CredentialRef,
			Enabled:       pl.Enabled,
			CreatedAt:     e.Time,
			UpdatedAt:     e.Time,
		})
	case EventNotificationChannelDeleted:
		var pl NotificationChannelDeleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.DeleteNotificationChannelTx(ctx, tx, e.TenantID, pl.ID)
	case EventNotificationRoutingPolicyUpserted:
		var pl NotificationRoutingPolicyUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyNotificationRoutingPolicyUpsertedTx(ctx, tx, store.NotificationRoutingPolicy{
			ID:                 pl.ID,
			TenantID:           e.TenantID,
			Name:               pl.Name,
			ChannelsBySeverity: pl.ChannelsBySeverity,
			DefaultChannels:    pl.DefaultChannels,
			OwnerRef:           pl.OwnerRef,
			OwnerEmail:         pl.OwnerEmail,
			DigestInterval:     pl.DigestInterval,
			DigestTimezone:     pl.DigestTimezone,
			CreatedAt:          e.Time,
			UpdatedAt:          e.Time,
		})
	case EventNotificationRoutingPolicyDeleted:
		var pl NotificationRoutingPolicyDeleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.DeleteNotificationRoutingPolicyTx(ctx, tx, e.TenantID, pl.ID)
	case EventNotificationRead:
		var pl NotificationRead
		if err := decode(e, &pl); err != nil {
			return err
		}
		readAt := pl.ReadAt
		if readAt.IsZero() {
			readAt = e.Time
		}
		return p.store.ApplyNotificationReadTx(ctx, tx, store.NotificationReadReceipt{
			TenantID: e.TenantID, OutboxID: pl.OutboxID, ReadAt: readAt,
		})
	case EventCBOMAssetObserved:
		var pl CBOMAssetObserved
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Kind == "" || pl.Location == "" || pl.Strength == "" {
			return fmt.Errorf("projections: %s requires id, kind, location, and strength", e.Type)
		}
		return p.store.ApplyCryptoAssetObservedTx(ctx, tx, store.CryptoAsset{
			ID: pl.ID, TenantID: e.TenantID, Kind: pl.Kind, Location: pl.Location,
			Algorithm: pl.Algorithm, KeyBits: pl.KeyBits, Protocol: pl.Protocol,
			Cipher: pl.Cipher, Library: pl.Library, Strength: pl.Strength,
			QuantumVulnerable: pl.QuantumVulnerable, OutOfPolicy: pl.OutOfPolicy,
			Reasons: pl.Reasons,
		}, e.Sequence, e.Time)
	case EventLicensedCryptoMigrationStarted:
		var pl LicensedCryptoMigrationStarted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.RunID == "" || len(pl.AssetIDs) == 0 || pl.TargetAlgorithm == "" || pl.Protocol == "" {
			return fmt.Errorf("projections: %s requires run_id, asset_ids, target_algorithm, and protocol", e.Type)
		}
		return nil
	case EventLicensedCryptoMigrationAssetCompleted:
		var pl LicensedCryptoMigrationAssetCompleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.RunID == "" || pl.AssetID == "" || pl.Kind == "" || pl.Location == "" || pl.EffectiveAlgorithm == "" {
			return fmt.Errorf("projections: %s requires run_id, asset_id, kind, location, and effective_algorithm", e.Type)
		}
		reasons := []string{"licensed crypto migration run " + pl.RunID + " re-issued through " + pl.Protocol}
		return p.store.ApplyCryptoAssetMigratedTx(ctx, tx, store.CryptoAsset{
			ID: pl.AssetID, TenantID: e.TenantID, Kind: pl.Kind, Location: pl.Location,
			Algorithm: pl.EffectiveAlgorithm, KeyBits: pl.EffectiveKeyBits, Library: pl.OriginalLibrary,
			Strength: "strong", QuantumVulnerable: false, OutOfPolicy: false, Reasons: reasons,
		}, e.Sequence, e.Time)
	case EventLicensedCryptoMigrationRollbackCompleted:
		var pl LicensedCryptoMigrationRollbackCompleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.RunID == "" || pl.AssetID == "" || pl.Kind == "" || pl.Location == "" || pl.Strength == "" {
			return fmt.Errorf("projections: %s requires run_id, asset_id, kind, location, and strength", e.Type)
		}
		return p.store.ApplyCryptoAssetRolledBackTx(ctx, tx, store.CryptoAsset{
			ID: pl.AssetID, TenantID: e.TenantID, Kind: pl.Kind, Location: pl.Location,
			Algorithm: pl.Algorithm, KeyBits: pl.KeyBits, Protocol: pl.Protocol,
			Cipher: pl.Cipher, Library: pl.Library, Strength: pl.Strength,
			QuantumVulnerable: pl.QuantumVulnerable, OutOfPolicy: pl.OutOfPolicy, Reasons: pl.Reasons,
		}, e.Sequence, e.Time)
	case EventConnectorDeliveryRecorded:
		var pl ConnectorDeliveryRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Status == "" {
			return fmt.Errorf("projections: %s requires id and status", e.Type)
		}
		receipt := store.ConnectorDeliveryReceipt{
			ID: pl.ID, TenantID: e.TenantID, OutboxID: pl.OutboxID, IdentityID: pl.IdentityID,
			Destination: pl.Destination, Connector: pl.Connector, Target: pl.Target,
			Fingerprint: pl.Fingerprint, Status: pl.Status, Attempts: pl.Attempts,
			Reason: pl.Reason, Detail: pl.Detail, RollbackRef: pl.RollbackRef,
			IdempotencyKey: pl.IdempotencyKey, CreatedAt: e.Time, UpdatedAt: e.Time,
		}
		if err := p.store.ApplyConnectorDeliveryRecordedTx(ctx, tx, receipt); err != nil {
			return err
		}
		if pl.RemediationRunID == "" {
			return nil
		}
		if pl.Destination != "connector.right_size" || pl.OutboxID == nil || pl.Reason == "" {
			return fmt.Errorf("projections: %s right-size terminal event is incomplete", e.Type)
		}
		status, phase := "", ""
		switch pl.Status {
		case "delivered":
			status, phase = "succeeded", "right_size_entitlements_mutated"
		case "failed":
			status, phase = "failed", "right_size_connector_failed"
		default:
			return fmt.Errorf("projections: %s right-size terminal status %q is invalid", e.Type, pl.Status)
		}
		return p.store.ApplyConnectorRightSizeTerminalTx(ctx, tx, e.TenantID,
			pl.RemediationRunID, pl.ID, *pl.OutboxID, status, phase, pl.Reason, e.Time)
	case EventDeploymentTargetUpserted:
		var pl DeploymentTargetUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Name == "" || pl.Connector == "" {
			return fmt.Errorf("projections: %s requires id, name, and connector", e.Type)
		}
		return p.store.ApplyDeploymentTargetUpsertedTx(ctx, tx, store.DeploymentTarget{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Name, Type: pl.Connector, Config: pl.Config,
		}, e.ID, e.Time)
	case EventDeploymentTargetDeleted:
		var pl DeploymentTargetDeleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		return p.store.ApplyDeploymentTargetDeletedTx(ctx, tx, e.TenantID, pl.ID)
	case EventIdentityConnectorTargetBound:
		var pl IdentityConnectorTargetBound
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.IdentityID == "" || pl.TargetID == "" || pl.Connector == "" || pl.Target == "" {
			return fmt.Errorf("projections: %s requires identity_id, target_id, connector, and target", e.Type)
		}
		return p.store.BindIdentityDeploymentTargetTx(ctx, tx, e.TenantID, pl.IdentityID, pl.TargetID, pl.Connector, pl.Target, pl.Route)
	case EventLifecycleRotationRecorded:
		var pl LifecycleRotationRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.IdentityID == "" || pl.Status == "" {
			return fmt.Errorf("projections: %s requires id, identity_id, and status", e.Type)
		}
		return p.store.ApplyRotationRunRecordedTx(ctx, tx, store.RotationRun{
			ID: pl.ID, TenantID: e.TenantID, IdentityID: pl.IdentityID, OutboxID: pl.OutboxID,
			Status: pl.Status, Trigger: pl.Trigger, Reason: pl.Reason,
			PredecessorFingerprint: pl.PredecessorFingerprint, SuccessorFingerprint: pl.SuccessorFingerprint,
			RollbackRef: pl.RollbackRef, Error: pl.Error, IdempotencyKey: pl.IdempotencyKey,
			CreatedAt: e.Time, UpdatedAt: e.Time, CompletedAt: pl.CompletedAt,
			FirstEventSequence: e.Sequence, LatestEventSequence: e.Sequence,
		})
	case EventOutboxReconciliationConflictRecorded:
		var pl OutboxReconciliationConflictRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.SourceEventID == "" || pl.SourceEventSequence == 0 || pl.SourceEventType == "" ||
			pl.IdempotencyKey == "" || pl.ExistingOutboxID <= 0 || pl.ExistingDestination == "" ||
			pl.ExistingEffectLane == "" || len(pl.ExistingPayloadSHA256) != 64 ||
			pl.CandidateDestination == "" || pl.CandidateEffectLane == "" ||
			len(pl.CandidatePayloadSHA256) != 64 || pl.Reason == "" || pl.Status != "quarantined" {
			return fmt.Errorf("projections: %s requires complete immutable old/new command evidence", e.Type)
		}
		return p.store.ApplyOutboxReconciliationConflictRecordedTx(ctx, tx, store.OutboxReconciliationConflict{
			ID: e.ID, TenantID: e.TenantID, SourceEventID: pl.SourceEventID,
			SourceEventSequence: pl.SourceEventSequence, SourceEventType: pl.SourceEventType,
			IdempotencyKey: pl.IdempotencyKey, ExistingOutboxID: pl.ExistingOutboxID,
			ExistingDestination: pl.ExistingDestination, ExistingEffectLane: pl.ExistingEffectLane,
			ExistingPayloadSHA256:     pl.ExistingPayloadSHA256,
			ExistingRequiredAgentRole: pl.ExistingRequiredAgentRole,
			ExistingRequiredAgentID:   pl.ExistingRequiredAgentID,
			CandidateDestination:      pl.CandidateDestination, CandidateEffectLane: pl.CandidateEffectLane,
			CandidatePayloadSHA256:     pl.CandidatePayloadSHA256,
			CandidateRequiredAgentRole: pl.CandidateRequiredAgentRole,
			CandidateRequiredAgentID:   pl.CandidateRequiredAgentID,
			Reason:                     pl.Reason, Status: pl.Status, DetectedAt: e.Time,
		})
	case EventIncidentExecutionRecorded:
		var pl IncidentExecutionRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.CompromisedIdentityID == "" || pl.Status == "" {
			return fmt.Errorf("projections: %s requires id, compromised_identity_id, and status", e.Type)
		}
		return p.store.ApplyIncidentExecutionRecordedTx(ctx, tx, store.IncidentExecution{
			ID: pl.ID, TenantID: e.TenantID, CompromisedIdentityID: pl.CompromisedIdentityID,
			ReplacementIdentityID: pl.ReplacementIdentityID, ConnectorDeliveryID: pl.ConnectorDeliveryID,
			Status: pl.Status, Phase: pl.Phase, Reason: pl.Reason, BlastRadius: pl.BlastRadius,
			RevocationStatus: pl.RevocationStatus, EvidenceBundleFormat: pl.EvidenceBundleFormat,
			EvidenceBundle: pl.EvidenceBundle, FailedTargets: pl.FailedTargets, RollbackRefs: pl.RollbackRefs,
			IdempotencyKey: pl.IdempotencyKey, CreatedBy: pl.CreatedBy, CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventIncidentFleetReissuanceRecorded:
		var pl IncidentFleetReissuanceRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.IssuerID == "" || pl.Status == "" {
			return fmt.Errorf("projections: %s requires id, issuer_id, and status", e.Type)
		}
		batches := make([]store.FleetReissuanceBatch, 0, len(pl.Batches))
		for _, b := range pl.Batches {
			batches = append(batches, store.FleetReissuanceBatch{
				Index: b.Index, Status: b.Status, IdentityIDs: b.IdentityIDs,
				ReplacementIdentityIDs: b.ReplacementIdentityIDs, HealthGate: b.HealthGate,
			})
		}
		healthGates := make([]store.FleetReissuanceHealthGate, 0, len(pl.HealthGates))
		for _, g := range pl.HealthGates {
			healthGates = append(healthGates, store.FleetReissuanceHealthGate{Name: g.Name, Status: g.Status})
		}
		return p.store.ApplyIncidentFleetReissuanceRecordedTx(ctx, tx, store.IncidentFleetReissuanceRun{
			ID: pl.ID, TenantID: e.TenantID, IssuerID: pl.IssuerID,
			MigrationRunID: pl.MigrationRunID, ReplacementAuthorityID: pl.ReplacementAuthorityID,
			Mode: pl.Mode, PlanDigest: pl.PlanDigest, ExactTrustStoreIDs: pl.ExactTrustStoreIDs,
			ExactTrustHosts: pl.ExactTrustHosts, CandidateTrustStoreIDs: pl.CandidateTrustStoreIDs,
			CandidateTrustHosts: pl.CandidateTrustHosts,
			Status:              pl.Status, Phase: pl.Phase, Reason: pl.Reason, BatchSize: pl.BatchSize,
			NextBatchIndex: pl.NextBatchIndex, HaltedReason: pl.HaltedReason,
			Connector: pl.Connector, Target: pl.Target, GraphImpact: pl.GraphImpact,
			AffectedIdentityIDs: pl.AffectedIdentityIDs, ReplacementIdentityIDs: pl.ReplacementIdentityIDs,
			RevokedIdentityIDs: pl.RevokedIdentityIDs, ConnectorDeliveryIDs: pl.ConnectorDeliveryIDs,
			Batches: batches, HealthGates: healthGates, FailedTargets: pl.FailedTargets,
			RollbackRefs: pl.RollbackRefs, EvidenceBundleFormat: pl.EvidenceBundleFormat,
			EvidenceBundle: pl.EvidenceBundle, IdempotencyKey: pl.IdempotencyKey,
			CreatedBy: pl.CreatedBy, CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventRemediationPlaybookRunRecorded:
		var pl RemediationPlaybookRunRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.PlaybookID == "" || pl.Status == "" || pl.Action == "" {
			return fmt.Errorf("projections: %s requires id, playbook_id, status, and action", e.Type)
		}
		run := store.RemediationPlaybookRun{
			ID: pl.ID, TenantID: e.TenantID, PlaybookID: pl.PlaybookID,
			TargetIdentityID: pl.TargetIdentityID, InventoryID: pl.InventoryID,
			Status: pl.Status, Phase: pl.Phase, Action: pl.Action, Reason: pl.Reason,
			Connector: pl.Connector, Target: pl.Target, OutboxID: pl.OutboxID,
			ConnectorDeliveryID: pl.ConnectorDeliveryID, ScopeDelta: pl.ScopeDelta,
			EvidenceRefs: pl.EvidenceRefs, RollbackRefs: pl.RollbackRefs,
			IdempotencyKey: pl.IdempotencyKey, RequestBinding: pl.RequestBinding,
			InitialHTTPStatus: pl.InitialHTTPStatus, InitialResponse: pl.InitialResponse,
			TerminalReason: pl.TerminalReason, CreatedBy: pl.CreatedBy,
			CreatedAt: e.Time, UpdatedAt: e.Time,
		}
		if pl.Action != "right_size" || pl.RequestBinding == "" {
			return p.store.ApplyRemediationPlaybookRunRecordedTx(ctx, tx, run)
		}
		if pl.ConnectorDeliveryID == nil || *pl.ConnectorDeliveryID == "" ||
			pl.OutboxIdempotencyKey == "" || pl.InitialHTTPStatus == 0 || len(pl.InitialResponse) == 0 {
			return fmt.Errorf("projections: %s durable right-size operation is incomplete", e.Type)
		}
		var identityID *string
		if pl.TargetIdentityID != "" {
			value := pl.TargetIdentityID
			identityID = &value
		}
		rollbackRef := ""
		if len(pl.RollbackRefs) > 0 {
			rollbackRef = pl.RollbackRefs[0]
		}
		return p.store.ApplyConnectorRightSizeRequestedTx(ctx, tx, run, store.ConnectorDeliveryReceipt{
			ID: *pl.ConnectorDeliveryID, TenantID: e.TenantID, IdentityID: identityID,
			Destination: "connector.right_size", Connector: pl.Connector, Target: pl.Target,
			Status: "queued", Attempts: 0, Reason: "least_privilege_right_size_queued",
			Detail: "usage-backed right-size connector intent queued", RollbackRef: rollbackRef,
			IdempotencyKey: pl.OutboxIdempotencyKey, CreatedAt: e.Time, UpdatedAt: e.Time,
		}, "connector.right_size", pl.OutboxIdempotencyKey, e.Data)
	case EventResponseIntegrationDispatched:
		var pl ResponseIntegrationDispatched
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Title == "" || len(pl.Destinations) == 0 {
			return fmt.Errorf("projections: %s requires id, title, and destinations", e.Type)
		}
		for _, dst := range pl.Destinations {
			if dst.Provider == "" {
				return fmt.Errorf("projections: %s destination requires provider", e.Type)
			}
		}
		return nil
	case EventPrivacySubjectErased:
		var pl PrivacySubjectErased
		if err := decode(e, &pl); err != nil {
			return err
		}
		if err := ValidatePrivacySubjectErasedPayload(e, pl); err != nil {
			return err
		}
		erasure := store.PrivacySubjectErasure{
			TenantID:       e.TenantID,
			SubjectRef:     pl.SubjectRef,
			RequestedByRef: pl.RequestedByRef,
			Reason:         pl.Reason,
			Selectors:      pl.Selectors,
			Counts:         pl.Counts,
			ErasedAt:       e.Time,
		}
		if schemaVersionOf(e) >= PrivacySubjectErasedOperationEventSchemaVersion {
			return p.store.ApplyPrivacySubjectErasureOperationTx(ctx, tx, store.PrivacySubjectErasureOperation{
				PrivacySubjectErasure: erasure,
				OperationID:           pl.OperationID,
				RequestBinding:        pl.RequestBinding,
				EventID:               e.ID,
				EventSequence:         e.Sequence,
			})
		}
		return p.store.ApplyPrivacySubjectErasedTx(ctx, tx, erasure)
	case EventPrivacyRetentionEnforced:
		var pl PrivacyRetentionEnforced
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.RunID == "" {
			return fmt.Errorf("projections: %s requires run_id", e.Type)
		}
		return p.store.ApplyPrivacyRetentionEnforcedTx(ctx, tx, store.PrivacyRetentionRun{
			TenantID:       e.TenantID,
			RunID:          pl.RunID,
			RequestedByRef: pl.RequestedByRef,
			Cutoffs:        pl.Cutoffs,
			Counts:         pl.Counts,
			EnforcedAt:     e.Time,
		})
	case EventPrivacyArchiveErasureAttested:
		var pl PrivacyArchiveErasureAttested
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.AttestationID == "" || pl.SubjectRef == "" || pl.ArtifactType == "" || pl.Action == "" {
			return fmt.Errorf("projections: %s requires attestation_id, subject_ref, artifact_type, and action", e.Type)
		}
		return p.store.ApplyPrivacyArchiveErasureAttestedTx(ctx, tx, store.PrivacyArchiveErasureAttestation{
			TenantID:       e.TenantID,
			AttestationID:  pl.AttestationID,
			SubjectRef:     pl.SubjectRef,
			RequestedByRef: pl.RequestedByRef,
			ArtifactType:   pl.ArtifactType,
			ArtifactURI:    pl.ArtifactURI,
			Action:         pl.Action,
			Reason:         pl.Reason,
			EvidenceRefs:   pl.EvidenceRefs,
			HeldUntil:      pl.HeldUntil,
			AttestedAt:     e.Time,
		})
	case EventTenantMemberUpserted:
		var pl TenantMemberUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.Subject == "" {
			return fmt.Errorf("projections: %s requires subject", e.Type)
		}
		source := pl.Source
		if source == "" {
			source = "manual"
		}
		return p.store.ApplyTenantMemberUpsertedTx(ctx, tx, store.TenantMember{
			TenantID: e.TenantID, Subject: pl.Subject, DisplayName: pl.DisplayName,
			Email: pl.Email, Roles: pl.Roles, Source: source, Status: "active",
			CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventTenantMemberOffboarded:
		var pl TenantMemberOffboarded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.Subject == "" {
			return fmt.Errorf("projections: %s requires subject", e.Type)
		}
		if err := p.store.ApplyTenantMemberOffboardedTx(ctx, tx, store.TenantMember{
			TenantID: e.TenantID, Subject: pl.Subject, Status: "offboarded",
			UpdatedAt: e.Time, OffboardedBy: pl.OffboardedBy, OffboardReason: pl.Reason,
		}); err != nil {
			return err
		}
		return p.store.ApplyAPITokensRevokedForSubjectTx(ctx, tx, e.TenantID, pl.Subject, pl.OffboardedBy, "member offboarded: "+pl.Reason, e.Time)
	case EventAPITokenCreated:
		var pl APITokenCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.TokenHash == "" || pl.Subject == "" {
			return fmt.Errorf("projections: %s requires id, token_hash, and subject", e.Type)
		}
		return p.store.ApplyAPITokenCreatedTx(ctx, tx, store.APITokenRecord{
			ID: pl.ID, TenantID: e.TenantID, TokenHash: pl.TokenHash, Subject: pl.Subject,
			Scopes: pl.Scopes, ExpiresAt: pl.ExpiresAt, CreatedAt: e.Time,
		})
	case EventAPITokenRevoked:
		var pl APITokenRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		return p.store.ApplyAPITokenRevokedTx(ctx, tx, e.TenantID, pl.ID, pl.RevokedBy, pl.Reason, e.Time)
	case EventPAMSessionStarted:
		var pl PAMSessionStarted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.TargetType == "" || pl.TargetID == "" || pl.Status == "" || pl.Subject == "" || pl.ExpiresAt.IsZero() {
			return fmt.Errorf("projections: %s requires id, target, status, subject, and expires_at", e.Type)
		}
		startedAt := pl.StartedAt
		if startedAt.IsZero() {
			startedAt = e.Time
		}
		return p.store.ApplyPAMSessionStartedTx(ctx, tx, store.PAMSession{
			TenantID: e.TenantID, ID: pl.ID, TargetType: pl.TargetType, TargetID: pl.TargetID,
			Role: pl.Role, Status: pl.Status, Subject: pl.Subject, RequestedBy: pl.RequestedBy,
			Reason: pl.Reason, AttestationID: pl.AttestationID, BackendRef: pl.BackendRef,
			SSHKeyID: pl.SSHKeyID, SSHSerial: pl.SSHSerial, IdempotencyKey: pl.IdempotencyKey,
			Audit: pl.Audit, StartedAt: startedAt, ExpiresAt: pl.ExpiresAt,
		})
	case EventPAMSessionExpired:
		var pl PAMSessionExpired
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		endedAt := pl.EndedAt
		if endedAt.IsZero() {
			endedAt = e.Time
		}
		return p.store.ApplyPAMSessionExpiredTx(ctx, tx, e.TenantID, pl.ID, endedAt)
	case EventMachineSessionStarted:
		var pl MachineSessionStarted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Principal == "" || pl.Method == "" || pl.ExpiresAt.IsZero() {
			return fmt.Errorf("projections: %s requires id, principal, method, and expires_at", e.Type)
		}
		issuedAt := pl.IssuedAt
		if issuedAt.IsZero() {
			issuedAt = e.Time
		}
		return p.store.ApplyMachineSessionStartedTx(ctx, tx, store.MachineSession{
			TenantID: e.TenantID, ID: pl.ID, Principal: pl.Principal, Method: pl.Method,
			Scopes: pl.Scopes, Status: store.MachineSessionStatusActive,
			IssuedAt: issuedAt, ExpiresAt: pl.ExpiresAt,
		})
	case EventMachineSessionRevoked:
		var pl MachineSessionRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires id", e.Type)
		}
		revokedAt := pl.RevokedAt
		if revokedAt.IsZero() {
			revokedAt = e.Time
		}
		return p.store.ApplyMachineSessionRevokedTx(ctx, tx, e.TenantID, pl.ID, pl.RevokedBy, revokedAt)
	case EventMachineAuthMethodDisabled, EventMachineAuthMethodEnabled:
		var pl MachineAuthMethodOverride
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.Name == "" {
			return fmt.Errorf("projections: %s requires name", e.Type)
		}
		return p.store.ApplyMachineAuthMethodOverrideTx(ctx, tx, e.TenantID, pl.Name, e.Type == EventMachineAuthMethodDisabled, pl.UpdatedBy, e.Time)
	case EventPQCMigrationCampaignStarted:
		var pl PQCMigrationCampaignStarted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Name == "" || pl.OwnerRef == "" || pl.Deadline.IsZero() ||
			pl.Wave == "" || len(pl.ReadinessCriteria) == 0 || len(pl.Findings) == 0 {
			return fmt.Errorf("projections: %s requires id, name, owner_ref, deadline, wave, readiness_criteria, and findings", e.Type)
		}
		findings := make([]store.PQCMigrationCampaignFinding, 0, len(pl.Findings))
		for _, finding := range pl.Findings {
			if finding.FindingID == "" || finding.FindingDigest == "" ||
				finding.Kind == "" || finding.Location == "" {
				return fmt.Errorf("projections: %s finding requires finding_id, finding_digest, kind, and location", e.Type)
			}
			findings = append(findings, store.PQCMigrationCampaignFinding{
				TenantID: e.TenantID, CampaignID: pl.ID, FindingID: finding.FindingID,
				FindingDigest: finding.FindingDigest, Kind: finding.Kind, Location: finding.Location,
				Algorithm: finding.Algorithm, KeyBits: finding.KeyBits, Protocol: finding.Protocol,
				Cipher: finding.Cipher, Disposition: "pending", CreatedAt: e.Time, UpdatedAt: e.Time,
			})
		}
		return p.store.ApplyPQCMigrationCampaignStartedTx(ctx, tx, store.PQCMigrationCampaign{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Name, OwnerRef: pl.OwnerRef,
			Deadline: pl.Deadline, Wave: pl.Wave, ReadinessCriteria: pl.ReadinessCriteria,
			ReadinessStatus: "pending", Status: "open", FindingCount: len(findings),
			PendingCount: len(findings), CreatedAt: e.Time, UpdatedAt: e.Time,
		}, findings)
	case EventPQCMigrationCampaignUpdated:
		var pl PQCMigrationCampaignUpdated
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CampaignID == "" || pl.OwnerRef == "" || pl.Deadline.IsZero() ||
			pl.Wave == "" || len(pl.ReadinessCriteria) == 0 || pl.ReadinessStatus == "" {
			return fmt.Errorf("projections: %s requires campaign_id, owner_ref, deadline, wave, readiness_criteria, and readiness_status", e.Type)
		}
		updatedAt := pl.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = e.Time
		}
		return p.store.ApplyPQCMigrationCampaignUpdatedTx(ctx, tx, e.TenantID, store.PQCMigrationCampaignUpdate{
			CampaignID: pl.CampaignID, OwnerRef: pl.OwnerRef, Deadline: pl.Deadline,
			Wave: pl.Wave, ReadinessCriteria: pl.ReadinessCriteria,
			ReadinessStatus: pl.ReadinessStatus, ReadinessEvidenceRefs: pl.ReadinessEvidenceRefs,
			UpdatedAt: updatedAt,
		})
	case EventPQCMigrationCampaignFindingDispositioned:
		var pl PQCMigrationCampaignFindingDispositioned
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CampaignID == "" || pl.FindingID == "" || pl.Disposition == "" ||
			pl.RemediationMethod == "" || pl.Reason == "" || len(pl.EvidenceDigests) == 0 {
			return fmt.Errorf("projections: %s requires campaign_id, finding_id, disposition, remediation_method, reason, and evidence_digests", e.Type)
		}
		dispositionedAt := pl.DispositionedAt
		if dispositionedAt.IsZero() {
			dispositionedAt = e.Time
		}
		return p.store.ApplyPQCMigrationFindingDispositionedTx(ctx, tx, e.TenantID, store.PQCMigrationFindingDisposition{
			CampaignID: pl.CampaignID, FindingID: pl.FindingID, Disposition: pl.Disposition,
			RemediationMethod: pl.RemediationMethod, Reason: pl.Reason,
			EvidenceRefs: pl.EvidenceRefs, EvidenceDigests: pl.EvidenceDigests,
			DispositionedAt: dispositionedAt,
		})
	case EventPQCMigrationCampaignClosed:
		var pl PQCMigrationCampaignClosed
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CampaignID == "" || pl.SignedJWS == "" || len(pl.PublicJWKS) == 0 || pl.ClosedBy == "" {
			return fmt.Errorf("projections: %s requires campaign_id, signed_jws, public_jwks, and closed_by", e.Type)
		}
		closedAt := pl.ClosedAt
		if closedAt.IsZero() {
			closedAt = e.Time
		}
		return p.store.ApplyPQCMigrationCampaignClosedTx(ctx, tx, e.TenantID, store.PQCMigrationCampaignClosure{
			CampaignID: pl.CampaignID, SignedJWS: pl.SignedJWS, PublicJWKS: pl.PublicJWKS,
			ClosedBy: pl.ClosedBy, ClosedAt: closedAt,
		})
	case EventTenantKeyDomainMigrationStarted,
		EventTenantKeyDomainMigrationProgressed,
		EventTenantKeyDomainMigrationCompleted,
		EventTenantKeyDomainMigrationFailed,
		EventTenantKeyDomainSealRequested,
		EventTenantKeyDomainSealFailed,
		EventTenantKeyDomainSealed,
		EventTenantKeyDomainUnsealRequested,
		EventTenantKeyDomainUnsealed:
		var pl TenantKeyDomainSnapshot
		if err := decode(e, &pl); err != nil {
			return err
		}
		if e.ID == "" || e.Time.IsZero() || e.Sequence == 0 {
			return fmt.Errorf("projections: %s requires immutable event id, time, and positive stream-sequence evidence", e.Type)
		}
		if err := validateTenantKeyDomainSnapshot(e.Type, pl); err != nil {
			return err
		}
		if err := p.validateTenantKeyDomainExposureTransitionTx(ctx, tx, e, pl); err != nil {
			return err
		}
		createdAt := pl.CreatedAt
		if createdAt.IsZero() {
			createdAt = e.Time
		}
		updatedAt := pl.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = e.Time
		}
		if e.Type == EventTenantKeyDomainMigrationStarted && pl.MigrationStartedAt == nil {
			at := e.Time
			pl.MigrationStartedAt = &at
		}
		if e.Type == EventTenantKeyDomainMigrationCompleted && pl.MigrationCompletedAt == nil {
			at := e.Time
			pl.MigrationCompletedAt = &at
		}
		if e.Type == EventTenantKeyDomainSealed && pl.SealedAt == nil {
			at := e.Time
			pl.SealedAt = &at
		}
		if e.Type == EventTenantKeyDomainUnsealed && pl.UnsealedAt == nil {
			at := e.Time
			pl.UnsealedAt = &at
		}
		actor := ""
		if e.Actor != nil {
			actor = e.Actor.Subject
		}
		if err := p.store.ApplyTenantKeyDomainSnapshotTx(ctx, tx, store.TenantKeyDomain{
			TenantID: e.TenantID, DomainID: pl.DomainID, Generation: pl.Generation,
			ProtectionMode: pl.ProtectionMode, State: pl.State,
			WrapperKind: pl.WrapperKind, WrapperID: pl.WrapperID,
			WrappedDomainKEK: pl.WrappedDomainKEK, OperationID: pl.OperationID,
			OperationKind: pl.OperationKind, OperationStatus: pl.OperationStatus,
			MigrationStage: pl.MigrationStage, ProgressCompleted: pl.ProgressCompleted,
			ProgressTotal: pl.ProgressTotal, ProgressCursor: pl.ProgressCursor,
			Retryable: pl.Retryable, LastErrorCode: pl.LastErrorCode,
			LastError: pl.LastError, LegacyHistoryExposure: pl.LegacyHistoryExposure,
			MigrationStartedAt:   pl.MigrationStartedAt,
			MigrationCompletedAt: pl.MigrationCompletedAt, SealedAt: pl.SealedAt,
			UnsealedAt: pl.UnsealedAt, LastTransitionEventID: e.ID,
			LastTransitionType: e.Type, LastTransitionActor: actor,
			LastTransitionAt:           e.Time,
			LastTransitionEvidenceRefs: pl.TransitionEvidenceRefs,
			LastTransitionSequence:     e.Sequence, CreatedAt: createdAt, UpdatedAt: updatedAt,
		}); err != nil {
			return err
		}
		if e.Type == EventTenantKeyDomainSealRequested {
			return p.store.EnsureTenantKeyDomainSealOutboxTx(
				ctx, tx, e.TenantID, *pl.OperationID,
				pl.SealIdempotencyKey, pl.SealRequestBinding,
			)
		}
		return nil
	case EventNHIAccessReviewCampaignStarted:
		var pl NHIAccessReviewCampaignStarted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Name == "" || pl.ReviewerSubject == "" || pl.RequestedBy == "" || len(pl.Items) == 0 {
			return fmt.Errorf("projections: %s requires id, name, reviewer_subject, requested_by, and items", e.Type)
		}
		scope := pl.Scope
		if scope == "" {
			scope = "all_nhi"
		}
		items := make([]store.NHIReviewItem, 0, len(pl.Items))
		for _, item := range pl.Items {
			if item.ItemID == "" || item.NHIID == "" || item.NHIKind == "" || item.DisplayName == "" || item.Resource == "" || item.Entitlement == "" {
				return fmt.Errorf("projections: %s item requires item_id, nhi_id, nhi_kind, display_name, resource, and entitlement", e.Type)
			}
			risk := item.Risk
			if risk == "" {
				risk = "medium"
			}
			items = append(items, store.NHIReviewItem{
				TenantID: e.TenantID, CampaignID: pl.ID, ItemID: item.ItemID,
				NHIID: item.NHIID, NHIKind: item.NHIKind, DisplayName: item.DisplayName,
				OwnerRef: item.OwnerRef, Resource: item.Resource, Entitlement: item.Entitlement,
				Risk: risk, EvidenceRefs: item.EvidenceRefs, Status: "pending",
				CreatedAt: e.Time, UpdatedAt: e.Time,
			})
		}
		return p.store.ApplyNHIReviewCampaignStartedTx(ctx, tx, store.NHIReviewCampaign{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Name, Scope: scope,
			ReviewerSubject: pl.ReviewerSubject, RequestedBy: pl.RequestedBy,
			Status: "open", DueAt: pl.DueAt, ItemCount: len(items), PendingCount: len(items),
			CreatedAt: e.Time, UpdatedAt: e.Time,
		}, items)
	case EventNHIAccessReviewItemDecided:
		var pl NHIAccessReviewItemDecided
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.CampaignID == "" || pl.ItemID == "" || pl.Decision == "" || pl.ReviewerSubject == "" {
			return fmt.Errorf("projections: %s requires campaign_id, item_id, decision, and reviewer_subject", e.Type)
		}
		decidedAt := pl.DecidedAt
		if decidedAt.IsZero() {
			decidedAt = e.Time
		}
		return p.store.ApplyNHIReviewItemDecidedTx(ctx, tx, e.TenantID, store.NHIReviewDecision{
			CampaignID: pl.CampaignID, ItemID: pl.ItemID, Decision: pl.Decision,
			ReviewerSubject: pl.ReviewerSubject, Reason: pl.Reason,
			DecisionEvidenceRefs: pl.DecisionEvidenceRefs, DecidedAt: decidedAt,
		})
	case EventAccessChangeRequestCreated:
		var pl AccessChangeRequestCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.RequestedAction == "" || pl.RequesterSubject == "" || pl.NHIID == "" ||
			pl.NHIKind == "" || pl.DisplayName == "" || pl.Resource == "" || pl.Entitlement == "" ||
			pl.ChangeRef == "" || pl.Reason == "" || pl.RequiredApprovals < 1 {
			return fmt.Errorf("projections: %s requires id, action, requester, NHI, resource, entitlement, change_ref, reason, and required_approvals", e.Type)
		}
		changeSystem := pl.ChangeSystem
		if changeSystem == "" {
			changeSystem = "external"
		}
		risk := pl.Risk
		if risk == "" {
			risk = "medium"
		}
		return p.store.ApplyAccessChangeRequestCreatedTx(ctx, tx, store.AccessChangeRequest{
			ID: pl.ID, TenantID: e.TenantID, RequestedAction: pl.RequestedAction,
			RequesterSubject: pl.RequesterSubject, NHIID: pl.NHIID, NHIKind: pl.NHIKind,
			DisplayName: pl.DisplayName, OwnerRef: pl.OwnerRef, Resource: pl.Resource,
			Entitlement: pl.Entitlement, ChangeRef: pl.ChangeRef, ChangeSystem: changeSystem,
			ChangeURL: pl.ChangeURL, Risk: risk, Reason: pl.Reason, EvidenceRefs: pl.EvidenceRefs,
			Status: "pending", RequiredApprovals: pl.RequiredApprovals, CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventAccessChangeRequestDecided:
		var pl AccessChangeRequestDecided
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.RequestID == "" || pl.Decision == "" || pl.ApproverSubject == "" {
			return fmt.Errorf("projections: %s requires request_id, decision, and approver_subject", e.Type)
		}
		decidedAt := pl.DecidedAt
		if decidedAt.IsZero() {
			decidedAt = e.Time
		}
		return p.store.ApplyAccessChangeRequestDecidedTx(ctx, tx, e.TenantID, store.AccessChangeDecision{
			RequestID: pl.RequestID, Decision: pl.Decision, ApproverSubject: pl.ApproverSubject,
			Reason: pl.Reason, DecisionEvidenceRefs: pl.DecisionEvidenceRefs, DecidedAt: decidedAt,
		})
	default:
		// An identity lifecycle transition (identity.issued, …) updates the
		// identity's status AND is recorded in the identity_transitions read model
		// so History/State are a bounded, tenant-scoped read rather than a full
		// cross-tenant log replay (SPINE-001). Both writes share this transaction,
		// so the projection of one transition is atomic.
		if isLifecycleEvent(e.Type) {
			var pl identityTransition
			if err := decode(e, &pl); err != nil {
				return err
			}
			if err := validateLifecycleApprovalShape(e, pl); err != nil {
				return err
			}
			if pl.Approval != nil {
				request, err := p.store.GetOperationApprovalForUpdateTx(ctx, tx, e.TenantID, pl.Approval.RequestID)
				if err != nil {
					return err
				}
				identity, version, err := p.store.IdentityApprovalTargetTx(ctx, tx, e.TenantID, pl.IdentityID, true)
				if err != nil {
					return err
				}
				if err := validateLifecycleApprovalAuthority(e, pl, request, identity, version); err != nil {
					return err
				}
				if request.Status != store.ApprovalStatusConsumed && pl.Approval.Issuance != nil &&
					pl.Approval.Issuance.ProfileID != "" {
					if err := p.store.ValidateActiveProfileApprovalBindingTx(ctx, tx, e.TenantID, *pl.Approval.Issuance); err != nil {
						return err
					}
				}
				if err := p.store.ConsumeOperationApprovalTx(ctx, tx, e.TenantID, *pl.Approval, e.ID, e.Time); err != nil {
					return err
				}
			}
			if pl.Issuance != nil && pl.Issuance.ProfileID != "" {
				// A v5 non-approval issuance is still pinned to one active profile
				// revision. Rebuild checks the same revision at this exact log
				// position, so warm state and zero-state replay cannot disagree.
				if err := p.store.ValidateActiveProfileApprovalBindingTx(ctx, tx, e.TenantID, *pl.Issuance); err != nil {
					return err
				}
			}
			if schemaVersionOf(e) == LifecycleOwnershipReadinessEventSchemaVersion {
				if pl.OwnershipReadiness == nil || p.ownershipAttestationCadence <= 0 ||
					(pl.To != "deployed") || !pl.OwnershipReadiness.EvaluatedAt.Equal(e.Time) {
					return fmt.Errorf("projections: %s v%d is missing exact ownership-readiness authority", e.Type, schemaVersionOf(e))
				}
				if err := p.store.ValidateOwnershipReadinessEvidenceTx(ctx, tx, e.TenantID,
					*pl.OwnershipReadiness, p.ownershipAttestationCadence); err != nil {
					return fmt.Errorf("projections: %s ownership-readiness authority: %w", e.Type, err)
				}
			} else if pl.OwnershipReadiness != nil {
				return fmt.Errorf("projections: %s ownership-readiness payload/schema mismatch", e.Type)
			}
			if err := p.store.SetIdentityStatusTx(ctx, tx, e.TenantID, pl.IdentityID, pl.To); err != nil {
				return err
			}
			return p.store.AppendIdentityTransitionTx(ctx, tx, e.TenantID, store.IdentityTransition{
				IdentityID: pl.IdentityID, Seq: e.Sequence, FromState: pl.From, ToState: pl.To,
				EventType: e.Type, Reason: pl.Reason, OccurredAt: e.Time,
			})
		}
		return nil
	}
}

func (p *Projector) applyRestoreDrillRecordedTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	if p.restoreDrillVerificationKeys == nil {
		return errors.New("projections: restore-drill verification keys are not configured")
	}
	var payload RestoreDrillRecorded
	if err := json.Unmarshal(e.Data, &payload); err != nil {
		return fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if payload.AttestationID != RestoreDrillAttestationID(e.TenantID, payload.Evidence.DrillID) ||
		!payload.Evidence.Attestation.CompletedAt.Equal(e.Time) {
		return errors.New("projections: restore-drill event identity/time does not match signed evidence")
	}
	if err := backup.VerifyDrillEvidence(payload.Evidence, p.restoreDrillVerificationKeys); err != nil {
		return fmt.Errorf("projections: reject restore-drill evidence: %w", err)
	}
	evidenceJSON, err := json.Marshal(payload.Evidence)
	if err != nil {
		return fmt.Errorf("projections: encode restore-drill evidence: %w", err)
	}
	verifiedAt := e.Time.UTC()
	row := store.Attestation{
		ID: payload.AttestationID, TenantID: e.TenantID,
		Kind: RestoreDrillAttestationKind, Evidence: evidenceJSON,
		VerifiedAt: &verifiedAt, CreatedAt: e.Time.UTC(),
	}
	var destination, alertKey string
	var alertJSON []byte
	if payload.Evidence.AlertReason != "" {
		kind, severity := restoreDrillAlertVocabulary(payload.Evidence.AlertReason)
		alert := restoreDrillAlert{
			Kind: kind, TenantID: e.TenantID,
			OperationID: "restore-drill:" + payload.AttestationID,
			Subject:     "restore drill " + string(payload.Evidence.AlertReason),
			Detail:      payload.Evidence.Attestation.Detail, Severity: severity,
		}
		alertJSON, err = json.Marshal(alert)
		if err != nil {
			return fmt.Errorf("projections: encode restore-drill alert: %w", err)
		}
		destination = "notification.restore_drill"
		alertKey = "restore-drill-alert:" + payload.AttestationID
	}
	return p.store.ApplyRestoreDrillAttestationTx(ctx, tx, row, destination, alertJSON, alertKey)
}

func restoreDrillAlertVocabulary(reason RestoreDrillAlertReason) (string, string) {
	switch reason {
	case RestoreDrillAlertFailed:
		return "backup.restore_drill_failed", "critical"
	case RestoreDrillAlertSkipped:
		return "backup.restore_drill_skipped", "warning"
	default:
		return "backup.restore_drill_objective_breached", "warning"
	}
}

// restoreDrillAlert mirrors only the credential-free notification vocabulary
// this projector emits. The notify package consumes projections, so importing it
// here would create a cycle; JSON is the stable outbox contract between them.
type restoreDrillAlert struct {
	Kind        string `json:"kind"`
	TenantID    string `json:"tenant_id"`
	OperationID string `json:"operation_id,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// validateLifecycleApprovalShape checks the immutable event bytes before any
// authority is consumed or identity/read-history row is changed. V4 means the
// payload carries one exact approval use. V5 means an issuance without approval
// carries one exact profile/TTL binding. Older schemas predate both capabilities
// and must never gain either through permissive JSON decoding. This check runs
// even when consumed_event_id already equals e.ID: JetStream duplicate
// suppression expires, so a later same-ID publish cannot retarget another row.
func validateLifecycleApprovalShape(e events.Event, pl identityTransition) error {
	hasApproval := pl.Approval != nil
	hasIssuance := pl.Issuance != nil
	schemaVersion := schemaVersionOf(e)
	switch schemaVersion {
	case LifecycleApprovalEventSchemaVersion:
		if !hasApproval || hasIssuance {
			return fmt.Errorf("projections: %s approval payload/schema mismatch", e.Type)
		}
	case LifecycleIssuanceEventSchemaVersion:
		if hasApproval || !hasIssuance {
			return fmt.Errorf("projections: %s issuance payload/schema mismatch", e.Type)
		}
	case LifecycleOwnershipReadinessEventSchemaVersion:
		if hasApproval || hasIssuance || pl.OwnershipReadiness == nil || pl.To != "deployed" ||
			(e.Type != EventIdentityDeployed && e.Type != EventIdentityRenewed) {
			return fmt.Errorf("projections: %s ownership-readiness payload/schema mismatch", e.Type)
		}
		if pl.SideEffect == nil || pl.SideEffect.Destination != "connector.deploy" ||
			pl.SideEffect.IdempotencyKey != lifecycleApprovalOutboxKey(e.ID, pl.IdempotencyKey) ||
			len(pl.SideEffect.Payload) != 0 {
			return fmt.Errorf("projections: %s ownership-readiness side-effect mismatch", e.Type)
		}
		return nil
	default:
		if hasApproval {
			return fmt.Errorf("projections: %s approval payload/schema mismatch", e.Type)
		}
		if hasIssuance {
			return fmt.Errorf("projections: %s issuance payload/schema mismatch", e.Type)
		}
		return nil
	}
	if hasIssuance {
		if _, err := pl.Issuance.EvidenceRefs(); err != nil {
			return fmt.Errorf("projections: %s issuance binding is invalid: %w", e.Type, err)
		}
		expectedType, _, destination, ok := lifecycleApprovalEdge(pl.From, pl.To)
		if !ok || expectedType != EventIdentityIssued || e.Type != expectedType ||
			pl.From != "requested" || pl.To != "issued" {
			return fmt.Errorf("projections: %s issuance binding is on a non-issuance transition", e.Type)
		}
		if pl.SideEffect == nil || pl.SideEffect.Destination != destination ||
			pl.SideEffect.IdempotencyKey != lifecycleApprovalOutboxKey(e.ID, pl.IdempotencyKey) ||
			len(pl.SideEffect.Payload) != 0 {
			return fmt.Errorf("projections: %s issuance side-effect is not derived from the outer lifecycle event", e.Type)
		}
		return nil
	}
	approval := pl.Approval
	if approval.ResourceKind != "identity" || approval.ResourceID != pl.IdentityID ||
		approval.FromState != pl.From || approval.ToState != pl.To {
		return fmt.Errorf("projections: %s approval target mismatch", e.Type)
	}
	expectedType, expectedAction, destination, ok := lifecycleApprovalEdge(pl.From, pl.To)
	if !ok || e.Type != expectedType || approval.Action != expectedAction {
		return fmt.Errorf("projections: %s approval edge/action mismatch", e.Type)
	}
	if e.ID != LifecycleApprovalEventID(e.TenantID, *approval) {
		return fmt.Errorf("projections: %s approval event identity mismatch", e.Type)
	}
	if approval.Issuance != nil && (approval.Action != "issue" || pl.To != "issued") {
		return fmt.Errorf("projections: %s approval issuance binding is on a non-issuance transition", e.Type)
	}
	if pl.SideEffect == nil || pl.SideEffect.Destination != destination ||
		pl.SideEffect.IdempotencyKey != lifecycleApprovalOutboxKey(e.ID, pl.IdempotencyKey) ||
		len(pl.SideEffect.Payload) != 0 {
		return fmt.Errorf("projections: %s approval side-effect is not derived from the outer lifecycle event", e.Type)
	}
	return nil
}

// ValidateLifecycleApprovalEvent validates the self-contained v4 approval and v5
// non-approval issuance envelopes without touching a projection. The historical
// name stays source-compatible; boot reconciliation uses it before deriving an
// outbox command from retained history.
func ValidateLifecycleApprovalEvent(e events.Event) error {
	if schemaVersionOf(e) != LifecycleApprovalEventSchemaVersion &&
		schemaVersionOf(e) != LifecycleIssuanceEventSchemaVersion &&
		schemaVersionOf(e) != LifecycleOwnershipReadinessEventSchemaVersion {
		return nil
	}
	var payload identityTransition
	if err := decode(e, &payload); err != nil {
		return err
	}
	return validateLifecycleApprovalShape(e, payload)
}

// LifecycleApprovalEventID is the sole immutable event identity allowed to spend
// one lifecycle approval. It is public so the command side and projector cannot
// drift into different replay identities.
func LifecycleApprovalEventID(tenantID string, approval store.OperationApprovalUse) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("approval-execution\x00"+tenantID+"\x00"+
		approval.RequestID+"\x00"+approval.IntentDigest)).String()
}

func lifecycleApprovalEdge(from, to string) (eventType, action, destination string, ok bool) {
	switch {
	case from == "requested" && to == "issued":
		return EventIdentityIssued, "issue", "ca.issue", true
	case from == "issued" && to == "revoked":
		return EventIdentityRevoked, "revoke", "revocation.publish", true
	case from == "deployed" && to == "revoked":
		return EventIdentityRevoked, "revoke", "revocation.publish", true
	case from == "renewing" && to == "revoked":
		return EventIdentityRevoked, "revoke", "revocation.publish", true
	default:
		return "", "", "", false
	}
}

func lifecycleApprovalOutboxKey(eventID, requestKey string) string {
	requestKey = strings.TrimSpace(requestKey)
	if requestKey == "" {
		return eventID
	}
	return "transition:" + requestKey
}

func validateLifecycleApprovalAuthority(
	e events.Event,
	pl identityTransition,
	request store.OperationApprovalRequest,
	identity store.Identity,
	version uint64,
) error {
	approval := pl.Approval
	if approval == nil {
		return store.ErrApprovalNotReady
	}
	if request.ID != approval.RequestID || request.IntentDigest != approval.IntentDigest ||
		request.Reason != pl.Reason || approval.EvidenceRefs == nil ||
		approval.Reason != request.Reason || !sameLifecycleEvidence(approval.EvidenceRefs, request.EvidenceRefs) {
		return store.ErrApprovalDrifted
	}
	if err := ValidateLifecycleApprovalAttemptEvidence(request.EvidenceRefs, pl.IdempotencyKey, pl.SubjectCSRPEM); err != nil {
		return err
	}

	// A fresh projection must still see the exact reviewed state/version. An
	// at-least-once replay is allowed only when this same event is the consumed
	// authority and is the identity's current lifecycle version. A physically new
	// same-ID event after the broker dedup window therefore cannot retarget state.
	switch request.Status {
	case store.ApprovalStatusConsumed:
		if request.ConsumedEventID != e.ID || identity.Status != pl.To || version != e.Sequence {
			return store.ErrApprovalDrifted
		}
	default:
		if identity.Status != pl.From || version != approval.TargetVersion {
			return store.ErrApprovalDrifted
		}
	}
	return nil
}

func sameLifecycleEvidence(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// ValidateLifecycleApprovalAttemptEvidence proves that the exact HTTP retry key
// and CSR carried by a lifecycle command are the values reviewers saw as
// non-secret digests. It is also used by receiver-commit replay validation.
func ValidateLifecycleApprovalAttemptEvidence(refs []string, idempotencyKey, csrPEM string) error {
	if strings.TrimSpace(idempotencyKey) == "" {
		return fmt.Errorf("%w: approved lifecycle command has no idempotency key", store.ErrApprovalDrifted)
	}
	expectedKey := "idempotency-key-sha256:" + cryptoboundary.SHA256Hex([]byte(strings.TrimSpace(idempotencyKey)))
	if !hasOnlyExpectedLifecycleEvidence(refs, "idempotency-key-sha256:", expectedKey) {
		return fmt.Errorf("%w: approved lifecycle idempotency evidence changed", store.ErrApprovalDrifted)
	}
	expectedCSR := ""
	if csrPEM = strings.TrimSpace(csrPEM); csrPEM != "" {
		expectedCSR = "csr-sha256:" + cryptoboundary.SHA256Hex([]byte(csrPEM))
	}
	if !hasOnlyExpectedLifecycleEvidence(refs, "csr-sha256:", expectedCSR) {
		return fmt.Errorf("%w: approved lifecycle CSR evidence changed", store.ErrApprovalDrifted)
	}
	return nil
}

func hasOnlyExpectedLifecycleEvidence(refs []string, prefix, expected string) bool {
	count := 0
	for _, ref := range refs {
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		count++
		if ref != expected {
			return false
		}
	}
	if expected == "" {
		return count == 0
	}
	return count == 1
}

func validateTenantKeyDomainSnapshot(eventType string, pl TenantKeyDomainSnapshot) error {
	if pl.DomainID == "" || pl.Generation <= 0 ||
		pl.ProtectionMode != store.TenantKeyProtectionTenantDomain ||
		pl.WrapperKind == "" || pl.WrapperID == "" || len(pl.WrappedDomainKEK) == 0 {
		return fmt.Errorf("projections: %s requires domain_id, positive generation, tenant_domain protection, wrapper kind/id, and wrapped domain KEK", eventType)
	}
	if pl.OperationID == nil {
		return fmt.Errorf("projections: %s requires an operation_id UUID", eventType)
	}
	if _, err := uuid.Parse(*pl.OperationID); err != nil {
		return fmt.Errorf("projections: %s requires a valid operation_id UUID", eventType)
	}
	if pl.ProgressCompleted < 0 || pl.ProgressTotal < 0 || pl.ProgressCompleted > pl.ProgressTotal {
		return fmt.Errorf("projections: %s has invalid migration progress %d/%d", eventType, pl.ProgressCompleted, pl.ProgressTotal)
	}
	if !oneOf(pl.State,
		store.TenantKeyDomainStateMigrating,
		store.TenantKeyDomainStatePartial,
		store.TenantKeyDomainStateUnsealed,
		store.TenantKeyDomainStateSealQueued,
		store.TenantKeyDomainStateSealing,
		store.TenantKeyDomainStateSealed,
		store.TenantKeyDomainStateUnsealing,
		store.TenantKeyDomainStateWrapperUnavailable,
		store.TenantKeyDomainStateWrongWrapper,
		store.TenantKeyDomainStateCorrupt) {
		return fmt.Errorf("projections: %s has unsupported tenant key-domain state %q", eventType, pl.State)
	}
	if !oneOf(pl.OperationKind,
		store.TenantKeyOperationMigrate,
		store.TenantKeyOperationSeal,
		store.TenantKeyOperationUnseal) {
		return fmt.Errorf("projections: %s has unsupported operation kind %q", eventType, pl.OperationKind)
	}
	if !oneOf(pl.OperationStatus,
		store.TenantKeyOperationPending,
		store.TenantKeyOperationRunning,
		store.TenantKeyOperationCompleted,
		store.TenantKeyOperationFailed) {
		return fmt.Errorf("projections: %s has unsupported operation status %q", eventType, pl.OperationStatus)
	}
	if !oneOf(pl.LegacyHistoryExposure,
		store.TenantKeyLegacyNone,
		store.TenantKeyLegacyHotHistoryPending,
		store.TenantKeyLegacyExternalArchivesPossible) {
		return fmt.Errorf("projections: %s has unsupported legacy-history exposure %q", eventType, pl.LegacyHistoryExposure)
	}

	switch eventType {
	case EventTenantKeyDomainMigrationStarted:
		if pl.State != store.TenantKeyDomainStateMigrating ||
			pl.OperationKind != store.TenantKeyOperationMigrate ||
			!oneOf(pl.OperationStatus, store.TenantKeyOperationPending, store.TenantKeyOperationRunning) ||
			pl.LegacyHistoryExposure != store.TenantKeyLegacyHotHistoryPending {
			return fmt.Errorf("projections: %s must start a pending/running migration with hot history pending", eventType)
		}
	case EventTenantKeyDomainMigrationProgressed:
		if !oneOf(pl.State, store.TenantKeyDomainStateMigrating, store.TenantKeyDomainStatePartial) ||
			pl.OperationKind != store.TenantKeyOperationMigrate ||
			pl.OperationStatus != store.TenantKeyOperationRunning {
			return fmt.Errorf("projections: %s must carry running migration progress", eventType)
		}
	case EventTenantKeyDomainMigrationCompleted:
		if pl.OperationKind != store.TenantKeyOperationMigrate ||
			pl.OperationStatus != store.TenantKeyOperationCompleted ||
			pl.ProgressCompleted != pl.ProgressTotal {
			return fmt.Errorf("projections: %s must carry completed migration progress", eventType)
		}
		switch {
		case pl.State == store.TenantKeyDomainStateUnsealed &&
			pl.LegacyHistoryExposure == store.TenantKeyLegacyNone:
			// Strong independence is honest only after both hot and external history
			// are proven clean.
			if !hasNonBlankTenantKeyDomainEvidence(pl.TransitionEvidenceRefs) {
				return fmt.Errorf("projections: %s requires evidence before clearing legacy-history exposure", eventType)
			}
		case pl.State == store.TenantKeyDomainStatePartial &&
			pl.LegacyHistoryExposure == store.TenantKeyLegacyExternalArchivesPossible:
			// Hot state is migrated, but old backups/archives may still be
			// deployment-KEK decryptable, so the row remains explicitly partial.
		default:
			return fmt.Errorf("projections: %s may be unsealed only with no legacy exposure, or partial while external archives may remain", eventType)
		}
	case EventTenantKeyDomainMigrationFailed:
		if pl.OperationKind != store.TenantKeyOperationMigrate ||
			pl.OperationStatus != store.TenantKeyOperationFailed ||
			!oneOf(pl.State,
				store.TenantKeyDomainStatePartial,
				store.TenantKeyDomainStateWrapperUnavailable,
				store.TenantKeyDomainStateWrongWrapper,
				store.TenantKeyDomainStateCorrupt) ||
			pl.LastErrorCode == "" || pl.LastError == "" {
			return fmt.Errorf("projections: %s must preserve failed migration progress and a visible error", eventType)
		}
	case EventTenantKeyDomainSealRequested:
		if pl.State != store.TenantKeyDomainStateSealQueued ||
			pl.OperationKind != store.TenantKeyOperationSeal ||
			pl.OperationStatus != store.TenantKeyOperationPending ||
			strings.TrimSpace(pl.SealIdempotencyKey) == "" ||
			strings.TrimSpace(pl.SealRequestBinding) == "" {
			return fmt.Errorf("projections: %s must carry a queued seal operation with its idempotency key and request binding", eventType)
		}
	case EventTenantKeyDomainSealFailed:
		validRestoredState := (pl.State == store.TenantKeyDomainStateUnsealed &&
			pl.LegacyHistoryExposure == store.TenantKeyLegacyNone) ||
			(pl.State == store.TenantKeyDomainStatePartial &&
				pl.LegacyHistoryExposure == store.TenantKeyLegacyExternalArchivesPossible)
		if !validRestoredState || pl.OperationKind != store.TenantKeyOperationSeal ||
			pl.OperationStatus != store.TenantKeyOperationFailed || !pl.Retryable ||
			strings.TrimSpace(pl.LastErrorCode) == "" || strings.TrimSpace(pl.LastError) == "" {
			return fmt.Errorf("projections: %s must restore an available tenant-only state with a visible retryable seal failure", eventType)
		}
	case EventTenantKeyDomainSealed:
		if pl.State != store.TenantKeyDomainStateSealed ||
			pl.OperationKind != store.TenantKeyOperationSeal ||
			pl.OperationStatus != store.TenantKeyOperationCompleted {
			return fmt.Errorf("projections: %s must carry a completed sealed state", eventType)
		}
	case EventTenantKeyDomainUnsealRequested:
		if pl.State != store.TenantKeyDomainStateUnsealing ||
			pl.OperationKind != store.TenantKeyOperationUnseal ||
			!oneOf(pl.OperationStatus, store.TenantKeyOperationPending, store.TenantKeyOperationRunning) {
			return fmt.Errorf("projections: %s must carry a pending/running unseal operation", eventType)
		}
	case EventTenantKeyDomainUnsealed:
		if pl.State != store.TenantKeyDomainStateUnsealed ||
			pl.OperationKind != store.TenantKeyOperationUnseal ||
			pl.OperationStatus != store.TenantKeyOperationCompleted {
			return fmt.Errorf("projections: %s must carry a completed unsealed state", eventType)
		}
	}
	return nil
}

func (p *Projector) validateTenantKeyDomainExposureTransitionTx(
	ctx context.Context,
	tx pgx.Tx,
	e events.Event,
	pl TenantKeyDomainSnapshot,
) error {
	switch e.Type {
	case EventTenantKeyDomainMigrationStarted, EventTenantKeyDomainMigrationCompleted:
		return nil
	}

	current, err := p.store.GetTenantKeyDomainTx(ctx, tx, e.TenantID)
	if errors.Is(err, store.ErrTenantKeyDomainNotFound) {
		return fmt.Errorf("projections: %s requires an existing tenant key-domain transition", e.Type)
	}
	if err != nil {
		return fmt.Errorf("projections: read tenant key-domain transition guard: %w", err)
	}
	if e.Sequence <= current.LastTransitionSequence {
		return nil
	}
	if tenantKeyDomainExposureRank(pl.LegacyHistoryExposure) <
		tenantKeyDomainExposureRank(current.LegacyHistoryExposure) {
		return fmt.Errorf(
			"projections: %s cannot reduce legacy-history exposure from %q to %q",
			e.Type, current.LegacyHistoryExposure, pl.LegacyHistoryExposure,
		)
	}
	return nil
}

func tenantKeyDomainExposureRank(exposure string) int {
	switch exposure {
	case store.TenantKeyLegacyNone:
		return 0
	case store.TenantKeyLegacyExternalArchivesPossible:
		return 1
	case store.TenantKeyLegacyHotHistoryPending:
		return 2
	default:
		return 3
	}
}

func hasNonBlankTenantKeyDomainEvidence(refs []string) bool {
	for _, ref := range refs {
		if strings.TrimSpace(ref) != "" {
			return true
		}
	}
	return false
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// discoveryMetadataBool accepts both the server scanner's JSON booleans and
// the agent channel's string-valued metadata map. Discovery events are
// immutable, so projections must keep replaying both historical wire shapes.
func discoveryMetadataBool(raw json.RawMessage) bool {
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		return value
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return false
	}
	value, _ = strconv.ParseBool(text)
	return value
}

func decode(e events.Event, v any) error {
	if err := json.Unmarshal(e.Data, v); err != nil {
		return fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	return nil
}

// Project replays the log from the beginning and applies every event to the read
// model. It does NOT consult the projection checkpoint, so it always re-applies
// from sequence 0; ProjectCatchUp is the bounded boot path. Project remains for
// tests and for an explicit "apply everything from scratch" caller.
func (p *Projector) Project(ctx context.Context, log *events.Log) error {
	if err := p.validateSecretSyncRetainedHistory(ctx, log, false, false); err != nil {
		return err
	}
	secretAuthority, err := classifySecretSyncLifecycle(ctx, log)
	if err != nil {
		return err
	}
	dynamicSecretAuthority, err := classifyDynamicSecretLifecycle(ctx, log)
	if err != nil {
		return err
	}
	if err := p.resetEventProjections(ctx); err != nil {
		return err
	}
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		skip, err := secretAuthority.skip(e)
		if err != nil {
			return err
		}
		skipDynamicSecret, err := dynamicSecretAuthority.skip(e)
		if err != nil {
			return err
		}
		skip = skip || skipDynamicSecret
		if skip {
			if err := ValidateSchemaVersion(e); err != nil {
				return err
			}
			return p.applyEventProjections(ctx, e)
		}
		if isTenantLifecycleEventType(e.Type) {
			return p.ApplyRetainedTenantLifecycle(ctx, e)
		}
		return p.Apply(ctx, e)
	}); err != nil {
		return err
	}
	return p.validateSecretSyncRetainedHistory(ctx, log, true, false)
}

// ProjectCatchUp brings the read model up to the head of the log by replaying
// ONLY the events after the persisted projection checkpoint — the high-water mark
// of the last sequence already applied (SPINE-007). The relational read model
// survives a restart in PostgreSQL, so on a warm boot there is nothing (or only a
// short tail) to re-apply; cold start no longer grows linearly with the lifetime
// event count.
//
// It advances the checkpoint as it applies (every checkpointEvery events and once
// at the end), so a crash mid-catch-up resumes from roughly where it stopped on
// the next boot. Applying an event is an idempotent upsert (Apply), so re-applying
// the last partially-checkpointed batch after a crash is harmless — the watermark
// is an optimization for WHERE to resume, never a correctness boundary. The log
// stays the source of truth (AN-2); an explicit Rebuild still re-derives from
// sequence 0 and resets the checkpoint.
func (p *Projector) ProjectCatchUp(ctx context.Context, log *events.Log) error {
	// The privacy operation grant is deliberately outermost. It closes the live
	// race where another replica prepares SQL erasure authority after validation
	// but before this replica replaces extension state, and preserves the global
	// order: privacy operation -> projection -> event history.
	return p.store.WithPrivacyReadModelReplacementBarrier(ctx, func(barrierCtx context.Context) error {
		return p.projectCatchUpWithPrivacyBarrier(barrierCtx, log)
	})
}

func (p *Projector) projectCatchUpWithPrivacyBarrier(ctx context.Context, log *events.Log) error {
	if err := p.validateSecretSyncRetainedHistory(ctx, log, true, true); err != nil {
		return err
	}
	// Serialize the catch-up across replicas under the projection advisory lock
	// (RESIL-004): N replicas booting at once each run this, and without
	// coordination they would reset/replay extension state and replay into the
	// same core read-model tables concurrently. Inside that lock, one history
	// generation and inclusive head cover BOTH passes. An event appended while
	// extensions rebuild is therefore either in both passes or beyond the saved
	// checkpoint for the next catch-up/tailer; it can never land in core alone.
	if err := p.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		return log.WithHistoryRead(ctx, func(readCtx context.Context) error {
			replayHead, err := log.LastSequence(readCtx)
			if err != nil {
				return fmt.Errorf("projections: capture catch-up history head: %w", err)
			}
			secretAuthority, err := classifySecretSyncLifecycleThrough(readCtx, log, replayHead)
			if err != nil {
				return fmt.Errorf("projections: classify catch-up secret-sync lifecycle: %w", err)
			}
			dynamicSecretAuthority, err := classifyDynamicSecretLifecycleThrough(readCtx, log, replayHead)
			if err != nil {
				return fmt.Errorf("projections: classify catch-up dynamic-secret lifecycle: %w", err)
			}
			if err := p.rebuildEventProjectionsThrough(readCtx, log, replayHead); err != nil {
				return err
			}
			from, err := p.store.ProjectionCheckpoint(readCtx)
			if err != nil {
				return fmt.Errorf("projections: read checkpoint: %w", err)
			}
			if from > replayHead {
				return fmt.Errorf(
					"projections: checkpoint %d is beyond event history head %d",
					from, replayHead,
				)
			}
			var last uint64
			sinceCheckpoint := 0
			if from < replayHead {
				err = log.ReplayThrough(readCtx, from+1, replayHead, func(e events.Event) error {
					skip, err := secretAuthority.skip(e)
					if err != nil {
						return err
					}
					skipDynamicSecret, err := dynamicSecretAuthority.skip(e)
					if err != nil {
						return err
					}
					skip = skip || skipDynamicSecret
					if !skip {
						err = p.applyCore(readCtx, e)
					}
					if err != nil {
						return err
					}
					last = e.Sequence
					sinceCheckpoint++
					if sinceCheckpoint < checkpointEvery {
						return nil
					}
					if err := p.store.AdvanceProjectionCheckpoint(readCtx, last); err != nil {
						return err
					}
					sinceCheckpoint = 0
					return nil
				})
				if err != nil {
					return err
				}
			}
			if replayHead > 0 {
				if err := p.store.AdvanceProjectionCheckpoint(readCtx, replayHead); err != nil {
					return fmt.Errorf("projections: advance checkpoint: %w", err)
				}
			}
			return nil
		})
	}); err != nil {
		return err
	}
	return p.validateSecretSyncRetainedHistory(ctx, log, true, false)
}

// checkpointEvery is how many events ProjectCatchUp applies between watermark
// advances. A batch keeps the per-event write amplification low while bounding how
// much a crash forces a re-replay on the next boot.
const checkpointEvery = 256

// AdvanceCheckpoint moves the projection high-water mark forward to seq (SPINE-007).
// The tailing projection worker calls it after applying an out-of-band event so the
// boot catch-up watermark tracks the tail's position. The advance is monotonic
// (it never rewinds), so it is safe to call with sequences that may already be
// below the current watermark.
func (p *Projector) AdvanceCheckpoint(ctx context.Context, seq uint64) error {
	return p.store.AdvanceProjectionCheckpoint(ctx, seq)
}

// Rebuild discards the event-sourced read model and re-derives it from the whole
// log, reproducing the same state (AN-2). This is the disaster-recovery and
// migration primitive: the relational state is a pure function of the log.
//
// It is ATOMIC (RESIL-003): the truncate and the full replay run in ONE
// transaction, so a crash or error mid-rebuild rolls back to the prior read model
// rather than leaving a truncated/partial inventory the API might answer queries
// from. The transaction runs as the owner role (it must TRUNCATE and re-derive every
// tenant); each event is applied with the tenant GUC set, and every projection write
// carries its tenant_id explicitly, so AN-1 holds even with RLS bypassed for this
// trusted system operation.
func (p *Projector) Rebuild(ctx context.Context, log *events.Log) error {
	if !p.allowSecretSyncRecoveryBootstrap {
		if err := p.validateSecretSyncRetainedHistory(ctx, log, false, false); err != nil {
			return err
		}
	}
	if err := p.store.WithPrivacyReadModelReplacementBarrier(ctx, func(barrierCtx context.Context) error {
		return p.rebuildWithPrivacyBarrier(barrierCtx, log)
	}); err != nil {
		return err
	}
	return p.validateSecretSyncRetainedHistory(ctx, log, true, false)
}

func (p *Projector) rebuildWithPrivacyBarrier(ctx context.Context, log *events.Log) error {
	return log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		replayHead, err := log.LastSequence(readCtx)
		if err != nil {
			return fmt.Errorf("projections: capture rebuild history head: %w", err)
		}
		eventCheckpoints := map[string]audit.Checkpoint{}
		secretAuthority, err := classifySecretSyncLifecycleThrough(readCtx, log, replayHead)
		if err != nil {
			return fmt.Errorf("projections: preflight secret-sync lifecycle: %w", err)
		}
		dynamicSecretAuthority, err := classifyDynamicSecretLifecycleThrough(readCtx, log, replayHead)
		if err != nil {
			return fmt.Errorf("projections: preflight dynamic-secret lifecycle: %w", err)
		}
		if err := log.ReplayThrough(readCtx, 1, replayHead, func(event events.Event) error {
			if event.Type != audit.EventTypeArchived {
				return nil
			}
			if err := ValidateSchemaVersion(event); err != nil {
				return err
			}
			var payload audit.ArchivedEvent
			if err := decode(event, &payload); err != nil {
				return err
			}
			if !payload.SourceHistoryRetained {
				return errors.New("projections: audit.archived does not attest retained AN-2 source history")
			}
			checkpoint := audit.Checkpoint{
				TenantID: event.TenantID, BoundarySeq: payload.BoundarySeq,
				BoundaryHash: payload.BoundaryHash, RecordCount: payload.Count,
				ArchiveURI: payload.ArchiveURI,
			}
			if prior, ok := eventCheckpoints[event.TenantID]; !ok ||
				checkpoint.BoundarySeq > prior.BoundarySeq {
				eventCheckpoints[event.TenantID] = checkpoint
			}
			return nil
		}); err != nil {
			return fmt.Errorf("projections: preflight replayable audit checkpoints: %w", err)
		}
		eventCheckpointTenants := make([]string, 0, len(eventCheckpoints))
		for tenantID := range eventCheckpoints {
			eventCheckpointTenants = append(eventCheckpointTenants, tenantID)
		}
		sort.Strings(eventCheckpointTenants)
		for _, tenantID := range eventCheckpointTenants {
			checkpoint := eventCheckpoints[tenantID]
			if err := audit.VerifyCheckpointSourceRetained(readCtx, log, checkpoint); err != nil {
				return fmt.Errorf("projections: refuse lossy rebuild from audit.archived event: %w", err)
			}
		}
		checkpointTenants, err := p.store.ListAuditCheckpointTenants(readCtx)
		if err != nil {
			return fmt.Errorf("projections: list audit checkpoints before rebuild: %w", err)
		}
		for _, tenantID := range checkpointTenants {
			checkpoint, ok, err := p.store.LatestAuditCheckpoint(readCtx, tenantID)
			if err != nil {
				return fmt.Errorf("projections: read audit checkpoint before rebuild: %w", err)
			}
			if !ok {
				return fmt.Errorf("projections: audit checkpoint inventory lost tenant %s", tenantID)
			}
			if err := audit.VerifyCheckpointSourceRetained(readCtx, log, checkpoint); err != nil {
				return fmt.Errorf("projections: refuse lossy rebuild: %w", err)
			}
			eventCheckpoint, replayable := eventCheckpoints[tenantID]
			if !replayable ||
				eventCheckpoint.BoundarySeq != checkpoint.BoundarySeq ||
				eventCheckpoint.RecordCount != checkpoint.RecordCount ||
				eventCheckpoint.BoundaryHash != checkpoint.BoundaryHash ||
				eventCheckpoint.ArchiveURI != checkpoint.ArchiveURI {
				return fmt.Errorf(
					"projections: audit checkpoint for tenant %s has no exact replayable audit.archived v%d event; refusing to erase its served-view boundary",
					tenantID, audit.ArchivedEventSchemaVersion,
				)
			}
		}
		return p.store.RebuildReadModelTx(readCtx, func(tx pgx.Tx) error {
			if err := p.resetEventProjectionsTx(readCtx, tx); err != nil {
				return err
			}
			// A full rebuild re-derives from sequence 0, so the projection checkpoint
			// (SPINE-007) is reset in the SAME transaction as truncate+replay. The
			// exact pinned head, not merely the last live callback, becomes the new
			// watermark: restored history can end in deleted positions or be all gaps.
			if err := p.store.ResetProjectionCheckpointTx(readCtx, tx); err != nil {
				return err
			}
			if err := log.ReplayThrough(readCtx, 0, replayHead, func(e events.Event) error {
				// The preflight authority marks exactly the secret-bearing source and
				// terminal sequences erased by an offboarded lifecycle. A later
				// registration of the same tenant UUID is classified independently.
				_, skipOffboardedSecretTarget := secretAuthority.skipSequences[e.Sequence]
				_, skipOffboardedDynamicSecret := dynamicSecretAuthority.skipSequences[e.Sequence]
				if skipOffboardedSecretTarget || skipOffboardedDynamicSecret {
					if err := ValidateSchemaVersion(e); err != nil {
						return err
					}
				} else if err := p.applyForRebuild(readCtx, tx, e); err != nil {
					return fmt.Errorf(
						"projections: rebuild apply %s event %s at sequence %d: %w",
						e.Type, e.ID, e.Sequence, err,
					)
				}
				return p.applyEventProjectionsTx(readCtx, tx, e)
			}); err != nil {
				return err
			}
			return p.store.SetProjectionCheckpointTx(readCtx, tx, replayHead)
		})
	})
}

// Snapshot persists a per-tenant read-model snapshot at the current projection
// checkpoint (SPINE-007 / EXC-SCALE-01), so a later cold boot or DR restore can
// rehydrate from it and replay only the tail. It captures each tenant's read-model
// rows and stamps them with the global offset the read model has applied
// (ProjectionCheckpoint), then bounds catch-up at boot to O(events-since-snapshot)
// instead of O(lifetime events).
//
// The snapshot is purely an optimization (AN-2): the log stays the source of truth,
// a snapshot is reproducible by Rebuild from sequence 0, and a corrupt/missing one is
// ignored on boot in favor of a full replay. Store.WriteReadModelSnapshots owns the
// complete cross-replica lock order: shared privacy history operation, durable
// unfinished-preparation check, projection lock, then PostgreSQL capture. That keeps
// a snapshot writer out of both the live SQL-prepared cutover window and a crashed
// marker's recovery window.
//
// Per-tenant capture is tenant-scoped under RLS (AN-1): WriteTenantSnapshot runs in
// the tenant's RLS context, so a tenant's snapshot can only ever hold that tenant's
// rows. It returns the number of tenants snapshotted.
func (p *Projector) Snapshot(ctx context.Context) (int, error) {
	return p.store.WriteReadModelSnapshots(ctx)
}

// RestoreFromSnapshot rehydrates the read model from the latest snapshots and then
// replays ONLY the events after the offset the snapshots cover (SPINE-007 /
// EXC-SCALE-01), so boot/restore is O(events-since-snapshot) rather than a full-log
// replay. It reports whether it handled the boot (restored == true): when no
// known-format snapshot exists it returns (false, nil) so the caller falls through to
// the existing checkpoint catch-up.
//
// The log remains the source of truth (AN-2): the restore-then-tail-replay runs in
// ONE owner-role transaction (atomic, like Rebuild — a crash mid-restore rolls back
// to the prior read model), and the replayed tail is applied with the SAME projection
// logic a rebuild uses. If the snapshot is corrupt or the restore fails for any
// reason, it FALLS BACK to a full Rebuild from sequence 0 (the log is truth) and
// still returns restored == true, so a bad snapshot can never leave the read model
// wrong — at worst it costs a one-time full replay. It takes the projection advisory
// lock so concurrent replica boots serialize (RESIL-004).
func (p *Projector) RestoreFromSnapshot(ctx context.Context, log *events.Log) (restored bool, err error) {
	if err := p.validateSecretSyncRetainedHistory(ctx, log, false, false); err != nil {
		return false, err
	}
	err = p.store.WithPrivacyReadModelReplacementBarrier(ctx, func(barrierCtx context.Context) error {
		var restoreErr error
		restored, restoreErr = p.restoreFromSnapshotWithPrivacyBarrier(barrierCtx, log)
		return restoreErr
	})
	if err != nil || !restored {
		return restored, err
	}
	return true, p.validateSecretSyncRetainedHistory(ctx, log, true, false)
}

func (p *Projector) restoreFromSnapshotWithPrivacyBarrier(
	ctx context.Context,
	log *events.Log,
) (restored bool, err error) {
	var handled bool
	lockErr := p.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		from, err := p.store.LatestSnapshotOffset(ctx)
		if errors.Is(err, store.ErrNoSnapshot) {
			return nil // no snapshot — caller does the normal checkpoint catch-up
		}
		if err != nil {
			return err
		}
		// Only restore when the snapshot knows MORE than the current projection
		// checkpoint — i.e. the snapshot's covered offset is ahead of the watermark. That
		// is the DR/cold-start case: the read model and its checkpoint were lost (a fresh
		// PostgreSQL) but the snapshot survived, so the checkpoint reads 0 (or behind) and
		// the snapshot is the fast way back. On a WARM boot the checkpoint is at or ahead
		// of the snapshot, so we skip the (wasteful) truncate+reload and let the caller's
		// checkpoint catch-up replay just the short tail. This keeps the snapshot a pure
		// accelerator: it never penalizes a healthy restart, and the log stays truth.
		checkpoint, err := p.store.ProjectionCheckpoint(ctx)
		if err != nil {
			return fmt.Errorf("projections: read checkpoint for snapshot restore: %w", err)
		}
		if from <= checkpoint {
			return nil // checkpoint already covers the snapshot — normal catch-up suffices
		}
		handled = true
		// Atomic restore + tail replay in one transaction. RestoreSnapshotsTx truncates
		// the read model and reloads every tenant's snapshot rows; we then set the
		// checkpoint to the snapshot offset and replay the tail after it, advancing the
		// checkpoint to the new head — all committing or rolling back together.
		txErr := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
			replayHead, herr := log.LastSequence(readCtx)
			if herr != nil {
				return fmt.Errorf("projections: capture snapshot-tail history head: %w", herr)
			}
			secretAuthority, herr := classifySecretSyncLifecycleThrough(readCtx, log, replayHead)
			if herr != nil {
				return fmt.Errorf("projections: classify snapshot-tail secret-sync lifecycle: %w", herr)
			}
			dynamicSecretAuthority, herr := classifyDynamicSecretLifecycleThrough(readCtx, log, replayHead)
			if herr != nil {
				return fmt.Errorf("projections: classify snapshot-tail dynamic-secret lifecycle: %w", herr)
			}
			if replayHead < from {
				return fmt.Errorf(
					"projections: snapshot offset %d is beyond event history head %d",
					from, replayHead,
				)
			}
			return p.store.RestoreReadModelTx(readCtx, func(tx pgx.Tx) error {
				if _, rerr := p.store.RestoreSnapshotsTx(readCtx, tx); rerr != nil {
					return rerr
				}
				if serr := p.store.SetProjectionCheckpointTx(readCtx, tx, from); serr != nil {
					return serr
				}
				if rerr := log.ReplayThrough(readCtx, from+1, replayHead, func(e events.Event) error {
					_, skipSecretSync := secretAuthority.skipSequences[e.Sequence]
					_, skipDynamicSecret := dynamicSecretAuthority.skipSequences[e.Sequence]
					if skipSecretSync || skipDynamicSecret {
						return ValidateSchemaVersion(e)
					}
					return p.applyForRebuild(readCtx, tx, e)
				}); rerr != nil {
					return rerr
				}
				// Advance across every position in the pinned tail, including a
				// trailing or all-gap range that produced no live callbacks.
				return p.store.SetProjectionCheckpointTx(readCtx, tx, replayHead)
			})
		})
		if txErr != nil {
			// The snapshot path failed (e.g. a corrupt payload). The log is the source of
			// truth, so fall back to a full rebuild from sequence 0 rather than serving a
			// partially-restored read model. Rebuild is itself atomic and resets the
			// checkpoint; we keep handled == true so the caller does not double-catch-up.
			return p.rebuildWithPrivacyBarrier(ctx, log)
		}
		return nil
	})
	if lockErr != nil {
		return handled, lockErr
	}
	return handled, nil
}

// applyForRebuild applies one event to the read model on the rebuild's single
// transaction (RESIL-003). It mirrors Apply's dispatch but shares one tx instead of
// opening a per-event transaction, so the whole rebuild commits or rolls back as a
// unit:
//   - tenant.registered  -> UpsertTenantTx (the tenant projection joins the rebuild tx)
//   - tenant.offboarded  -> delete this tenant's rows from the read-model tables on
//     the tx, so a rebuilt read model does not resurrect a deleted tenant. Only the
//     event-sourced read model (ReadModelTables) is in the rebuild's scope, so it does
//     not touch independent tenant tables (api_tokens, CT config), which are not
//     rebuilt from the log.
//   - everything else    -> set the tenant GUC on the tx, then ApplyTx.
func (p *Projector) applyForRebuild(ctx context.Context, tx pgx.Tx, e events.Event) error {
	switch e.Type {
	case EventTenantRegistered:
		if err := ValidateSchemaVersion(e); err != nil {
			return err
		}
		var payload tenantRegistered
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return p.store.UpsertTenantTx(ctx, tx, store.Tenant{
			TenantID: e.TenantID, Name: payload.Name, EventSeq: e.Sequence,
		})
	case EventTenantOffboarded:
		if err := ValidateSchemaVersion(e); err != nil {
			return err
		}
		var payload tenantOffboarded
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if err := p.store.SetTenantGUCTx(ctx, tx, e.TenantID); err != nil {
			return err
		}
		// The rebuild owns exactly the event-sourced read model, so it erases this
		// tenant's read-model rows here (the equivalent, within the rebuild's scope, of
		// the live OffboardTenant) rather than re-running the full cross-table erase.
		return p.store.DeleteTenantReadModelTx(ctx, tx, e.TenantID)
	default:
		if err := p.store.SetTenantGUCTx(ctx, tx, e.TenantID); err != nil {
			return err
		}
		return p.ApplyTx(ctx, tx, e)
	}
}

func projectionADCSWorstSeverity(findings []adcsdiscovery.Finding) string {
	worst := ""
	best := 0
	for _, finding := range findings {
		rank := 0
		switch finding.Severity {
		case adcsdiscovery.SeverityMedium:
			rank = 1
		case adcsdiscovery.SeverityHigh:
			rank = 2
		case adcsdiscovery.SeverityCritical:
			rank = 3
		}
		if rank > best {
			best, worst = rank, string(finding.Severity)
		}
	}
	return worst
}
