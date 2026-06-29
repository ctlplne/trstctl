package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Event types for the served domain (AN-2). Every served mutation emits one of
// these; the read model is rebuilt by applying them. They are the contract
// between the command side (which appends them) and the projector (which builds
// the read model from them).
const (
	EventTenantRegistered                 = "tenant.registered"
	EventTenantOffboarded                 = "tenant.offboarded"
	EventOwnerCreated                     = "owner.created"
	EventOwnerUpdated                     = "owner.updated"
	EventOwnerDeleted                     = "owner.deleted"
	EventIssuerCreated                    = "issuer.created"
	EventIdentityCreated                  = "identity.created"
	EventIdentityIssued                   = "identity.issued"
	EventIdentityDeployed                 = "identity.deployed"
	EventIdentityRevoked                  = "identity.revoked"
	EventIdentityRenewing                 = "identity.renewing"
	EventIdentityRenewed                  = "identity.renewed"
	EventIdentityRetired                  = "identity.retired"
	EventCertificateRecorded              = "certificate.recorded"
	EventCertificateRevoked               = "certificate.revoked"
	EventCertificateSuperseded            = "certificate.superseded"
	EventCAIssuedCertificate              = "ca.certificate.issued"
	EventCACertificateRevoked             = "ca.certificate.revoked"
	EventCACeremonyStarted                = "ca.ceremony.started"
	EventCACeremonyApproved               = "ca.ceremony.approved"
	EventCARootCreated                    = "ca.root.created"
	EventCAAuthorityImported              = "ca.authority.imported"
	EventCAIntermediateCreated            = "ca.intermediate.created"
	EventCAIntermediateCSRIssued          = "ca.intermediate_csr.issued"
	EventCAEndEntityIssued                = "ca.endentity.issued"
	EventCRLPublished                     = "ca.crl.published"
	EventOCSPResponderRotated             = "ca.ocsp_responder.rotated"
	EventAgentHeartbeat                   = "agent.heartbeat"
	EventAgentCertRenewed                 = "agent.cert.renewed"
	EventAgentCertRevoked                 = "agent.cert.revoked"
	EventProfileCreated                   = "profile.created"
	EventProfileUpdated                   = "profile.updated"
	EventDiscoverySourceUpserted          = "discovery.source.upserted"
	EventDiscoveryScheduleUpserted        = "discovery.schedule.upserted"
	EventDiscoveryRunQueued               = "discovery.run.queued"
	EventDiscoveryRunStarted              = "discovery.run.started"
	EventDiscoveryFindingRecorded         = "discovery.finding.recorded"
	EventDiscoveryFindingTriageChanged    = "discovery.finding.triage_changed"
	EventDiscoveryRunCompleted            = "discovery.run.completed"
	EventComplianceReportScheduleUpserted = "compliance.report_schedule.upserted"
	EventNotificationRead                 = "notification.read"
	EventNotificationThresholdDelivered   = "notification.threshold.delivered"
	EventCBOMAssetObserved                = "cbom.asset.observed"
	EventPQCMigrationStarted              = "pqc.migration.started"
	EventPQCMigrationAssetCompleted       = "pqc.migration.asset_completed"
	EventPQCMigrationRollbackCompleted    = "pqc.migration.rollback_completed"
	EventDeploymentTargetUpserted         = "deployment_target.upserted"
	EventDeploymentTargetDeleted          = "deployment_target.deleted"
	EventIdentityConnectorTargetBound     = "identity.connector_target_bound"
	EventConnectorDeliveryRecorded        = "connector.delivery.recorded"
	EventLifecycleRotationRecorded        = "lifecycle.rotation.recorded"
	EventIncidentExecutionRecorded        = "incident.execution.recorded"
	EventIncidentFleetReissuanceRecorded  = "incident.fleet_reissuance.recorded"
	EventRemediationPlaybookRunRecorded   = "remediation.playbook_run.recorded"
	EventResponseIntegrationDispatched    = "response.integration.dispatched"
	EventPrivacySubjectErased             = "privacy.subject.erased"
	EventPrivacyRetentionEnforced         = "privacy.retention.enforced"
	EventTenantMemberUpserted             = "tenant.member.upserted"
	EventTenantMemberOffboarded           = "tenant.member.offboarded"
	EventAPITokenCreated                  = "api_token.created"
	EventAPITokenRevoked                  = "api_token.revoked"
	EventPAMSessionStarted                = "pam.session.started"
	EventPAMSessionExpired                = "pam.session.expired"
	EventNHIAccessReviewCampaignStarted   = "nhi.access_review.campaign.started"
	EventNHIAccessReviewItemDecided       = "nhi.access_review.item.decided"

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

// Payloads. Each carries everything needed to reconstruct the read-model row
// (the surrogate id included), so a replay is deterministic. created_at is NOT a
// payload field: it is the event's own time, set by the projector, so a rebuild
// reproduces it exactly.

// OwnerCreated is the payload of an owner.created event.
type OwnerCreated struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// OwnerUpdated is the payload of an owner.updated event.
type OwnerUpdated struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Email string `json:"email"`
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
	IssuanceIdempotencyKey string     `json:"issuance_idempotency_key,omitempty"`
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
	SubjectRef     string                        `json:"subject_ref"`
	RequestedByRef string                        `json:"requested_by_ref,omitempty"`
	Reason         string                        `json:"reason,omitempty"`
	Selectors      store.PrivacyErasureSelectors `json:"selectors"`
	Counts         map[string]int                `json:"counts,omitempty"`
}

// PrivacyRetentionEnforced is the payload of a privacy.retention.enforced event.
// It carries policy cutoffs and counts, not the personal values being removed.
type PrivacyRetentionEnforced struct {
	RunID          string                        `json:"run_id"`
	RequestedByRef string                        `json:"requested_by_ref,omitempty"`
	Cutoffs        store.PrivacyRetentionCutoffs `json:"cutoffs"`
	Counts         map[string]int                `json:"counts,omitempty"`
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

// DiscoveryScheduleUpserted is the payload of discovery.schedule.upserted.
type DiscoveryScheduleUpserted struct {
	ID              string `json:"id"`
	SourceID        string `json:"source_id"`
	Name            string `json:"name"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
}

// DiscoveryRunQueued is the payload of discovery.run.queued.
type DiscoveryRunQueued struct {
	ID          string  `json:"id"`
	SourceID    string  `json:"source_id"`
	ScheduleID  *string `json:"schedule_id,omitempty"`
	DryRun      bool    `json:"dry_run"`
	RequestedBy string  `json:"requested_by,omitempty"`
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
	ID                string  `json:"id"`
	Status            string  `json:"status"`
	ManagedIdentityID *string `json:"managed_identity_id,omitempty"`
	Actor             string  `json:"actor,omitempty"`
	Reason            string  `json:"reason,omitempty"`
}

// DiscoveryRunCompleted is the payload of discovery.run.completed.
type DiscoveryRunCompleted struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Targets    int    `json:"targets"`
	Discovered int    `json:"discovered"`
	Failed     int    `json:"failed"`
	Rejected   int    `json:"rejected"`
	Error      string `json:"error,omitempty"`
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

// NotificationThresholdDelivered is the payload of
// notification.threshold.delivered.
type NotificationThresholdDelivered struct {
	Subject       string    `json:"subject"`
	ThresholdDays int       `json:"threshold_days"`
	Channel       string    `json:"channel"`
	SentAt        time.Time `json:"sent_at,omitempty"`
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

// PQCMigrationStarted records the tenant-scoped operator intent to re-issue CBOM
// assets toward a post-quantum target. The side effect itself is still an outbox
// row; this event is the immutable request fact.
type PQCMigrationStarted struct {
	RunID              string   `json:"run_id"`
	AssetIDs           []string `json:"asset_ids"`
	TargetAlgorithm    string   `json:"target_algorithm"`
	EffectiveAlgorithm string   `json:"effective_algorithm"`
	Protocol           string   `json:"protocol"`
	RollbackOnFailure  bool     `json:"rollback_on_failure"`
	Queued             int      `json:"queued"`
}

// PQCMigrationAssetCompleted projects a migrated CBOM row after the outbox worker
// has minted the replacement certificate through the served protocol path.
type PQCMigrationAssetCompleted struct {
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

// PQCMigrationRollbackCompleted projects the original CBOM row back after an
// operator rollback drill or break-glass rollback.
type PQCMigrationRollbackCompleted struct {
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
	ID             string  `json:"id"`
	OutboxID       *int64  `json:"outbox_id,omitempty"`
	IdentityID     *string `json:"identity_id,omitempty"`
	Destination    string  `json:"destination"`
	Connector      string  `json:"connector"`
	Target         string  `json:"target"`
	Fingerprint    string  `json:"fingerprint,omitempty"`
	Status         string  `json:"status"`
	Attempts       int     `json:"attempts,omitempty"`
	Reason         string  `json:"reason,omitempty"`
	Detail         string  `json:"detail,omitempty"`
	RollbackRef    string  `json:"rollback_ref,omitempty"`
	IdempotencyKey string  `json:"idempotency_key,omitempty"`
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
	Status                 string                      `json:"status"`
	Phase                  string                      `json:"phase"`
	Reason                 string                      `json:"reason,omitempty"`
	BatchSize              int                         `json:"batch_size,omitempty"`
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
	ID                  string          `json:"id"`
	PlaybookID          string          `json:"playbook_id"`
	TargetIdentityID    string          `json:"target_identity_id,omitempty"`
	InventoryID         string          `json:"inventory_id,omitempty"`
	Status              string          `json:"status"`
	Phase               string          `json:"phase"`
	Action              string          `json:"action"`
	Reason              string          `json:"reason,omitempty"`
	Connector           string          `json:"connector,omitempty"`
	Target              string          `json:"target,omitempty"`
	OutboxID            *int64          `json:"outbox_id,omitempty"`
	ConnectorDeliveryID *string         `json:"connector_delivery_id,omitempty"`
	ScopeDelta          json.RawMessage `json:"scope_delta"`
	EvidenceRefs        []string        `json:"evidence_refs,omitempty"`
	RollbackRefs        []string        `json:"rollback_refs,omitempty"`
	IdempotencyKey      string          `json:"idempotency_key,omitempty"`
	CreatedBy           string          `json:"created_by,omitempty"`
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

// identityTransition decodes the orchestrator's lifecycle event payload. The
// projector applies the new status to the identity row AND appends the full
// transition to the identity_transitions read model (SPINE-001), so History/State
// read an indexed, tenant-scoped projection instead of replaying the whole log.
// (The contract is the JSON, so the projector does not import the orchestrator.)
type identityTransition struct {
	IdentityID string `json:"identity_id"`
	From       string `json:"from"`
	To         string `json:"to"`
	Reason     string `json:"reason,omitempty"`
}

// Projector derives PostgreSQL read models from the event stream (AN-2). The
// read model is always a projection of the log; nothing writes the served
// domain read model except through here.
type Projector struct {
	store *store.Store
}

// New returns a Projector that writes into s.
func New(s *store.Store) *Projector { return &Projector{store: s} }

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

// Apply applies a single event to the read model in its own tenant-scoped
// transaction. It is exported so the command side can project an event live,
// right after appending it, using the same logic a rebuild uses.
func (p *Projector) Apply(ctx context.Context, e events.Event) error {
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
		if _, err := p.store.OffboardTenant(ctx, e.TenantID); err != nil {
			return fmt.Errorf("projections: apply %s: %w", e.Type, err)
		}
		return nil
	}
	// Domain entity events apply under the tenant's RLS context.
	return p.store.WithTenant(ctx, e.TenantID, func(tx pgx.Tx) error {
		return p.ApplyTx(ctx, tx, e)
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
	EventTenantRegistered:                 {1: true},
	EventTenantOffboarded:                 {1: true},
	EventOwnerCreated:                     {1: true},
	EventOwnerUpdated:                     {1: true},
	EventOwnerDeleted:                     {1: true},
	EventIssuerCreated:                    {1: true},
	EventIdentityCreated:                  {1: true},
	EventIdentityIssued:                   {1: true},
	EventIdentityDeployed:                 {1: true},
	EventIdentityRevoked:                  {1: true},
	EventIdentityRenewing:                 {1: true},
	EventIdentityRenewed:                  {1: true},
	EventIdentityRetired:                  {1: true},
	EventCertificateRecorded:              {1: true},
	EventCertificateRevoked:               {1: true},
	EventCertificateSuperseded:            {1: true},
	EventCAIssuedCertificate:              {1: true},
	EventCACertificateRevoked:             {1: true},
	EventCACeremonyStarted:                {1: true},
	EventCACeremonyApproved:               {1: true},
	EventCRLPublished:                     {1: true, 2: true, 3: true},
	EventOCSPResponderRotated:             {1: true},
	EventAgentHeartbeat:                   {1: true},
	EventAgentCertRenewed:                 {1: true},
	EventAgentCertRevoked:                 {1: true},
	EventProfileCreated:                   {1: true, 2: true},
	EventProfileUpdated:                   {1: true, 2: true},
	EventDiscoverySourceUpserted:          {1: true},
	EventDiscoveryScheduleUpserted:        {1: true},
	EventDiscoveryRunQueued:               {1: true},
	EventDiscoveryRunStarted:              {1: true},
	EventDiscoveryFindingRecorded:         {1: true},
	EventDiscoveryFindingTriageChanged:    {1: true},
	EventDiscoveryRunCompleted:            {1: true},
	EventComplianceReportScheduleUpserted: {1: true},
	EventNotificationRead:                 {1: true},
	EventNotificationThresholdDelivered:   {1: true},
	EventCBOMAssetObserved:                {1: true},
	EventDeploymentTargetUpserted:         {1: true},
	EventDeploymentTargetDeleted:          {1: true},
	EventIdentityConnectorTargetBound:     {1: true},
	EventConnectorDeliveryRecorded:        {1: true},
	EventLifecycleRotationRecorded:        {1: true},
	EventIncidentExecutionRecorded:        {1: true},
	EventIncidentFleetReissuanceRecorded:  {1: true},
	EventRemediationPlaybookRunRecorded:   {1: true},
	EventResponseIntegrationDispatched:    {1: true},
	EventPrivacySubjectErased:             {1: true},
	EventPrivacyRetentionEnforced:         {1: true},
	EventTenantMemberUpserted:             {1: true},
	EventTenantMemberOffboarded:           {1: true},
	EventAPITokenCreated:                  {1: true},
	EventAPITokenRevoked:                  {1: true},
	EventPAMSessionStarted:                {1: true},
	EventPAMSessionExpired:                {1: true},
	EventNHIAccessReviewCampaignStarted:   {1: true},
	EventNHIAccessReviewItemDecided:       {1: true},
}

func init() {
	knownSchemaVersions[EventPQCMigrationStarted] = map[int]bool{1: true}
	knownSchemaVersions[EventPQCMigrationAssetCompleted] = map[int]bool{1: true}
	knownSchemaVersions[EventPQCMigrationRollbackCompleted] = map[int]bool{1: true}
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
	case EventOwnerCreated:
		var pl OwnerCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyOwnerCreatedTx(ctx, tx, store.Owner{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.OwnerKind(pl.Kind),
			Name: pl.Name, Email: pl.Email, CreatedAt: e.Time,
		})
	case EventOwnerUpdated:
		var pl OwnerUpdated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyOwnerUpdatedTx(ctx, tx, store.Owner{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.OwnerKind(pl.Kind), Name: pl.Name, Email: pl.Email,
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
		if err := p.store.ApplyCertificateRecordedTx(ctx, tx, store.Certificate{
			ID: pl.ID, TenantID: e.TenantID, CAID: pl.CAID, OwnerID: pl.OwnerID, Subject: pl.Subject, SANs: pl.SANs,
			Issuer: pl.Issuer, Serial: pl.Serial, Fingerprint: pl.Fingerprint, KeyAlgorithm: pl.KeyAlgorithm,
			NotBefore: pl.NotBefore, NotAfter: pl.NotAfter, DeploymentLocation: pl.DeploymentLocation,
			Source: pl.Source, CertificateDER: pl.CertificateDER, IssuanceIdempotencyKey: pl.IssuanceIdempotencyKey,
			ReplacesID: pl.ReplacesID, CreatedAt: e.Time,
		}); err != nil {
			return err
		}
		if pl.CAID == "" || pl.Serial == "" {
			return nil
		}
		return p.store.RecordIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, e.Time)
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
		return p.store.ApplyAgentHeartbeatTx(ctx, tx, store.Agent{
			ID: pl.ID, TenantID: e.TenantID, Name: pl.Agent, Status: pl.Status,
			Version: pl.Version, LastSeenAt: &lastSeen, CreatedAt: e.Time,
		})
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
	case EventDiscoverySourceUpserted:
		var pl DiscoverySourceUpserted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: pl.ID, TenantID: e.TenantID, Kind: pl.Kind, Name: pl.Name,
			Config: pl.Config, CreatedAt: e.Time, UpdatedAt: e.Time,
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
			Status: "queued", DryRun: pl.DryRun, RequestedBy: pl.RequestedBy, CreatedAt: e.Time,
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
		return p.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
			ID: pl.ID, TenantID: e.TenantID, RunID: pl.RunID, SourceID: pl.SourceID,
			Kind: pl.Kind, Ref: pl.Ref, Provenance: pl.Provenance, Fingerprint: pl.Fingerprint,
			RiskScore: pl.RiskScore, Metadata: pl.Metadata, DiscoveredAt: e.Time,
		})
	case EventDiscoveryFindingTriageChanged:
		var pl DiscoveryFindingTriageChanged
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyDiscoveryFindingTriageChangedTx(ctx, tx, store.DiscoveryFindingTriageChange{
			TenantID: e.TenantID, FindingID: pl.ID, Status: pl.Status,
			ManagedIdentityID: pl.ManagedIdentityID, Actor: pl.Actor, Reason: pl.Reason,
			ChangedAt: e.Time,
		})
	case EventDiscoveryRunCompleted:
		var pl DiscoveryRunCompleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		completedAt := e.Time
		return p.store.ApplyDiscoveryRunCompletedTx(ctx, tx, store.DiscoveryRun{
			ID: pl.ID, TenantID: e.TenantID, Status: pl.Status, Targets: pl.Targets,
			Discovered: pl.Discovered, Failed: pl.Failed, Rejected: pl.Rejected,
			Error: pl.Error, CompletedAt: &completedAt,
		})
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
		}, e.Time)
	case EventPQCMigrationStarted:
		var pl PQCMigrationStarted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.RunID == "" || len(pl.AssetIDs) == 0 || pl.TargetAlgorithm == "" || pl.Protocol == "" {
			return fmt.Errorf("projections: %s requires run_id, asset_ids, target_algorithm, and protocol", e.Type)
		}
		return nil
	case EventPQCMigrationAssetCompleted:
		var pl PQCMigrationAssetCompleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.RunID == "" || pl.AssetID == "" || pl.Kind == "" || pl.Location == "" || pl.EffectiveAlgorithm == "" {
			return fmt.Errorf("projections: %s requires run_id, asset_id, kind, location, and effective_algorithm", e.Type)
		}
		reasons := []string{"PQC migration run " + pl.RunID + " re-issued through " + pl.Protocol}
		return p.store.ApplyCryptoAssetMigratedTx(ctx, tx, store.CryptoAsset{
			ID: pl.AssetID, TenantID: e.TenantID, Kind: pl.Kind, Location: pl.Location,
			Algorithm: pl.EffectiveAlgorithm, KeyBits: pl.EffectiveKeyBits, Library: pl.OriginalLibrary,
			Strength: "strong", QuantumVulnerable: false, OutOfPolicy: false, Reasons: reasons,
		}, e.Time)
	case EventPQCMigrationRollbackCompleted:
		var pl PQCMigrationRollbackCompleted
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
		}, e.Time)
	case EventConnectorDeliveryRecorded:
		var pl ConnectorDeliveryRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Status == "" {
			return fmt.Errorf("projections: %s requires id and status", e.Type)
		}
		return p.store.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
			ID: pl.ID, TenantID: e.TenantID, OutboxID: pl.OutboxID, IdentityID: pl.IdentityID,
			Destination: pl.Destination, Connector: pl.Connector, Target: pl.Target,
			Fingerprint: pl.Fingerprint, Status: pl.Status, Attempts: pl.Attempts,
			Reason: pl.Reason, Detail: pl.Detail, RollbackRef: pl.RollbackRef,
			IdempotencyKey: pl.IdempotencyKey, CreatedAt: e.Time, UpdatedAt: e.Time,
		})
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
		}, e.Time)
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
			Status: pl.Status, Phase: pl.Phase, Reason: pl.Reason, BatchSize: pl.BatchSize,
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
		return p.store.ApplyRemediationPlaybookRunRecordedTx(ctx, tx, store.RemediationPlaybookRun{
			ID: pl.ID, TenantID: e.TenantID, PlaybookID: pl.PlaybookID,
			TargetIdentityID: pl.TargetIdentityID, InventoryID: pl.InventoryID,
			Status: pl.Status, Phase: pl.Phase, Action: pl.Action, Reason: pl.Reason,
			Connector: pl.Connector, Target: pl.Target, OutboxID: pl.OutboxID,
			ConnectorDeliveryID: pl.ConnectorDeliveryID, ScopeDelta: pl.ScopeDelta,
			EvidenceRefs: pl.EvidenceRefs, RollbackRefs: pl.RollbackRefs,
			IdempotencyKey: pl.IdempotencyKey, CreatedBy: pl.CreatedBy,
			CreatedAt: e.Time, UpdatedAt: e.Time,
		})
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
		if pl.SubjectRef == "" {
			return fmt.Errorf("projections: %s requires subject_ref", e.Type)
		}
		return p.store.ApplyPrivacySubjectErasedTx(ctx, tx, store.PrivacySubjectErasure{
			TenantID:       e.TenantID,
			SubjectRef:     pl.SubjectRef,
			RequestedByRef: pl.RequestedByRef,
			Reason:         pl.Reason,
			Selectors:      pl.Selectors,
			Counts:         pl.Counts,
			ErasedAt:       e.Time,
		})
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
	return log.Replay(ctx, 0, func(e events.Event) error {
		return p.Apply(ctx, e)
	})
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
	// Serialize the catch-up across replicas under the projection advisory lock
	// (RESIL-004): N replicas booting at once each run this, and without
	// coordination they would replay into the same read-model tables concurrently.
	// The lock makes the second replica wait, then resume from the advanced
	// checkpoint with little or nothing left to apply, so a non-idempotent apply
	// ordering cannot interleave between two projectors.
	return p.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		from, err := p.store.ProjectionCheckpoint(ctx)
		if err != nil {
			return fmt.Errorf("projections: read checkpoint: %w", err)
		}
		var last uint64
		sinceCheckpoint := 0
		if err := log.Replay(ctx, from+1, func(e events.Event) error {
			if err := p.Apply(ctx, e); err != nil {
				return err
			}
			last = e.Sequence
			sinceCheckpoint++
			if sinceCheckpoint >= checkpointEvery {
				if err := p.store.AdvanceProjectionCheckpoint(ctx, last); err != nil {
					return err
				}
				sinceCheckpoint = 0
			}
			return nil
		}); err != nil {
			return err
		}
		if last > 0 {
			if err := p.store.AdvanceProjectionCheckpoint(ctx, last); err != nil {
				return fmt.Errorf("projections: advance checkpoint: %w", err)
			}
		}
		return nil
	})
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
	return p.store.RebuildReadModelTx(ctx, func(tx pgx.Tx) error {
		// A full rebuild re-derives from sequence 0, so the projection checkpoint
		// (SPINE-007) is reset to 0 in the SAME transaction as the truncate+replay.
		// This keeps the watermark consistent with the rebuilt read model: a crash
		// mid-rebuild rolls back both, and after a successful rebuild the next boot's
		// ProjectCatchUp resumes from the rebuilt head (advanced below).
		if err := p.store.ResetProjectionCheckpointTx(ctx, tx); err != nil {
			return err
		}
		var last uint64
		if err := log.Replay(ctx, 0, func(e events.Event) error {
			if err := p.applyForRebuild(ctx, tx, e); err != nil {
				return err
			}
			last = e.Sequence
			return nil
		}); err != nil {
			return err
		}
		if last > 0 {
			if err := p.store.SetProjectionCheckpointTx(ctx, tx, last); err != nil {
				return err
			}
		}
		return nil
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
// ignored on boot in favor of a full replay. Snapshot takes the projection advisory
// lock so it cannot race a concurrent catch-up on a multi-replica deployment — the
// checkpoint and the captured rows are read consistently (RESIL-004), and only the
// leader runs the periodic snapshot worker anyway.
//
// Per-tenant capture is tenant-scoped under RLS (AN-1): WriteTenantSnapshot runs in
// the tenant's RLS context, so a tenant's snapshot can only ever hold that tenant's
// rows. It returns the number of tenants snapshotted.
func (p *Projector) Snapshot(ctx context.Context) (int, error) {
	var n int
	err := p.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		covered, err := p.store.ProjectionCheckpoint(ctx)
		if err != nil {
			return fmt.Errorf("projections: read checkpoint for snapshot: %w", err)
		}
		tenants, err := p.store.ListTenants(ctx)
		if err != nil {
			return fmt.Errorf("projections: list tenants for snapshot: %w", err)
		}
		for _, t := range tenants {
			if err := p.store.WriteTenantSnapshot(ctx, t.TenantID, covered); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
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
		txErr := p.store.RestoreReadModelTx(ctx, func(tx pgx.Tx) error {
			if _, rerr := p.store.RestoreSnapshotsTx(ctx, tx); rerr != nil {
				return rerr
			}
			if serr := p.store.SetProjectionCheckpointTx(ctx, tx, from); serr != nil {
				return serr
			}
			var last uint64
			if rerr := log.Replay(ctx, from+1, func(e events.Event) error {
				if aerr := p.applyForRebuild(ctx, tx, e); aerr != nil {
					return aerr
				}
				last = e.Sequence
				return nil
			}); rerr != nil {
				return rerr
			}
			if last > from {
				if serr := p.store.SetProjectionCheckpointTx(ctx, tx, last); serr != nil {
					return serr
				}
			}
			return nil
		})
		if txErr != nil {
			// The snapshot path failed (e.g. a corrupt payload). The log is the source of
			// truth, so fall back to a full rebuild from sequence 0 rather than serving a
			// partially-restored read model. Rebuild is itself atomic and resets the
			// checkpoint; we keep handled == true so the caller does not double-catch-up.
			return p.Rebuild(ctx, log)
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
