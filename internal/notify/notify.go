// SPDX-License-Identifier: MPL-2.0

// Package notify defines the shared notification surface that trstctl emits
// operational alerts to. Expiration alerts (F6) are the first producer; later
// features (CT monitoring F17, drift detection F18) emit to the same surface,
// and channel integrations (Slack, Teams, email, ... F29) consume it.
//
// An alert is delivered through the outbox (AN-6): the producer enqueues an
// Alert as the JSON payload of an entry on the notification.* destination
// namespace, in the same transaction as the state change that raised it, and a
// dispatcher delivers it. This package is just the shared vocabulary — the
// destination names and the Alert payload — so producers and consumers agree.
package notify

import "time"

// Outbox destinations in the notification surface.
const (
	// DestinationExpiry carries certificate-expiration alerts (F6).
	DestinationExpiry = "notification.expiry"
	// DestinationCTLog carries Certificate Transparency monitoring alerts
	// (F17) — a sibling destination on the same notification surface, so the
	// same channel integrations (Slack, Teams, email, ... F29) consume both.
	DestinationCTLog = "notification.ct"
	// DestinationVerification carries endpoint verification divergence (D2):
	// the listener is not serving what was deployed. It is the first alert in
	// this product sourced from an OBSERVATION rather than from trstctl's own
	// records, which is why it can fire when every delivery receipt is green.
	DestinationVerification = "notification.verification"
	// DestinationDrift carries credential drift alerts (F18) through the same
	// notification fanout as expiry and CT monitoring.
	DestinationDrift = "notification.drift"
	// DestinationResponse carries incident-response integration alerts (CAP-REM-03)
	// through the same outbox-backed notification fanout as expiry, CT, and drift.
	DestinationResponse = "notification.response"
	// DestinationTest carries operator-requested channel test alerts.
	DestinationTest = "notification.test"
	// DestinationApproval carries dual-control approval requests. The approval
	// row and this delivery intent are committed in one PostgreSQL transaction;
	// channel delivery happens later in the bounded notification outbox worker.
	DestinationApproval = "notification.approval"
	// DestinationCAHorizon carries year-scale CA hierarchy expiry alerts (H5).
	// It is a sibling of DestinationExpiry rather than a reuse of it because the
	// two answer different questions on different clocks: expiry alerting asks
	// "renew this leaf this month", horizon alerting asks "start planning a trust
	// migration this year". Routing them separately lets an operator page on one
	// and file the other.
	DestinationCAHorizon = "notification.ca_horizon"
	// DestinationRevocation carries relay-verified CRL/OCSP freshness and
	// reachability failures (R1). It is separate so network and PKI teams can
	// route endpoint incidents independently from certificate expiry.
	DestinationRevocation = "notification.revocation"
	// DestinationOwnership carries initial and cadence-driven ownership
	// attestation requests (I1/AUD-44).
	DestinationOwnership = "notification.ownership"
	// DestinationRestoreDrill carries failed, skipped, or objective-breaching
	// disaster-recovery drill alerts (J2/AUD-54).
	DestinationRestoreDrill = "notification.restore_drill"
	// DestinationRisk carries canonical urgent-risk alerts. It is separate from
	// discovery delivery because the alert names the risk decision, while the
	// immutable discovery event remains its evidence source.
	DestinationRisk = "notification.risk"
)

// Alert kinds.
const (
	// KindCertificateExpiry marks an alert raised because a certificate is
	// approaching expiry.
	KindCertificateExpiry = "certificate.expiry"
	// KindUnexpectedIssuance marks an alert raised because a certificate was
	// found in a CT log for a watched domain that trstctl did not expect —
	// shadow IT or rogue issuance (F17).
	KindUnexpectedIssuance = "certificate.unexpected_issuance"
	// KindCredentialDrift marks an alert raised because a credential no longer
	// matches the state the agent/control plane declared.
	KindCredentialDrift = "credential.drift" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	// KindResponseIntegration marks an operator-dispatched incident/remediation
	// response packet for chat notification integrations.
	KindResponseIntegration = "response.integration"
	// KindNotificationChannelTest marks an operator-requested channel test.
	KindNotificationChannelTest = "notification.channel_test"
	// KindApprovalRequest marks a privileged action waiting for a distinct
	// approver. It contains routing metadata only, never credential material.
	KindApprovalRequest = "approval.requested"
	// KindCAHorizon marks a CA authority crossing into a tighter expiry band
	// (H5). Replacing a trust anchor is a quarters-long programme, so this fires
	// years ahead and again at each tightening.
	// KindEndpointVerificationFailed means a TLS handshake found a listener
	// serving something other than what was deployed (D2).
	//
	// Deliberately NOT KindCredentialDrift: that kind drives a file-repair
	// workflow keyed on a filesystem path, and a served-identity divergence has
	// no path to repair — the file is usually correct and the process never
	// reloaded it. Routing one into the other would send an operator to fix
	// something that is not broken.
	KindEndpointVerificationFailed = "endpoint.verification_failed"
	// KindEndpointUnreachable means a verification probe could not connect at
	// all. Separate from a divergence because the person who fixes a network
	// path is rarely the person who fixes a certificate.
	KindEndpointUnreachable = "endpoint.unreachable"
	KindCAHorizon           = "ca.horizon"
	// KindCAValidityCompression marks a CA authority whose remaining life is
	// shorter than the validity its leaves are supposed to receive. Issuance keeps
	// succeeding and the certificates just get quietly shorter, so this is the
	// only warning an operator gets before something downstream rejects one.
	KindCAValidityCompression = "ca.validity_compression"
	// KindRevocationHealth marks a CRL or OCSP endpoint whose signed evidence is
	// stale, nearing expiry, unreachable, or invalid.
	KindRevocationHealth       = "revocation.health"
	KindOwnershipReattestation = "ownership.reattestation_requested"
	KindRestoreDrillFailed     = "backup.restore_drill_failed"
	KindRestoreDrillSkipped    = "backup.restore_drill_skipped"
	KindRestoreDrillObjective  = "backup.restore_drill_objective_breached"
	KindUrgentRisk             = "risk.urgent"
)

// Alert severity tiers. Low is the safe fallback tier for unknown or missing
// severity values; informational is accepted as the certctl-compatible spelling.
const (
	AlertSeverityLow           = "low"
	AlertSeverityInformational = "informational"
	AlertSeverityWarning       = "warning"
	AlertSeverityCritical      = "critical"
)

// Alert is one operational alert on the notification surface — the JSON payload
// of a notification.* outbox entry.
type AlertRecipient struct {
	Kind        string   `json:"kind"`
	Subject     string   `json:"subject"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles,omitempty"`
}

type Alert struct {
	Kind     string `json:"kind"`
	TenantID string `json:"tenant_id"`
	// OperationID is the durable receiver identity for operator-triggered alerts.
	// It is namespaced and derived from the API idempotency key, so two distinct
	// commands with identical human-readable text do not collapse at PagerDuty or
	// OpsGenie. RequestBinding is a non-secret digest of the authenticated caller
	// and canonical command retained in the outbox payload after response-cache GC.
	OperationID          string           `json:"operation_id,omitempty"`
	RequestBinding       string           `json:"request_binding,omitempty"`
	CredentialConfigured bool             `json:"credential_configured,omitempty"`
	CertificateID        string           `json:"certificate_id,omitempty"`
	Subject              string           `json:"subject,omitempty"`
	Serial               string           `json:"serial,omitempty"`
	NotAfter             time.Time        `json:"not_after,omitempty"`
	Detail               string           `json:"detail,omitempty"`
	Severity             string           `json:"severity,omitempty"`
	RoutingPolicyID      string           `json:"routing_policy_id,omitempty"`
	TargetChannel        string           `json:"target_channel,omitempty"`
	ThresholdDays        *int             `json:"threshold_days,omitempty"`
	OwnerID              string           `json:"owner_id,omitempty"`
	OwnerName            string           `json:"owner_name,omitempty"`
	OwnerEmail           string           `json:"owner_email,omitempty"`
	EscalationRecipients []AlertRecipient `json:"escalation_recipients,omitempty"`

	// CA calendar fields (H5), set only on KindCAHorizon and
	// KindCAValidityCompression. AuthorityID names the CA rather than a
	// certificate; HorizonMonths is the band crossed (36/24/12/6/3, or 0 for an
	// authority already past its expiry); RenewBy is the date after which leaves
	// under this authority stop receiving their full validity; and
	// DependentCertificates says how much of the estate sits behind the anchor,
	// so the alert carries blast radius instead of naming a CA in isolation.
	// Endpoint verification fields (D2), set only on the endpoint kinds.
	// EndpointAddress is the host:port that was handshaked; Vantage says
	// whether the serving host itself or a network relay observed it; Mismatch
	// names the divergence class. LastGoodAt is what turns an alert into a
	// judgement of severity — an endpoint that was good an hour ago and one
	// that has never once served correctly are different incidents.
	EndpointAddress string    `json:"endpoint_address,omitempty"`
	Vantage         string    `json:"vantage,omitempty"`
	Mismatch        string    `json:"mismatch,omitempty"`
	LastGoodAt      time.Time `json:"last_good_at,omitempty"`

	AuthorityID           string    `json:"authority_id,omitempty"`
	AuthorityKind         string    `json:"authority_kind,omitempty"`
	HorizonMonths         *int      `json:"horizon_months,omitempty"`
	RenewBy               time.Time `json:"renew_by,omitempty"`
	DependentCertificates *int      `json:"dependent_certificates,omitempty"`
}
