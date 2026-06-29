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
	// DestinationDrift carries credential drift alerts (F18) through the same
	// notification fanout as expiry and CT monitoring.
	DestinationDrift = "notification.drift"
	// DestinationResponse carries incident-response integration alerts (CAP-REM-03)
	// through the same outbox-backed notification fanout as expiry, CT, and drift.
	DestinationResponse = "notification.response"
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
	KindCredentialDrift = "credential.drift"
	// KindResponseIntegration marks an operator-dispatched incident/remediation
	// response packet for chat notification integrations.
	KindResponseIntegration = "response.integration"
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
	Kind                 string           `json:"kind"`
	TenantID             string           `json:"tenant_id"`
	CertificateID        string           `json:"certificate_id,omitempty"`
	Subject              string           `json:"subject,omitempty"`
	Serial               string           `json:"serial,omitempty"`
	NotAfter             time.Time        `json:"not_after,omitempty"`
	Detail               string           `json:"detail,omitempty"`
	Severity             string           `json:"severity,omitempty"`
	RoutingPolicyID      string           `json:"routing_policy_id,omitempty"`
	ThresholdDays        *int             `json:"threshold_days,omitempty"`
	OwnerID              string           `json:"owner_id,omitempty"`
	OwnerName            string           `json:"owner_name,omitempty"`
	OwnerEmail           string           `json:"owner_email,omitempty"`
	EscalationRecipients []AlertRecipient `json:"escalation_recipients,omitempty"`
}
