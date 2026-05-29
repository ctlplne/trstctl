// Package notify defines the shared notification surface that certctl emits
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
)

// Alert kinds.
const (
	// KindCertificateExpiry marks an alert raised because a certificate is
	// approaching expiry.
	KindCertificateExpiry = "certificate.expiry"
)

// Alert is one operational alert on the notification surface — the JSON payload
// of a notification.* outbox entry.
type Alert struct {
	Kind          string    `json:"kind"`
	TenantID      string    `json:"tenant_id"`
	CertificateID string    `json:"certificate_id,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Serial        string    `json:"serial,omitempty"`
	NotAfter      time.Time `json:"not_after,omitempty"`
	Detail        string    `json:"detail,omitempty"`
}
