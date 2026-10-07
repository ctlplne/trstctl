// SPDX-License-Identifier: BUSL-1.1

package projections

import "time"

const (
	EventACMEUpstreamARIRequested = "acme.upstream_ari.fetch_requested"
	EventACMEUpstreamARIObserved  = "acme.upstream_ari.observed"
)

// ACMEUpstreamARIRequested is the public, tenant-bound command that queues an
// unauthenticated ARI GET. The projector writes its outbox intent atomically.
type ACMEUpstreamARIRequested struct {
	CertificateID    string `json:"certificate_id"`
	AuthorityID      string `json:"authority_id"`
	ARICertificateID string `json:"ari_certificate_id"`
	Fingerprint      string `json:"fingerprint"`
}

// ACMEUpstreamARIObserved records either the CA window or a closed error class.
// Arbitrary upstream response text and URLs are never retained in this event.
type ACMEUpstreamARIObserved struct {
	CertificateID    string     `json:"certificate_id"`
	AuthorityID      string     `json:"authority_id"`
	ARICertificateID string     `json:"ari_certificate_id"`
	Fingerprint      string     `json:"fingerprint"`
	Status           string     `json:"status"`
	WindowStart      *time.Time `json:"window_start,omitempty"`
	WindowEnd        *time.Time `json:"window_end,omitempty"`
	NextPollAt       time.Time  `json:"next_poll_at"`
	FailureCount     int        `json:"failure_count"`
	ErrorClass       string     `json:"error_class,omitempty"`
}
