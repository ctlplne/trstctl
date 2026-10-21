// SPDX-License-Identifier: BUSL-1.1

package projections

import "time"

const (
	EventACMEUpstreamARIRequested = "acme.upstream_ari.fetch_requested"
	EventACMEUpstreamARIObserved  = "acme.upstream_ari.observed"

	// ACMEUpstreamARIProvenanceAuthenticatedIssuer: the leaf's issuer is an
	// authenticated issuance fact (certificates.issuing_external_ca_id). An
	// absent provenance on an older event means this.
	ACMEUpstreamARIProvenanceAuthenticatedIssuer = "authenticated_issuer"
	// ACMEUpstreamARIProvenanceIssuerKeyID: a discovered leaf matched to the
	// authority by its Authority Key Identifier against the operator-declared
	// ari_issuer_key_ids (A51). The leaf has no authenticated issuer.
	ACMEUpstreamARIProvenanceIssuerKeyID = "issuer_key_id"
)

// NormalizeACMEUpstreamARIProvenance maps an absent provenance to the
// authenticated default and rejects anything outside the closed set.
func NormalizeACMEUpstreamARIProvenance(raw string) (string, bool) {
	switch raw {
	case "", ACMEUpstreamARIProvenanceAuthenticatedIssuer:
		return ACMEUpstreamARIProvenanceAuthenticatedIssuer, true
	case ACMEUpstreamARIProvenanceIssuerKeyID:
		return ACMEUpstreamARIProvenanceIssuerKeyID, true
	}
	return "", false
}

// ACMEUpstreamARIRequested is the public, tenant-bound command that queues an
// unauthenticated ARI GET. The projector writes its outbox intent atomically.
type ACMEUpstreamARIRequested struct {
	CertificateID    string `json:"certificate_id"`
	AuthorityID      string `json:"authority_id"`
	ARICertificateID string `json:"ari_certificate_id"`
	Fingerprint      string `json:"fingerprint"`
	// Provenance says how the leaf was tied to the authority (A51); empty on
	// events written before discovered leaves could be polled.
	Provenance string `json:"provenance,omitempty"`
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
	Provenance       string     `json:"provenance,omitempty"`
}
