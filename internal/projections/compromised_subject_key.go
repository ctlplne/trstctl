// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

// EventCertificateSubjectKeyCompromised records one certificate's subject key
// as compromised when the certificate's identity is revoked with reason
// keyCompromise (owner decision, batch 14). The certificate itself is revoked
// later, when revocation.publish delivers; recording its key at the transition
// means issuance refuses that key from the moment of the compromise report,
// not from the moment of the publication. The event carries the key's SPKI
// SHA-256, so its projection reads no other row.
const EventCertificateSubjectKeyCompromised = "certificate.subject_key.compromised"

type CertificateSubjectKeyCompromised struct {
	IdentityID  string `json:"identity_id"`
	Fingerprint string `json:"fingerprint"`
	SPKISHA256  string `json:"spki_sha256"`
}

// CertificateSubjectKeyCompromisedEventID gives one certificate of one revoked
// identity a retry-stable event identity, so a retried command records nothing
// twice.
func CertificateSubjectKeyCompromisedEventID(tenantID, identityID, fingerprint string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("certificate-subject-key-compromised\x00"+tenantID+"\x00"+identityID+"\x00"+fingerprint)).String()
}

func ValidateCertificateSubjectKeyCompromised(record CertificateSubjectKeyCompromised) error {
	if id, err := uuid.Parse(record.IdentityID); err != nil || id.String() != record.IdentityID ||
		!revocationDigest(record.Fingerprint) || !revocationDigest(record.SPKISHA256) {
		return errors.New("projections: compromised subject key record is incomplete")
	}
	return nil
}

// The row is insert-only and keyed by certificate, so the publish's own
// recording, when the certificate's revocation projects, converges on it.
func (p *Projector) applyCertificateSubjectKeyCompromisedTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	var record CertificateSubjectKeyCompromised
	if err := decode(e, &record); err != nil {
		return err
	}
	if err := ValidateCertificateSubjectKeyCompromised(record); err != nil {
		return err
	}
	if e.ID != CertificateSubjectKeyCompromisedEventID(e.TenantID, record.IdentityID, record.Fingerprint) || e.Time.IsZero() {
		return errors.New("projections: compromised subject key record has no retry-stable identity")
	}
	return p.store.RecordCompromisedSubjectKeyTx(ctx, tx, e.TenantID, record.Fingerprint, record.SPKISHA256, e.Time)
}
