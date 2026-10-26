// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A145: the timestamping authority's certificate is an ordinary entry of its
// issuing CA's ledger, so the CA's CRL and OCSP responder answer for it, and an
// operator can revoke it. Registration happens when the server mints or loads
// a TSA certificate; revocation when an operator rotates the TSA away from a
// certificate with a reason, or revokes a certificate already rotated out.
const (
	EventTSACertificateRegistered = "tsa.certificate.registered"
	EventTSACertificateRevoked    = "tsa.certificate.revoked"
)

// TSACertificateRegistered records a TSA certificate in its CA's ledger.
type TSACertificateRegistered struct {
	CAID      string    `json:"ca_id"`
	Serial    string    `json:"serial"`
	Handle    string    `json:"handle"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	CertDER   []byte    `json:"cert_der"`
}

// TSACertificateRevoked revokes a registered TSA certificate.
type TSACertificateRevoked struct {
	CAID       string    `json:"ca_id"`
	Serial     string    `json:"serial"`
	ReasonCode int       `json:"reason_code"`
	RevokedAt  time.Time `json:"revoked_at"`
}

var tsaSerialRE = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

// ValidateTSACertificateRegistered checks the payload against the certificate
// it carries: the serial and validity are the certificate's own, and it is a
// timestamping end entity.
func ValidateTSACertificateRegistered(pl TSACertificateRegistered) error {
	if pl.CAID == "" || pl.Handle == "" || !tsaSerialRE.MatchString(pl.Serial) || len(pl.CertDER) == 0 {
		return errors.New("tsa certificate registration is incomplete")
	}
	info, err := certinfo.Inspect(pl.CertDER)
	if err != nil {
		return fmt.Errorf("tsa certificate: %w", err)
	}
	if info.SerialNumber != pl.Serial || !info.NotBefore.Equal(pl.NotBefore) || !info.NotAfter.Equal(pl.NotAfter) {
		return errors.New("tsa certificate registration does not match the certificate it carries")
	}
	if info.IsCA || len(info.ExtKeyUsages) != 1 || info.ExtKeyUsages[0] != "timeStamping" {
		return errors.New("tsa certificate is not a timestamping end entity")
	}
	return nil
}

func (p *Projector) applyTSACertificateTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventTSACertificateRegistered:
		var pl TSACertificateRegistered
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateTSACertificateRegistered(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		if err := p.store.RecordIssuedCertEventTx(ctx, tx, e, pl.CAID, pl.Serial, pl.NotBefore); err != nil {
			return true, err
		}
		return true, p.store.ApplyTSACertificateRegisteredTx(ctx, tx, store.TSACertificate{
			TenantID: e.TenantID, Serial: pl.Serial, CAID: pl.CAID, Handle: pl.Handle, CertDER: pl.CertDER,
			CertSHA256: crypto.SHA256Hex(pl.CertDER), NotBefore: pl.NotBefore, NotAfter: pl.NotAfter,
			RegisteredAt: e.Time, EventSequence: e.Sequence,
		})
	case EventTSACertificateRevoked:
		var pl TSACertificateRevoked
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.CAID == "" || !tsaSerialRE.MatchString(pl.Serial) || pl.RevokedAt.IsZero() || !crypto.ValidCRLReasonCode(pl.ReasonCode) {
			return true, fmt.Errorf("projections: %s: revocation is incomplete", e.Type)
		}
		if err := p.store.RevokeIssuedCertTx(ctx, tx, e.TenantID, pl.CAID, pl.Serial, pl.ReasonCode, pl.RevokedAt); err != nil {
			return true, err
		}
		return true, p.store.ApplyTSACertificateRevokedTx(ctx, tx, e.TenantID, pl.Serial, pl.ReasonCode, pl.RevokedAt)
	}
	return false, nil
}
