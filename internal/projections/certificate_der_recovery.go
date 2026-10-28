// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventCertificateDERRecovered gives an inventory row that held no
// certificate bytes the bytes of the certificate it names (A215).
const EventCertificateDERRecovered = "certificate.der.recovered"

// maxRecoveredDER bounds a recovered certificate.
const maxRecoveredDER = 64 << 10

// CertificateDERRecovered is the recovered certificate and where it was found:
// the mint event that retained it, or the endpoint address that served it.
type CertificateDERRecovered struct {
	CertificateID  string `json:"certificate_id"`
	Fingerprint    string `json:"fingerprint"`
	Method         string `json:"method"`
	Evidence       string `json:"evidence"`
	CertificateDER []byte `json:"certificate_der"`
}

// ValidateCertificateDERRecovered accepts only bytes that hash to the row's
// fingerprint: nothing is attached from names or serials alone.
func ValidateCertificateDERRecovered(pl CertificateDERRecovered) error {
	if !canonicalUUID(pl.CertificateID) || !lowerSHA256.MatchString(pl.Fingerprint) {
		return errors.New("a recovered certificate names its inventory row and fingerprint")
	}
	if pl.Method != store.DERRecoveredFromCALedger && pl.Method != store.DERRecoveredFromEndpoint {
		return errors.New("a recovered certificate names how it was found")
	}
	if pl.Evidence == "" || len(pl.Evidence) > 512 {
		return errors.New("a recovered certificate names the mint or endpoint it came from")
	}
	if len(pl.CertificateDER) == 0 || len(pl.CertificateDER) > maxRecoveredDER ||
		crypto.SHA256Hex(pl.CertificateDER) != pl.Fingerprint {
		return errors.New("recovered certificate bytes must hash to the row's fingerprint")
	}
	return nil
}

func (p *Projector) applyCertificateDERRecoveredTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventCertificateDERRecovered {
		return false, nil
	}
	var pl CertificateDERRecovered
	if err := decode(e, &pl); err != nil {
		return true, err
	}
	if err := ValidateCertificateDERRecovered(pl); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	return true, p.store.ApplyCertificateDERRecoveredTx(ctx, tx, store.CertificateDERRecovery{
		TenantID: e.TenantID, Fingerprint: pl.Fingerprint, Method: pl.Method, Evidence: pl.Evidence,
		RecoveredAt: e.Time, EventSequence: e.Sequence,
	}, pl.CertificateDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pl.CertificateDER}))
}
