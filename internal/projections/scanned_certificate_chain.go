// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A211: the issuer certificates a network scan saw served with a leaf.
const EventScannedCertificateChainObserved = "discovery.certificate_chain.observed"

// ScannedCertificateChainObserved names a leaf by fingerprint and carries the
// public issuer certificates served after it, each with its SHA-256.
type ScannedCertificateChainObserved struct {
	LeafFingerprint string                  `json:"leaf_fingerprint"`
	Issuers         []ScannedChainIssuerDER `json:"issuers"`
}

// ScannedChainIssuerDER is one served issuer certificate.
type ScannedChainIssuerDER struct {
	SHA256         string `json:"sha256"`
	CertificateDER []byte `json:"certificate_der"`
}

var lowerSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateScannedCertificateChain checks the bounds and that every issuer's
// bytes hash to the digest it names.
func ValidateScannedCertificateChain(pl ScannedCertificateChainObserved) error {
	if !lowerSHA256.MatchString(pl.LeafFingerprint) || len(pl.Issuers) == 0 || len(pl.Issuers) > 4 {
		return errors.New("a scanned chain names its leaf and one to four issuers")
	}
	for _, issuer := range pl.Issuers {
		if len(issuer.CertificateDER) == 0 || len(issuer.CertificateDER) > 16<<10 ||
			crypto.SHA256Hex(issuer.CertificateDER) != issuer.SHA256 {
			return errors.New("a scanned issuer's bytes do not match its digest or exceed the bound")
		}
	}
	return nil
}

func (p *Projector) applyScannedCertificateChainTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventScannedCertificateChainObserved {
		return false, nil
	}
	var pl ScannedCertificateChainObserved
	if err := decode(e, &pl); err != nil {
		return true, err
	}
	if err := ValidateScannedCertificateChain(pl); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	issuers := make([]store.ScannedIssuer, 0, len(pl.Issuers))
	for i, issuer := range pl.Issuers {
		issuers = append(issuers, store.ScannedIssuer{Position: i + 1, CertificateDER: issuer.CertificateDER, SHA256: issuer.SHA256})
	}
	return true, p.store.ApplyScannedCertificateChainTx(ctx, tx, e.TenantID, pl.LeafFingerprint, issuers, e.Time, e.Sequence)
}
