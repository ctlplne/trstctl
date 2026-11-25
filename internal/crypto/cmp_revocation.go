// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// VerifyCMPProtectionCRLs checks every certificate below an external trust
// anchor against a current CRL signed by its actual issuer. chainDER must be
// the path returned by X.509 verification, leaf first. A direct anchor pin has
// no issuer below the anchor; removing the pin is its revocation operation.
func VerifyCMPProtectionCRLs(chainDER, crlsDER [][]byte, now time.Time) error {
	if len(chainDER) == 0 {
		return errors.New("cmp: protection chain is empty")
	}
	if len(chainDER) == 1 {
		return nil
	}
	for i := 0; i < len(chainDER)-1; i++ {
		child, err := x509.ParseCertificate(chainDER[i])
		if err != nil {
			return fmt.Errorf("cmp: parse protection chain member %d: %w", i, err)
		}
		issuer, err := x509.ParseCertificate(chainDER[i+1])
		if err != nil {
			return fmt.Errorf("cmp: parse protection chain issuer %d: %w", i, err)
		}
		if err := VerifyCertificateIssuedBy(child, issuer); err != nil {
			return fmt.Errorf("cmp: protection chain signature: %w", err)
		}
		matches := 0
		for _, der := range crlsDER {
			rl, err := x509.ParseRevocationList(der)
			if err != nil {
				return fmt.Errorf("cmp: parse protection CRL: %w", err)
			}
			if !bytes.Equal(rl.RawIssuer, issuer.RawSubject) {
				continue
			}
			if len(rl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(rl.AuthorityKeyId, issuer.SubjectKeyId) {
				continue
			}
			matches++
			if matches > 1 {
				return errors.New("cmp: multiple CRLs for one protection issuer")
			}
			info, err := ParseCRL(der, issuer.Raw)
			if err != nil {
				return fmt.Errorf("cmp: verify protection CRL: %w", err)
			}
			if info.HasDeltaCRLIndicator || len(info.IssuingDistributionPointURLs) > 0 {
				return errors.New("cmp: scoped or delta CRL cannot prove complete protection status")
			}
			if info.ThisUpdate.After(now) || !info.NextUpdate.After(now) || !info.NextUpdate.After(info.ThisUpdate) {
				return errors.New("cmp: protection CRL is not current")
			}
			for _, revoked := range info.RevokedSerials {
				if revoked == child.SerialNumber.Text(16) {
					return errors.New("cmp: protection certificate is revoked")
				}
			}
		}
		if matches == 0 {
			return errors.New("cmp: no issuer CRL covers the protection certificate")
		}
	}
	return nil
}
