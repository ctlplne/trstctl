// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	corestore "trstctl.com/trstctl/internal/store"
)

// External CA ledgers (A218).
//
// An EJBCA or step-ca deployment records every certificate it issues and every
// revocation. Each becomes an authority that asserts those certificates in the
// shared vocabulary the store-backed authorities use: identity from the
// certificate's own DER (issuer name bytes and serial) and standing (active or
// revoked). Its counterpart is an inventory authority, the certificate
// inventory scoped to the same CAs. A round between the two witnesses drift
// both ways: a certificate the CA issued that the inventory lacks, one the
// inventory holds that the CA never recorded, and a revocation only one side
// knows.
//
// JURISDICTION. Both sides read the CAs named in the same issuer certificates
// file (a PEM bundle of the CA certificates) and only certificates unexpired at
// the observation: an EJBCA search for certificates in use leaves archived ones
// out, so comparing expired certificates would report EJBCA's housekeeping as
// drift.

// InventoryAuthorityConfig is an inventory authority: the certificate
// inventory's view of the CAs in IssuerCertificatesFile.
type InventoryAuthorityConfig struct {
	AuthorityID            string
	IssuerCertificatesFile string
}

var errCASourceConfig = errors.New("xrec ca source: configuration")

func newStoreInventoryJurisdictionSource(store *corestore.Store, cfg InventoryAuthorityConfig) (*storeInventorySource, error) {
	cfg.AuthorityID = strings.TrimSpace(cfg.AuthorityID)
	if cfg.AuthorityID == "" || strings.TrimSpace(cfg.IssuerCertificatesFile) == "" {
		return nil, fmt.Errorf("%w: an inventory authority needs an id and an issuer certificates file", errCASourceConfig)
	}
	file := strings.TrimSpace(cfg.IssuerCertificatesFile)
	return &storeInventorySource{
		store:         store,
		issuers:       func(context.Context, string) (map[string]struct{}, error) { return loadCAJurisdiction(file) },
		unexpiredOnly: true,
		watermark:     "inventory:" + cfg.AuthorityID,
	}, nil
}

// loadCAJurisdiction reads the issuer certificates file at each observation,
// so a rotated CA bundle applies to the next round, and returns the subject
// names of its certificates: the issuer names of what those CAs sign.
func loadCAJurisdiction(file string) (map[string]struct{}, error) {
	raw, err := os.ReadFile(file) // #nosec G304 -- operator-configured CA certificate bundle path (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("xrec ca source: read issuer certificates: %w", err)
	}
	names, err := crypto.CertificateSubjectNameDERsFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("xrec ca source: issuer certificates: %w", err)
	}
	out := make(map[string]struct{}, len(names))
	for _, name := range names {
		out[string(name)] = struct{}{}
	}
	return out, nil
}
