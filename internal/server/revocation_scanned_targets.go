// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/revocationhealth"
	"trstctl.com/trstctl/internal/store"
)

// maxScannedRevocationLeaves bounds the certificates known only from scans a
// tenant's sweep checks for their own serial.
const maxScannedRevocationLeaves = 256

// scannedRevocationTargets gives each certificate known only from a scan, whose
// public bytes the scan kept, its own probe targets (A211): one per CRL
// distribution point and OCSP responder, keyed by the certificate, so its own
// serial is checked rather than a representative's. The issuer is a served
// issuer the scan kept, else a known one, and must verify the leaf's
// signature; a leaf no issuer verifies is not probed.
func (s *Server) scannedRevocationTargets(ctx context.Context, tenantID string, certificates []store.Certificate,
	known []revocationIssuer) ([]revocationhealth.Target, error) {
	var leaves []store.Certificate
	for _, certificate := range certificates {
		if len(leaves) == maxScannedRevocationLeaves {
			break
		}
		if certificate.Status == "active" && len(certificate.CertificateDER) > 0 &&
			strings.HasPrefix(certificate.Source, "discovery:") {
			leaves = append(leaves, certificate)
		}
	}
	if len(leaves) == 0 {
		return nil, nil
	}
	fingerprints := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		fingerprints = append(fingerprints, strings.ToLower(leaf.Fingerprint))
	}
	chains, err := s.store.ScannedCertificateChains(ctx, tenantID, fingerprints)
	if err != nil {
		return nil, err
	}
	var targets []revocationhealth.Target
	for _, certificate := range leaves {
		leafDER, err := certinfo.LeafDER(certificate.CertificateDER)
		if err != nil {
			continue
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil || info.IsCA {
			continue
		}
		issuer := scannedLeafIssuer(leafDER, info.Issuer, chains[strings.ToLower(certificate.Fingerprint)], known)
		if len(issuer.DER) == 0 {
			continue
		}
		for _, endpoint := range info.CRLDistributionPoints {
			targets = append(targets, scannedRevocationTarget(certificate, info, leafDER, issuer, revocationhealth.ProtocolCRL, endpoint))
		}
		for _, endpoint := range info.OCSPServers {
			targets = append(targets, scannedRevocationTarget(certificate, info, leafDER, issuer, revocationhealth.ProtocolOCSP, endpoint))
		}
	}
	return targets, nil
}

// scannedLeafIssuer picks the issuer that verifies the leaf: first among the
// issuers the scan saw served with it, then among the tenant's known issuers.
func scannedLeafIssuer(leafDER []byte, issuerSubject string, served []store.ScannedIssuer, known []revocationIssuer) revocationIssuer {
	for _, candidate := range served {
		info, err := certinfo.Inspect(candidate.CertificateDER)
		if err == nil && info.IsCA && crypto.VerifyLeafSignedByCA(leafDER, candidate.CertificateDER) == nil {
			return revocationIssuer{Subject: info.Subject, Fingerprint: info.SHA256Fingerprint, DER: candidate.CertificateDER}
		}
	}
	return matchRevocationIssuer(leafDER, issuerSubject, known)
}

func scannedRevocationTarget(certificate store.Certificate, info certinfo.Info, leafDER []byte, issuer revocationIssuer,
	protocol, endpoint string) revocationhealth.Target {
	target := buildRevocationTarget(certificate, info, leafDER, issuer, protocol, endpoint)
	target.Key = crypto.SHA256Hex([]byte("certificate\x00" + protocol + "\x00" + strings.TrimSpace(endpoint) + "\x00" + info.SHA256Fingerprint))
	target.Scope = revocationhealth.ScopeCertificate
	return target
}
