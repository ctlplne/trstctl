// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/protocols/cmp"
)

// cmpQualificationSource exposes only secret-free, in-memory facts from the
// exact served process. It deliberately closes over the Server because the API
// is assembled before protocol mounts are built; requests cannot arrive until
// Build finishes and s.protocols contains the final mount generation.
type cmpQualificationSource struct {
	server        *Server
	configured    bool
	configuredFor string
	allowRA       bool
}

func newCMPQualificationSource(s *Server, protocols config.Protocols, tenantFallback string) cmpQualificationSource {
	return cmpQualificationSource{
		server:        s,
		configured:    protocols.CMP.Enabled,
		configuredFor: firstNonEmpty(protocols.CMP.TenantID, tenantFallback),
		allowRA:       protocols.CMPAllowRAEnrollment,
	}
}

func (s *Server) appendCMPQualificationOption(d Deps, options *[]api.Option) {
	source := newCMPQualificationSource(s, d.Protocols, d.ProtocolTenant)
	*options = append(*options, api.WithCMPQualificationPosture(source.read))
}

func (s *Server) buildServedCMP(cfg config.Protocols, tenantFallback string, issuer *protocolIssuer, raCertDER, raKeyPKCS8 []byte, pool *bulkhead.Pool, sp *servedProtocols) error {
	sp.cmpTenant = firstNonEmpty(cfg.CMP.TenantID, tenantFallback)
	// CMP's protection identity travels in the message's own extraCerts, so it
	// authenticates nothing until it chains to an operator-configured anchor.
	// Unset anchors leave the mount refusing to enroll (fail closed).
	cmpAnchors, err := loadCMPClientTrustAnchors(cfg.CMPClientTrustAnchorFile)
	if err != nil {
		return err
	}
	sp.cmp = cmp.New(cmp.Config{
		Enroller:              enrollerAdapter{tenantID: sp.cmpTenant, issuer: issuer},
		CACertDER:             raCertDER,
		CAKeyPKCS8:            raKeyPKCS8,
		Pool:                  pool,
		Log:                   s.log,
		ClientTrustAnchorsDER: cmpAnchors,
		// H1/V22: third-party enrollment is an explicit deployment opt-in;
		// the default binds every CSR to the authenticated protection identity.
		AllowRAEnrollment: cfg.CMPAllowRAEnrollment,
		// Algorithms the core parser cannot check route through the same
		// licensed verifier seam EST uses; protection stays core-verified.
		CSRVerifier:  issuer.verifyCSR,
		CSRInspector: issuer.inspectCSRInfo,
		CheckProtectionCertificate: func(ctx context.Context, req *crypto.CMPRequest) error {
			return s.checkCMPProtectionCertificate(ctx, sp.cmpTenant, req, cfg.CMPClientCRLFile)
		},
		FailureDiagnosis: func(requestCtx context.Context, diagnosis enrollmentdiag.Diagnosis) {
			if s.api == nil {
				return
			}
			if err := s.api.RecordEnrollmentDiagnosis(requestCtx, sp.cmpTenant, diagnosis); err != nil && s.logger != nil {
				s.logger.Warn("enrollment diagnosis persistence failed", slog.String("protocol", string(diagnosis.Protocol)), slog.String("error", err.Error()))
			}
		},
	})
	sp.cmpClientTrustAnchorCount = len(cmpAnchors)
	sp.cmpBulkheadReady = pool != nil
	sp.names = append(sp.names, "cmp")
	return nil
}

// checkCMPProtectionCertificate reads the same tenant-scoped issuance and
// pending-revocation state that backs the served OCSP responder. A certificate
// signed by our CA cannot authenticate CMP once its serial is revoked, pending
// revocation, or unknown to this tenant. Other trust anchors need their own
// revocation authority; this check never mistakes them for a platform leaf.
func (s *Server) checkCMPProtectionCertificate(ctx context.Context, tenantID string, req *crypto.CMPRequest, externalCRLFile string) error {
	if tenantID == "" || req == nil || len(req.ProtectionCertificateDER) == 0 || s.store == nil {
		return errors.New("server: CMP protection identity has no tenant, certificate, or standing store")
	}
	if crypto.VerifyLeafSignedByCA(req.ProtectionCertificateDER, s.caCertDER) == nil {
		info, err := certinfo.Inspect(req.ProtectionCertificateDER)
		if err != nil {
			return fmt.Errorf("server: inspect CMP protection identity: %w", err)
		}
		standing, _, err := issuedCertStatus(ctx, s.store, tenantID, IssuingCAID(), info.SerialNumber)
		if err != nil {
			return fmt.Errorf("server: read CMP protection identity standing: %w", err)
		}
		if standing != issuedCertGood {
			return errors.New("server: CMP protection identity is not in good standing")
		}
		return nil
	}
	if len(req.ProtectionChainDER) == 1 {
		// This exact certificate is an operator-pinned trust anchor, rather
		// than a leaf whose CA can revoke it. Removing the pin and reloading
		// the mount removes its authority.
		return nil
	}
	crls, err := loadCMPClientCRLs(externalCRLFile)
	if err != nil {
		return err
	}
	return crypto.VerifyCMPProtectionCRLs(req.ProtectionChainDER, crls, time.Now().UTC())
}

// loadCMPClientCRLs rereads an operator-owned local bundle on each request so
// replacing it atomically updates revocation decisions without a process
// restart. A missing, oversized, malformed, or empty bundle refuses issuance.
func loadCMPClientCRLs(path string) ([][]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("server: external CMP client CAs need a current CRL bundle")
	}
	f, err := os.Open(path) // #nosec G304 -- operator-configured local public CRL path, not request input; read bounded below (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("server: open CMP client CRL bundle: %w", err)
	}
	defer func() { _ = f.Close() }()
	const maxCRLBundleBytes = 2 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxCRLBundleBytes+1))
	if err != nil || len(data) > maxCRLBundleBytes {
		return nil, errors.New("server: CMP client CRL bundle is unreadable or too large")
	}
	var crls [][]byte
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN X509 CRL-----")) {
			return nil, errors.New("server: CMP client CRL bundle has non-PEM content")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "X509 CRL" || len(block.Headers) != 0 || len(crls) >= 32 {
			return nil, errors.New("server: CMP client CRL bundle is malformed")
		}
		crls = append(crls, block.Bytes)
		data = rest
	}
	if len(crls) == 0 {
		return nil, errors.New("server: CMP client CRL bundle is empty")
	}
	return crls, nil
}

func (source cmpQualificationSource) read(_ context.Context, tenantID string) api.CMPRuntimePosture {
	bindingMode := "subject-bound"
	if source.allowRA {
		bindingMode = "registration-authority"
	}
	posture := api.CMPRuntimePosture{
		Configured: source.configured, Endpoint: "/cmp",
		TenantBound: source.configured && source.configuredFor != "" && source.configuredFor == tenantID,
		ProfileName: "default", BindingMode: bindingMode,
	}
	if source.server == nil {
		return posture
	}
	if name := strings.TrimSpace(source.server.defaultProfile); name != "" {
		posture.ProfileName = name
	}
	served := source.server.protocols
	if served == nil || served.cmp == nil || served.cmpTenant != tenantID {
		return posture
	}
	posture.Served = true
	posture.RATransportReady = len(source.server.protoRACertDER) > 0 && len(source.server.protoRAKeyPKCS8) > 0
	posture.ClientTrustAnchorCount = served.cmpClientTrustAnchorCount
	posture.IssuingPathReady = source.server.caSigner != nil && len(source.server.caCertDER) > 0 && source.server.orch != nil && source.server.idem != nil
	posture.ProfileReady = posture.IssuingPathReady
	posture.BulkheadReady = served.cmpBulkheadReady
	return posture
}
