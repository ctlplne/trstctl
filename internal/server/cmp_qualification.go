// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"log/slog"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
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
	// Unset anchors leave the mount refusing to enrol (fail closed).
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
		CSRVerifier: issuer.verifyCSR,
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
