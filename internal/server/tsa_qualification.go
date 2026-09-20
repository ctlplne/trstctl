// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
)

// tsaQualificationSource exposes only secret-free facts from the exact served
// process. The API is assembled before protocol mounts, so the closure reads the
// final s.protocols generation at request time instead of caching startup hope.
type tsaQualificationSource struct {
	server               *Server
	configured           bool
	configuredFor        string
	stableCertConfigured bool
	eventLogReady        bool
}

func newTSAQualificationSource(s *Server, protocols config.Protocols, tenantFallback string, eventLogReady bool) tsaQualificationSource {
	return tsaQualificationSource{
		server:               s,
		configured:           protocols.TSA.Enabled,
		configuredFor:        firstNonEmpty(protocols.TSA.TenantID, tenantFallback),
		stableCertConfigured: strings.TrimSpace(protocols.TSACertFile) != "",
		eventLogReady:        eventLogReady,
	}
}

func (s *Server) appendTSAQualificationOption(d Deps, options *[]api.Option) {
	source := newTSAQualificationSource(s, d.Protocols, d.ProtocolTenant, d.Log != nil)
	*options = append(*options, api.WithTSAQualificationPosture(source.read))
}

func (source tsaQualificationSource) read(_ context.Context, tenantID string) api.TSARuntimePosture {
	posture := api.TSARuntimePosture{
		Configured:  source.configured,
		Endpoint:    "/tsa",
		TenantBound: source.configured && source.configuredFor != "" && source.configuredFor == tenantID,
		PolicyOID:   "1.3.6.1.4.1.59551.2.1",
	}
	if source.server == nil {
		return posture
	}
	served := source.server.protocols
	if served == nil || served.tsa == nil || served.tsaTenant != tenantID {
		return posture
	}
	posture.Served = true
	posture.Activated = served.activation == nil || served.activation.Active()
	// buildTSA cannot return an Authority until it has loaded or created a
	// timestamping-only certificate and matched it to the signer-held key.
	posture.StableCertificateReady = source.stableCertConfigured
	posture.SignerReady = source.server.signer != nil && source.server.signer.Client() != nil
	posture.AuditReady = source.eventLogReady
	posture.BulkheadReady = source.server.bulk != nil && source.server.bulk.Pool(bulkhead.SubsystemAPI) != nil
	return posture
}
