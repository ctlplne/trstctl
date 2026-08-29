// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
)

// spiffeQualificationSource exposes only credential-free facts from the exact
// served process. API construction happens before protocol assembly, so it reads
// the final mount at request time. The only filesystem read is an lstat of the
// configured Unix socket; it never dials the Workload API.
type spiffeQualificationSource struct {
	server        *Server
	configured    bool
	configuredFor string
	trustDomain   string
	socketPath    string
}

func newSPIFFEQualificationSource(s *Server, protocols config.Protocols, tenantFallback string) spiffeQualificationSource {
	socketPath := strings.TrimSpace(protocols.SPIFFE.SocketPath)
	trustDomain := strings.TrimSpace(protocols.SPIFFE.TrustDomain)
	if socketPath == "" {
		socketPath = defaultSPIFFESocket
	}
	return spiffeQualificationSource{
		server: s, configured: protocols.SPIFFE.Enabled && trustDomain != "",
		configuredFor: firstNonEmpty(protocols.SPIFFE.TenantID, tenantFallback),
		trustDomain:   trustDomain, socketPath: socketPath,
	}
}

func (s *Server) appendSPIFFEQualificationOption(d Deps, options *[]api.Option) {
	source := newSPIFFEQualificationSource(s, d.Protocols, d.ProtocolTenant)
	*options = append(*options, api.WithSPIFFEQualificationPosture(source.read))
}

func (source spiffeQualificationSource) read(_ context.Context, tenantID string) api.SPIFFERuntimePosture {
	posture := api.SPIFFERuntimePosture{
		Configured: source.configured, TenantBound: source.configured && source.configuredFor != "" && source.configuredFor == tenantID,
		TrustDomain: source.trustDomain, SocketURI: "unix://" + source.socketPath,
		LocalSocketDeprecated: true,
		SupportedOperations:   []string{"FetchX509SVID", "FetchX509Bundles", "FetchJWTSVID", "FetchJWTBundles", "ValidateJWTSVID"},
	}
	if source.server == nil {
		return posture
	}
	served := source.server.protocols
	if served == nil || served.spiffe == nil || served.spiffe.tenantID != tenantID {
		return posture
	}
	sp := served.spiffe
	posture.Served = sp.server != nil && sp.wl != nil
	posture.Activated = served.activation == nil || served.activation.Active()
	posture.TrustDomain = sp.trustDomain
	posture.SocketURI = "unix://" + sp.socket
	posture.RegistrationEntryCount = sp.registrationEntryCount
	posture.IssuingPathReady = source.server.caSigner != nil && len(source.server.caCertDER) > 0 && sp.server != nil && sp.wl != nil
	posture.BulkheadReady = sp.bulkheadReady
	if info, err := os.Lstat(sp.socket); err == nil && sp.running.Load() && info.Mode()&os.ModeSocket != 0 {
		posture.SocketReady = true
		posture.SocketMode = info.Mode().String()
		posture.SocketOwnerOnly = info.Mode().Perm()&0o077 == 0
	}
	return posture
}
