// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/signing"
)

// The tenants the token exchange serves (M4-L5). The SPIFFE surface's own
// tenant (protocols.spiffe.tenant_id) exchanges in its trust domain with the
// surface's JWT key; each tenant in protocols.spiffe.exchange_tenants does in
// a trust domain of its own, with its own JWT key ring in the signer, so a
// relying party that trusts one tenant's key set never accepts another
// tenant's token, and each tenant rotates its key on its own.

// workloadExchange is one tenant the token exchange serves.
type workloadExchange struct {
	tenantID    string
	trustDomain string
	issuer      tenantSPIFFEIssuer
	jwtKeys     *workloadJWTKeyRing
}

// exchangeFor is the exchange serving tenantID, or nil.
func (s *Server) exchangeFor(tenantID string) *workloadExchange {
	sp := s.spiffeForExchange()
	if sp == nil || tenantID == "" {
		return nil
	}
	if tenantID == sp.tenantID {
		return &workloadExchange{tenantID: sp.tenantID, trustDomain: sp.trustDomain, issuer: sp.issuer, jwtKeys: sp.jwtKeys}
	}
	return sp.exchanges[strings.ToLower(tenantID)]
}

// workloadJWTTenantHandle names an exchange tenant's first JWT key in the
// signer; later generations add -g<n>.
func workloadJWTTenantHandle(tenantID string) string {
	return spiffeJWTHandle + "-t-" + strings.ReplaceAll(strings.ToLower(tenantID), "-", "")
}

// buildExchangeTenants provisions each exchange tenant's JWT key in the
// signer (found again after a restart, created the first time) and its ring.
func (s *Server) buildExchangeTenants(ctx context.Context, c *signing.Client, cfg config.SPIFFEProtocol, alg crypto.Algorithm) (map[string]*workloadExchange, error) {
	out := make(map[string]*workloadExchange, len(cfg.ExchangeTenants))
	for _, t := range cfg.ExchangeTenants {
		tenantID := strings.ToLower(t.TenantID)
		handle := workloadJWTTenantHandle(tenantID)
		signer, err := s.signerForPrivilegedHandle(ctx, c, handle, signing.PurposeGeneric)
		var key crypto.DigestSigner = signer
		if err != nil {
			created, createErr := s.generatePrivilegedKeyHandle(ctx, c, alg, handle,
				[]signing.KeyPurpose{signing.PurposeGeneric}, signing.PurposeGeneric)
			if createErr != nil {
				return nil, fmt.Errorf("server: JWT key for exchange tenant %s: %w", tenantID, createErr)
			}
			key = created
		}
		issuer := &spiffe.CAIssuer{JWTSigner: key, JWTKeyID: projections.WorkloadJWTKeyID(1)}
		var ring *workloadJWTKeyRing
		if s.store != nil {
			ring = newWorkloadJWTKeyRing(s, c, tenantID, key, alg)
			ring.handlePrefix = handle
			issuer.JWTKeys = ring.keys
		}
		out[tenantID] = &workloadExchange{tenantID: tenantID, trustDomain: t.TrustDomain, jwtKeys: ring,
			issuer: tenantSPIFFEIssuer{Issuer: issuer, tenantID: tenantID, check: s.tenantServiceCheck, work: s.store.BeginTenantService, store: s.store}}
	}
	return out, nil
}
