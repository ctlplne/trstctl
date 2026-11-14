// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

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
	if ex := sp.exchanges[strings.ToLower(tenantID)]; ex != nil {
		return ex
	}
	// N5-L2: one already created on first use.
	sp.lazyMu.Lock()
	defer sp.lazyMu.Unlock()
	return sp.lazy[strings.ToLower(tenantID)]
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
		ex, err := s.newWorkloadExchange(ctx, c, strings.ToLower(t.TenantID), t.TrustDomain, alg)
		if err != nil {
			return nil, err
		}
		out[ex.tenantID] = ex
	}
	return out, nil
}

// newWorkloadExchange finds (or, the first time, creates) one tenant's JWT
// key in the signer and builds its exchange.
func (s *Server) newWorkloadExchange(ctx context.Context, c *signing.Client, tenantID, trustDomain string, alg crypto.Algorithm) (*workloadExchange, error) {
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
	return &workloadExchange{tenantID: tenantID, trustDomain: trustDomain, jwtKeys: ring,
		issuer: tenantSPIFFEIssuer{Issuer: issuer, tenantID: tenantID, check: s.tenantServiceCheck, work: s.store.BeginTenantService, store: s.store}}, nil
}

// maxLazyExchanges bounds the tenants served under exchange_all_tenants
// (N5-L2, AN-7).
const maxLazyExchanges = 10000

// exchangeForCtx is exchangeFor that, under exchange_all_tenants (N5-L2),
// also serves any live tenant: its exchange is created on first use, in its
// own trust domain under the suffix and with its own key. A tenant that is
// not registered, suspended or being offboarded gets none, and no key is
// created for it.
func (s *Server) exchangeForCtx(ctx context.Context, tenantID string) *workloadExchange {
	if ex := s.exchangeFor(tenantID); ex != nil {
		return ex
	}
	sp := s.spiffeForExchange()
	if sp == nil || !sp.allTenants || sp.jwtClient == nil {
		return nil
	}
	parsed, err := uuid.Parse(tenantID)
	if err != nil {
		return nil
	}
	tenantID = parsed.String()
	if err := s.tenantServiceCheck.Check(ctx, tenantID); err != nil {
		return nil
	}
	sp.lazyMu.Lock()
	defer sp.lazyMu.Unlock()
	if ex := sp.lazy[tenantID]; ex != nil {
		return ex
	}
	if len(sp.lazy) >= maxLazyExchanges {
		if s.logger != nil {
			s.logger.Warn("the token exchange serves its most tenants created on first use; a further tenant is refused", "max", maxLazyExchanges)
		}
		return nil
	}
	ex, err := s.newWorkloadExchange(ctx, sp.jwtClient, tenantID, strings.ReplaceAll(tenantID, "-", "")+"."+sp.tenantSuffix, sp.jwtAlgorithm)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("a tenant's token exchange could not be created", "tenant", tenantID, "error", err.Error())
		}
		return nil
	}
	sp.lazy[tenantID] = ex
	return ex
}
