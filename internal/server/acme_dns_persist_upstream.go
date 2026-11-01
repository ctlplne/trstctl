// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"trstctl.com/trstctl/internal/crypto/acmekey"
	acme "trstctl.com/trstctl/internal/protocols/acme"
)

// dns-persist-01 on the upstream client (P1), behind the authority's
// upstream_dns_persist flag. The standing record is published once through
// the same DNS-01 provider config, consent and CAA check as a dns-01 answer,
// and is never retracted: while it names the authority and this account,
// later orders reuse it with no DNS change and no provider call.

// withPersist turns dns-persist-01 on for this authority's binding.
func (b *upstreamDVBinding) withPersist(on bool) *upstreamDVBinding {
	if b != nil {
		b.persist = on
	}
	return b
}

// solvePersist publishes the standing record unless it already stands.
func (s *upstreamACMEDNS01Solver) solvePersist(ctx context.Context, req acmekey.ChallengeRequest) (func(context.Context) error, error) {
	tenantID, identifier := strings.TrimSpace(req.TenantID), strings.TrimSpace(req.Identifier)
	accountURI := strings.TrimSpace(req.AccountURI)
	if tenantID == "" || identifier == "" || accountURI == "" || len(req.IssuerDomainNames) == 0 {
		return nil, errors.New("server: a dns-persist-01 record needs a tenant, an identifier, the authority's issuer domain name and the account")
	}
	cfg, err := s.automation.selectProviderConfigForUpstream(ctx, tenantID, identifier)
	if err != nil {
		return nil, err
	}
	wildcard := strings.HasPrefix(identifier, "*.")
	if wildcard && !cfg.AllowWildcards {
		return nil, fmt.Errorf("server: %s is a wildcard and the DNS-01 provider config for it does not allow wildcards", identifier)
	}
	if err := s.enforceUpstreamCAA(ctx, identifier); err != nil {
		return nil, err
	}
	stands := acme.DNSPersistValidator{Resolver: s.persistResolver()}.
		ValidatePersist(ctx, identifier, accountURI, req.IssuerDomainNames) == nil
	if stands {
		return nil, nil
	}
	recordName := acme.DNSPersistRecordName(identifier)
	value := acme.DNSPersistRecordValue(req.IssuerDomainNames[0], accountURI, wildcard)
	// The publish's retraction is dropped on purpose: the record is meant to
	// stand. Removing it is the operator's act, and the next order then fails.
	if _, err := s.automation.presentRecord(ctx, tenantID, cfg, identifier, recordName, value); err != nil {
		return nil, err
	}
	return nil, nil
}

// persistResolver reads TXT the way the served ACME validator does.
func (s *upstreamACMEDNS01Solver) persistResolver() acme.Resolver {
	if s.automation != nil && len(s.automation.txtResolvers) > 0 && s.automation.txtResolvers[0] != nil {
		return s.automation.txtResolvers[0]
	}
	return net.DefaultResolver
}
