// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	acme "trstctl.com/trstctl/internal/protocols/acme"
)

// Unattended domain validation on the UPSTREAM client (epic B7).
//
// DNS-01 already shipped — for trstctl acting as the ACME server, where a
// client solves a challenge against us. The direction the compressing
// validation-reuse window acts on is the other one: trstctl as a client to a
// public CA, which could not validate at all. It looked only for http-01, and
// the production constructor wired a solver whose Present and Cleanup did
// nothing, so the whole path worked only against orders the authority had
// already authorized out of band.
//
// This solver closes that using the provider configs an operator has ALREADY
// created for the server direction: same credentials, same providers, same
// publish path through the outbox. What it does not reuse is the CAA check —
// see below, where reusing it would have been actively wrong.

// upstreamACMEDNS01Solver satisfies dns-01 challenges for the upstream client.
type upstreamACMEDNS01Solver struct {
	automation *servedACMEDNS01Automation
	log        *events.Log
	// caaIssuerDomain is the PUBLIC CA's CAA identifier, not ours.
	//
	// The served automation checks CAA against cfg.CAAIssuerDomain, which is
	// trstctl's own identifier — correct when trstctl is the issuer. Upstream,
	// the certificate comes from Let's Encrypt, so the CAA record must
	// authorize Let's Encrypt. Reusing the column would produce a check that
	// passes while authorizing the wrong issuer, which is worse than no check:
	// it would report the domain as safe to issue for and then fail at the
	// authority, or succeed against a CAA policy the operator believed
	// excluded it.
	caaIssuerDomain string
	// issuer is the configured authority's ID, recorded on every observation.
	// The same identifier authorized at two CAs has two independent reuse
	// windows; a row that did not name the authority would report their union
	// and hide whichever is about to lapse.
	issuer string
}

// SolvableChallenges reports dns-01 only.
//
// http-01 is deliberately absent. Serving it would require an inbound listener
// on port 80 of the validated host, which this architecture does not have and
// is not going to grow — the whole design is outbound-only. Claiming it would
// make the driver select http-01 and then fail at publish time, which is
// exactly the shape of failure the census discipline exists to prevent.
func (s *upstreamACMEDNS01Solver) SolvableChallenges() []string {
	return []string{acmekey.ChallengeDNS01}
}

// Solve publishes the challenge record and returns its retraction.
func (s *upstreamACMEDNS01Solver) Solve(ctx context.Context, req acmekey.ChallengeRequest) (func(context.Context) error, error) {
	if s == nil || s.automation == nil {
		return nil, errors.New("server: upstream dns-01 solver is not configured")
	}
	if req.Type != acmekey.ChallengeDNS01 {
		return nil, fmt.Errorf("server: upstream solver was asked for %q; it solves dns-01 only", req.Type)
	}
	tenantID := strings.TrimSpace(req.TenantID)
	identifier := strings.TrimSpace(req.Identifier)
	if tenantID == "" || identifier == "" {
		return nil, errors.New("server: upstream dns-01 solve requires a tenant and an identifier")
	}
	// No separate propagation budget here on purpose. The publish goes through
	// the automation's outbox wait (acmeDNS01OutboxWait), which already bounds
	// it, and a second timeout layered on top would be a knob nobody sets —
	// this file previously carried exactly that: a budget field no constructor
	// ever assigned, so the branch guarding it could not run.

	// The identifier arrives with its "*." intact so the wildcard policy can
	// see it. A config that has not opted into wildcards must not silently
	// authorize one — a wildcard certificate covers every name under the label,
	// including hosts the operator never intended to cover.
	cfg, err := s.automation.selectProviderConfigForUpstream(ctx, tenantID, identifier)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(identifier, "*.") && !cfg.AllowWildcards {
		return nil, fmt.Errorf("server: %s is a wildcard and the DNS-01 provider config for it does "+
			"not allow wildcards", identifier)
	}
	if err := s.enforceUpstreamCAA(ctx, identifier); err != nil {
		return nil, err
	}

	recordName := acme.DNS01RecordName(identifier)
	value := acme.DNS01RecordValue(req.KeyAuth)
	retract, err := s.automation.presentRecord(ctx, tenantID, cfg, identifier, recordName, value)
	if err != nil {
		return nil, err
	}
	return retract, nil
}

// enforceUpstreamCAA checks the domain's CAA authorizes the EXTERNAL issuer.
//
// Skipped, loudly, when no issuer domain is configured: a CAA check against an
// empty issuer would pass everything, and passing everything while appearing to
// check is the failure mode this codebase keeps finding. Configuration
// validation requires the domain whenever upstream DV is enabled, so reaching
// here without one is a bug rather than a supported state.
func (s *upstreamACMEDNS01Solver) enforceUpstreamCAA(ctx context.Context, identifier string) error {
	issuer := strings.TrimSpace(s.caaIssuerDomain)
	if issuer == "" {
		return errors.New("server: upstream dns-01 needs the external CA's CAA issuer domain; " +
			"without it the CAA check would authorize any issuer")
	}
	if s.automation == nil {
		return errors.New("server: upstream dns-01 CAA check has no DNS-01 automation to resolve through")
	}
	// The wildcard flag matters: CAA distinguishes issue from issuewild, and a
	// wildcard authorized by an issue record alone is not authorized.
	wildcard := strings.HasPrefix(identifier, "*.")
	checker := acme.CAAChecker{Resolver: s.caaResolver(), IssuerDomain: issuer}
	return checker.Check(ctx, strings.TrimPrefix(identifier, "*."), wildcard)
}

// caaResolver returns the resolver the CAA check runs through, defaulting to a
// live one exactly as the served direction does.
//
// This defaulting is the whole check. The field it reads is assigned in tests
// and nowhere else, so an earlier version that returned nil when the field was
// nil skipped CAA entirely in every shipped binary — while configuration
// validation went on requiring caa_issuer_domain and telling the operator the
// check "must name the authority that will issue". That is precisely the shape
// this file's own comment warns about: a control that passes everything while
// appearing to check. The served-direction twin (enforceLiveCAA) has always
// defaulted; the asymmetry was the bug.
func (s *upstreamACMEDNS01Solver) caaResolver() acme.CAAResolver {
	if s != nil && s.automation != nil && s.automation.caaResolver != nil {
		return s.automation.caaResolver
	}
	return acme.DefaultCAAResolver()
}

// ObserveAuthorization records every authorization outcome, including the ones
// the authority reused without a challenge.
//
// Reuse is the number that matters as validation windows compress. An install
// whose authorizations are all reused has not demonstrated it can still
// validate, and the day the window closes it discovers that for every domain at
// once. Recording reuse is what lets an operator see it coming.
func (s *upstreamACMEDNS01Solver) ObserveAuthorization(ctx context.Context, tenantID string, out acmekey.DVOutcome) {
	if s == nil || s.log == nil || strings.TrimSpace(tenantID) == "" {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"identifier":     out.Identifier,
		"issuer":         s.issuer,
		"challenge_type": out.ChallengeType,
		"reused":         out.Reused,
		"expires_at":     out.ExpiresAt,
	})
	if err != nil {
		return
	}
	_, _ = s.log.Append(ctx, events.Event{
		Type: projections.EventACMEUpstreamAuthorizationObserved, TenantID: tenantID, Data: payload,
	})
}

// upstreamDVHolder late-binds the DNS-01 automation into the external-CA
// factories.
//
// The factories are built in run.go before the Server exists, and the Server
// builds the automation during configureIssuanceSurfaces. The holder is what
// lets the earlier stage reference the later one without reordering startup or
// keeping a second copy of the automation.
//
// It deliberately does NOT hold a solver. The CAA issuer domain belongs to a
// particular authority, so a single shared solver would give the second
// configured ACME CA the first one's issuer — a CAA check that passes against
// the wrong CA is the same defect as one that passes against an empty issuer,
// only harder to see. Each external CA binds its own.
type upstreamDVHolder struct {
	mu         sync.RWMutex
	automation *servedACMEDNS01Automation
	log        *events.Log
}

func (h *upstreamDVHolder) set(automation *servedACMEDNS01Automation, log *events.Log) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.automation, h.log = automation, log
}

func (h *upstreamDVHolder) current() (*servedACMEDNS01Automation, *events.Log) {
	if h == nil {
		return nil, nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.automation, h.log
}

// bind returns this authority's view of the holder.
func (h *upstreamDVHolder) bind(caaIssuerDomain, issuer string) *upstreamDVBinding {
	return &upstreamDVBinding{holder: h, caaIssuerDomain: caaIssuerDomain, issuer: issuer}
}

// upstreamDVBinding is one authority's solver and observer. It resolves the
// automation at solve time, so an order that arrives before startup finishes
// fails closed with the not-configured reason rather than appearing to validate.
type upstreamDVBinding struct {
	holder          *upstreamDVHolder
	caaIssuerDomain string
	issuer          string
}

var (
	_ acmekey.ChallengeSolver = (*upstreamDVBinding)(nil)
	_ acmekey.DVObserver      = (*upstreamDVBinding)(nil)
)

func (b *upstreamDVBinding) solver() *upstreamACMEDNS01Solver {
	if b == nil {
		return nil
	}
	automation, log := b.holder.current()
	if automation == nil {
		return nil
	}
	return &upstreamACMEDNS01Solver{
		automation: automation, log: log,
		caaIssuerDomain: b.caaIssuerDomain, issuer: b.issuer,
	}
}

func (b *upstreamDVBinding) SolvableChallenges() []string {
	s := b.solver()
	if s == nil {
		return nil
	}
	return s.SolvableChallenges()
}

func (b *upstreamDVBinding) Solve(ctx context.Context, req acmekey.ChallengeRequest) (func(context.Context) error, error) {
	s := b.solver()
	if s == nil {
		return nil, acmekey.ErrSolverNotConfigured
	}
	return s.Solve(ctx, req)
}

func (b *upstreamDVBinding) ObserveAuthorization(ctx context.Context, tenantID string, out acmekey.DVOutcome) {
	if s := b.solver(); s != nil {
		s.ObserveAuthorization(ctx, tenantID, out)
	}
}
