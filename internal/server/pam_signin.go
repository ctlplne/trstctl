// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/discovery/compromise"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pamsignin"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A274: bypass detection. A pam_signin discovery source names a
// dynamic-secret provider; each run reads, through the provider's
// administrator connection, the sign-ins of the accounts the provider
// manages (its static roles' accounts), explains each by a span in which
// trstctl itself or a person it let in signed in as that account — a session
// to one of its targets, a revealed check-out, a rotation of the account, a
// credential health check — and records every unexplained sign-in as a
// compromised-credential finding (F31) with its evidence.

// pamSignInLookbackDefault is how far back a run reads when its source sets
// no lookback: overlapping runs refresh, never repeat, a finding.
const pamSignInLookbackDefault = time.Hour

// pamSignInHealthSpan is the span before a recorded health check in which
// its sign-in happened.
const pamSignInHealthSpan = 2 * time.Minute

// pamSignInSource is the provider side of bypass detection.
type pamSignInSource interface {
	Name() string
	DynamicSecretProviderType() string
	DynamicSecretManagedAccounts() map[string][]string
	DynamicSecretReadSignIns(ctx context.Context, accounts []string, since time.Time) ([]pamsignin.SignIn, string, error)
	DynamicSecretTargetAddress() string
}

// DynamicSecretManagedAccounts is each static role's accounts: its bound
// account, or the pair a two-user rotation alternates.
func (p *configuredDynamicProvider) DynamicSecretManagedAccounts() map[string][]string {
	out := map[string][]string{}
	for role, account := range p.cfg.RoleBindings {
		if account = strings.TrimSpace(account); account != "" && !strings.Contains(account, "=") {
			out[role] = []string{account}
		}
	}
	for role, pair := range p.cfg.RotationAccounts {
		out[role] = append([]string(nil), pair...)
	}
	return out
}

// DynamicSecretReadSignIns reads the target's sign-ins of the accounts
// through the provider's administrator connection.
func (p *configuredDynamicProvider) DynamicSecretReadSignIns(ctx context.Context, accounts []string, since time.Time) ([]pamsignin.SignIn, string, error) {
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return nil, "", err
	}
	defer closeBackend()
	reader, ok := backend.(dynsecret.SignInReader)
	if !ok {
		return nil, "", dynsecret.ErrSignInsNotSupported
	}
	return reader.ReadSignIns(ctx, accounts, since)
}

// DynamicSecretTargetAddress is the host:port the provider reaches its
// target at, when it names one (a host's SSH address).
func (p *configuredDynamicProvider) DynamicSecretTargetAddress() string {
	return strings.TrimSpace(p.cfg.Addr)
}

// pamSignInCollection is one run's sign-ins and how each was explained.
type pamSignInCollection struct {
	ProviderID, ProviderType, Collector string
	Accounts                            []string
	Matched                             []pamsignin.Matched
}

func (s *pamService) signInSource(tenantID, providerID string) (pamSignInSource, error) {
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != providerID {
			continue
		}
		src, ok := provider.(pamSignInSource)
		if !ok {
			return nil, fmt.Errorf("%w: provider %s cannot read its target's sign-ins", api.ErrPAMInvalid, providerID)
		}
		return src, nil
	}
	return nil, fmt.Errorf("%w: no dynamic-secret provider %s in this tenant", api.ErrPAMInvalid, providerID)
}

// collectSignIns reads the provider's managed accounts' sign-ins since a
// time and explains each.
func (s *pamService) collectSignIns(ctx context.Context, tenantID, providerID string, since, now time.Time) (pamSignInCollection, error) {
	src, err := s.signInSource(tenantID, providerID)
	if err != nil {
		return pamSignInCollection{}, err
	}
	roles := src.DynamicSecretManagedAccounts()
	seen := map[string]bool{}
	var accounts []string
	for _, pair := range roles {
		for _, a := range pair {
			if !seen[a] {
				seen[a] = true
				accounts = append(accounts, a)
			}
		}
	}
	sort.Strings(accounts)
	if len(accounts) == 0 {
		return pamSignInCollection{}, fmt.Errorf("%w: provider %s manages no static accounts to watch", api.ErrPAMInvalid, providerID)
	}
	signIns, collector, err := src.DynamicSecretReadSignIns(ctx, accounts, since)
	if err != nil {
		return pamSignInCollection{}, err
	}
	windows, err := s.signInWindows(ctx, tenantID, src, roles, since.Add(-pamsignin.DefaultSlack), now)
	if err != nil {
		return pamSignInCollection{}, err
	}
	return pamSignInCollection{ProviderID: providerID, ProviderType: src.DynamicSecretProviderType(), Collector: collector, Accounts: accounts,
		Matched: pamsignin.Match(signIns, windows, pamsignin.DefaultSlack)}, nil
}

// signInWindows are the spans in [from, to] in which trstctl or a person it
// let in signed in as one of the provider's accounts.
func (s *pamService) signInWindows(ctx context.Context, tenantID string, src pamSignInSource, roles map[string][]string, from, to time.Time) ([]pamsignin.Window, error) {
	providerID := src.Name()
	var windows []pamsignin.Window
	add := func(accounts []string, start, end time.Time, kind, ref string) {
		for _, a := range accounts {
			windows = append(windows, pamsignin.Window{Account: a, From: start, To: end, Kind: kind, Ref: ref})
		}
	}
	// Sessions: a vaulted account's target of this provider (the gateway,
	// or the session holder, signs in as it), and SSH sessions to this
	// provider's host as one of its accounts.
	sessions, err := s.store.ListPAMSessionsOverlapping(ctx, tenantID, from, to, 0)
	if err != nil {
		return nil, err
	}
	hostAddress := normalizedHostPort(src.DynamicSecretTargetAddress())
	for _, rec := range sessions {
		end := rec.ExpiresAt
		if rec.EndedAt != nil && rec.EndedAt.Before(end) {
			end = *rec.EndedAt
		}
		kind := pamsignin.WindowSession
		if rec.Delivery == "gateway" {
			kind = pamsignin.WindowGatewaySession
		}
		switch {
		case isPAMDatabaseType(rec.TargetType):
			target, err := s.databaseTarget(ctx, tenantID, rec.TargetType, rec.TargetID)
			if err != nil || target.cfg.ProviderID != providerID || target.cfg.AccountSecret == "" {
				continue
			}
			add(roles[target.cfg.AccountSecret], rec.StartedAt, end, kind, rec.ID)
		case rec.TargetType == pamTargetSSH && hostAddress != "" && rec.SSHPrincipal != "":
			target, err := s.sshTarget(ctx, tenantID, rec.TargetID)
			if err != nil || normalizedHostPort(net.JoinHostPort(target.Host, strconv.Itoa(target.Port))) != hostAddress {
				continue
			}
			add([]string{rec.SSHPrincipal}, rec.StartedAt, end, kind, rec.ID)
		}
	}
	checkouts, err := s.store.ListPAMCheckoutsOverlapping(ctx, tenantID, providerID, from, to, 0)
	if err != nil {
		return nil, err
	}
	for _, c := range checkouts {
		end := c.ExpiresAt
		if c.EndedAt != nil && c.EndedAt.Before(end) {
			end = *c.EndedAt
		}
		add(roles[c.AccountSecret], c.RevealedAt, end, pamsignin.WindowCheckout, c.RequestID)
	}
	rotations, err := s.store.ListStaticRotationSpansOverlapping(ctx, tenantID, providerID, from, to, 0)
	if err != nil {
		return nil, err
	}
	for _, r := range rotations {
		add(roles[r.Key], r.CreatedAt, r.EndedAt, pamsignin.WindowRotation, r.ID)
	}
	// Credential health checks (A258) sign in as a vaulted account; the last
	// one of each target is recorded.
	health, err := s.store.ListPAMAccountHealth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	targets, err := s.signInTargets(ctx, tenantID, providerID)
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		h, ok := health[[2]string{t.targetType, t.id}]
		if !ok || h.CheckedAt.Before(from) || h.CheckedAt.After(to) {
			continue
		}
		add(roles[t.accountSecret], h.CheckedAt.Add(-pamSignInHealthSpan), h.CheckedAt, pamsignin.WindowHealth, t.targetType+"/"+t.id)
	}
	return windows, nil
}

type pamSignInTarget struct{ targetType, id, accountSecret string }

// signInTargets are the provider's vaulted targets, configured and
// registered.
func (s *pamService) signInTargets(ctx context.Context, tenantID, providerID string) ([]pamSignInTarget, error) {
	var out []pamSignInTarget
	for key, target := range s.databases {
		if key.tenantID == tenantID && target.cfg.ProviderID == providerID && target.cfg.AccountSecret != "" {
			out = append(out, pamSignInTarget{key.targetType, key.id, target.cfg.AccountSecret})
		}
	}
	registered, err := s.store.ListPAMTargets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, rec := range registered {
		if rec.ProviderID == providerID && rec.AccountSecret != "" {
			out = append(out, pamSignInTarget{rec.TargetType, rec.ID, rec.AccountSecret})
		}
	}
	return out, nil
}

func normalizedHostPort(address string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return ""
	}
	return strings.ToLower(host) + ":" + port
}

// collectPAMSignIns is the discovery executor's hook into PAM.
func (s *Server) collectPAMSignIns(ctx context.Context, tenantID, providerID string, since, now time.Time) (pamSignInCollection, error) {
	if s.pam == nil {
		return pamSignInCollection{}, api.ErrPAMUnavailable
	}
	return s.pam.collectSignIns(ctx, tenantID, providerID, since, now)
}

// pamSignInFailure is the class a failed run records; never the error's
// text, which could name what the target said.
func pamSignInFailure(err error) string {
	switch {
	case errors.Is(err, dynsecret.ErrSignInsNotSupported):
		return "not_supported"
	case errors.Is(err, pamsignin.ErrIncomplete):
		return "incomplete"
	case errors.Is(err, api.ErrPAMInvalid):
		return "invalid: " + strings.TrimPrefix(err.Error(), api.ErrPAMInvalid.Error()+": ")
	}
	switch class := dynsecret.SignInStatusOf(err); class {
	case "rejected", "expired", "locked", "unreachable":
		return class
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "unreachable"
	}
	return "error"
}

// executePAMSignInDiscoveryRun reads a provider's managed accounts' sign-ins
// and records each one no session, check-out, rotation or health check
// explains as a compromised-credential finding.
func (d *issuanceDispatcher) executePAMSignInDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	cfg, err := pamsignin.ParseConfig(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if d.pamSignIns == nil {
		return netscan.Report{}, "failed", "privileged access is not served", nil
	}
	lookback := pamSignInLookbackDefault
	if cfg.LookbackSeconds > 0 {
		lookback = time.Duration(cfg.LookbackSeconds) * time.Second
	}
	now := time.Now().UTC()
	collection, err := d.pamSignIns(ctx, tenantID, cfg.ProviderID, now.Add(-lookback), now)
	if err != nil {
		return netscan.Report{}, "failed", pamSignInFailure(err), nil
	}
	rep := netscan.Report{Targets: len(collection.Matched)}
	if run.DryRun {
		return rep, "succeeded", "", nil
	}
	for _, signIn := range pamsignin.Bypasses(collection.Matched) {
		f := pamsignin.BypassFinding(collection.ProviderID, collection.ProviderType, collection.Collector, signIn)
		meta, err := json.Marshal(f.Metadata)
		if err != nil {
			return rep, "", "", err
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: run.ID, SourceID: src.ID, Kind: compromise.FindingKind, Ref: f.Ref,
			Provenance: f.Provenance, Fingerprint: f.Fingerprint, RiskScore: f.RiskScore, Metadata: meta,
		}); err != nil {
			return rep, "", "", err
		}
		rep.Discovered++
	}
	return rep, "succeeded", "", nil
}
