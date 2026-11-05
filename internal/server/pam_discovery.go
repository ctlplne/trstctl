// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A260: privileged account discovery. A source is one of the tenant's
// dynamic-secret providers whose administrator connection reads its target's
// accounts: PostgreSQL roles, MySQL users, SQL Server logins, or a Linux or
// Unix host's local accounts, sudo rights and authorized keys. A scan is
// read-only, bounded by pamDiscoveryTimeout, and one per source at a time;
// its result is one event, whose projection stages the accounts and records
// what changed since the source's previous complete scan. Discovery grants
// nothing.

const (
	pamDiscoveryTimeout     = 2 * time.Minute
	pamDiscoveryMinInterval = time.Hour
	pamDiscoveryMaxInterval = 30 * 24 * time.Hour
	pamDiscoveryScheduler   = "scheduler"
)

// pamDiscoveryTypes are the provider types whose targets discovery reads.
var pamDiscoveryTypes = map[string]bool{"postgresql": true, "mysql": true, "mssql": true, "unix": true}

// pamAccountDiscoverer is a provider that can read its target's privileged
// accounts.
type pamAccountDiscoverer interface {
	DynamicSecretProviderType() string
	DynamicSecretDiscoverAccounts(ctx context.Context) ([]pamdiscovery.Account, error)
}

// pamDiscovery marks the sources being scanned, so one runs at a time.
type pamDiscovery struct {
	mu      sync.Mutex
	running map[string]bool
}

func newPAMDiscovery() *pamDiscovery { return &pamDiscovery{running: map[string]bool{}} }

// DynamicSecretDiscoverAccounts reads the provider's target's privileged
// accounts through its administrator connection.
func (p *configuredDynamicProvider) DynamicSecretDiscoverAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return nil, err
	}
	defer closeBackend()
	discoverer, ok := backend.(dynsecret.AccountDiscoverer)
	if !ok {
		return nil, dynsecret.ErrDiscoveryNotSupported
	}
	return discoverer.DiscoverPrivilegedAccounts(ctx)
}

func (s *pamService) discoverer(tenantID, providerID string) (pamAccountDiscoverer, error) {
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != providerID {
			continue
		}
		d, ok := provider.(pamAccountDiscoverer)
		if !ok || !pamDiscoveryTypes[d.DynamicSecretProviderType()] {
			return nil, fmt.Errorf("%w: provider %s cannot list its target's accounts (PostgreSQL, MySQL, SQL Server and Linux or Unix hosts can)",
				api.ErrPAMInvalid, providerID)
		}
		return d, nil
	}
	return nil, fmt.Errorf("%w: no dynamic-secret provider %s in this tenant", api.ErrPAMInvalid, providerID)
}

// discoveryFailure is the class a failed scan records; never the error's
// text, which could name what the target said.
func discoveryFailure(err error) string {
	switch {
	case errors.Is(err, dynsecret.ErrDiscoveryNotSupported):
		return "not_supported"
	case errors.Is(err, errDiscoveryTooMany):
		return "too_many"
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

var errDiscoveryTooMany = errors.New("server: a scan found more privileged accounts than one discovery holds")

func (s *pamService) SavePAMDiscoverySource(ctx context.Context, tenantID, actor, providerID string, intervalSeconds int) (api.PAMDiscoverySource, error) {
	interval := time.Duration(intervalSeconds) * time.Second
	switch {
	case actor == "":
		return api.PAMDiscoverySource{}, fmt.Errorf("%w: an authenticated author is required", api.ErrPAMInvalid)
	case intervalSeconds != 0 && (interval < pamDiscoveryMinInterval || interval > pamDiscoveryMaxInterval):
		return api.PAMDiscoverySource{}, fmt.Errorf("%w: interval_seconds must be 0 (on demand) or %d-%d", api.ErrPAMInvalid,
			int(pamDiscoveryMinInterval/time.Second), int(pamDiscoveryMaxInterval/time.Second))
	}
	d, err := s.discoverer(tenantID, providerID)
	if err != nil {
		return api.PAMDiscoverySource{}, err
	}
	if err := s.appendProject(ctx, tenantID, projections.EventPAMDiscoverySourceSaved, projections.PAMDiscoverySourceSaved{
		ProviderID: providerID, ProviderType: d.DynamicSecretProviderType(), IntervalSeconds: intervalSeconds, Actor: actor,
		At: s.clock().UTC()}); err != nil {
		return api.PAMDiscoverySource{}, err
	}
	src, err := s.store.GetPAMDiscoverySource(ctx, tenantID, providerID)
	if err != nil {
		return api.PAMDiscoverySource{}, err
	}
	return s.sourceView(ctx, tenantID, src)
}

func (s *pamService) ListPAMDiscoverySources(ctx context.Context, tenantID string) ([]api.PAMDiscoverySource, error) {
	sources, err := s.store.ListPAMDiscoverySources(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMDiscoverySource, 0, len(sources))
	for _, src := range sources {
		view, err := s.sourceView(ctx, tenantID, src)
		if err != nil {
			return nil, err
		}
		out = append(out, view)
	}
	return out, nil
}

func (s *pamService) sourceView(ctx context.Context, tenantID string, src store.PAMDiscoverySource) (api.PAMDiscoverySource, error) {
	view := api.PAMDiscoverySource{ProviderID: src.ProviderID, ProviderType: src.ProviderType, IntervalSeconds: src.IntervalSeconds,
		SavedBy: src.SavedBy, SavedAt: src.SavedAt}
	runs, err := s.store.ListPAMDiscoveryRuns(ctx, tenantID, src.ProviderID, 1)
	if err != nil {
		return api.PAMDiscoverySource{}, err
	}
	if len(runs) == 1 {
		run := discoveryRunView(runs[0])
		view.LastRun = &run
	}
	return view, nil
}

func (s *pamService) DeletePAMDiscoverySource(ctx context.Context, tenantID, actor, providerID string) error {
	if _, err := s.store.GetPAMDiscoverySource(ctx, tenantID, providerID); err != nil {
		return err
	}
	return s.appendProject(ctx, tenantID, projections.EventPAMDiscoverySourceDeleted, projections.PAMDiscoverySourceDeleted{
		ProviderID: providerID, Actor: actor, At: s.clock().UTC()})
}

func (s *pamService) RunPAMDiscovery(ctx context.Context, tenantID, actor, providerID string) (api.PAMDiscoveryRun, error) {
	if actor == "" {
		return api.PAMDiscoveryRun{}, fmt.Errorf("%w: an authenticated author is required", api.ErrPAMInvalid)
	}
	if _, err := s.store.GetPAMDiscoverySource(ctx, tenantID, providerID); err != nil {
		return api.PAMDiscoveryRun{}, err
	}
	id, err := s.scan(ctx, tenantID, providerID, actor)
	if err != nil {
		return api.PAMDiscoveryRun{}, err
	}
	return s.GetPAMDiscoveryRun(ctx, tenantID, id)
}

// scan reads one source's target and records the run; it refuses a source
// already being scanned.
func (s *pamService) scan(ctx context.Context, tenantID, providerID, requestedBy string) (string, error) {
	key := tenantID + "/" + providerID
	s.discovery.mu.Lock()
	if s.discovery.running[key] {
		s.discovery.mu.Unlock()
		return "", fmt.Errorf("%w: a scan of %s is running", api.ErrPAMTargetConflict, providerID)
	}
	s.discovery.running[key] = true
	s.discovery.mu.Unlock()
	defer func() {
		s.discovery.mu.Lock()
		delete(s.discovery.running, key)
		s.discovery.mu.Unlock()
	}()
	started := s.clock().UTC()
	event := projections.PAMDiscoveryRunCompleted{RunID: uuid.NewString(), ProviderID: providerID, Status: "completed",
		RequestedBy: requestedBy, StartedAt: started, Accounts: []pamdiscovery.Account{}}
	d, err := s.discoverer(tenantID, providerID)
	if err == nil {
		scanCtx, cancel := context.WithTimeout(ctx, pamDiscoveryTimeout)
		var accounts []pamdiscovery.Account
		accounts, err = d.DynamicSecretDiscoverAccounts(scanCtx)
		cancel()
		if err == nil && len(accounts) > pamdiscovery.MaxAccounts {
			err = errDiscoveryTooMany
		}
		if err == nil {
			event.Accounts = pamdiscovery.Normalize(accounts)
		}
	}
	if err != nil {
		event.Status, event.Failure = "failed", discoveryFailure(err)
	}
	event.FinishedAt = s.clock().UTC()
	if err := s.appendProject(ctx, tenantID, projections.EventPAMDiscoveryRunCompleted, event); err != nil {
		return "", err
	}
	return event.RunID, nil
}

func (s *pamService) ListPAMDiscoveryRuns(ctx context.Context, tenantID, providerID string, limit int) ([]api.PAMDiscoveryRun, error) {
	runs, err := s.store.ListPAMDiscoveryRuns(ctx, tenantID, providerID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMDiscoveryRun, 0, len(runs))
	for _, r := range runs {
		out = append(out, discoveryRunView(r))
	}
	return out, nil
}

func (s *pamService) GetPAMDiscoveryRun(ctx context.Context, tenantID, id string) (api.PAMDiscoveryRun, error) {
	if _, err := uuid.Parse(id); err != nil {
		return api.PAMDiscoveryRun{}, store.ErrPAMDiscoveryRunNotFound
	}
	run, err := s.store.GetPAMDiscoveryRun(ctx, tenantID, id)
	if err != nil {
		return api.PAMDiscoveryRun{}, err
	}
	return discoveryRunView(run), nil
}

func (s *pamService) ListPAMDiscoveredAccounts(ctx context.Context, tenantID, providerID, status string, includeRemoved bool) ([]api.PAMDiscoveredAccount, error) {
	items, err := s.store.ListPAMDiscoveredAccounts(ctx, tenantID, providerID, status, includeRemoved)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMDiscoveredAccount, 0, len(items))
	for _, a := range items {
		out = append(out, api.PAMDiscoveredAccount{ID: a.ID, ProviderID: a.ProviderID, PAMDiscoveredAccountInfo: accountInfo(a.Account),
			FirstSeenAt: a.FirstSeenAt, LastSeenAt: a.LastSeenAt, RemovedAt: a.RemovedAt, Status: a.Status})
	}
	return out, nil
}

func accountInfo(a pamdiscovery.Account) api.PAMDiscoveredAccountInfo {
	privileges := a.Privileges
	if privileges == nil {
		privileges = []string{}
	}
	return api.PAMDiscoveredAccountInfo{Key: a.Key, Name: a.Name, Kind: a.Kind, Privileges: privileges, Disabled: a.Disabled, Details: a.Details}
}

func discoveryRunView(r store.PAMDiscoveryRun) api.PAMDiscoveryRun {
	view := api.PAMDiscoveryRun{ID: r.ID, ProviderID: r.ProviderID, Status: r.Status, Failure: r.Failure, RequestedBy: r.RequestedBy,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Accounts: r.Accounts, Added: r.Added, Removed: r.Removed, Changed: r.Changed}
	for _, c := range r.Changes {
		view.Changes = append(view.Changes, api.PAMDiscoveryChange{Change: c.Change, Account: accountInfo(c.Account)})
	}
	return view
}

// RunPAMAccountDiscovery scans every interval source when it is due, one
// scan at a time.
func (s *Server) RunPAMAccountDiscovery(ctx context.Context) {
	if s.pam == nil {
		<-ctx.Done()
		return
	}
	s.pam.RunAccountDiscovery(ctx)
}

// RunAccountDiscovery checks for due sources every minute.
func (s *pamService) RunAccountDiscovery(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.discoveryPass(ctx)
	}
}

func (s *pamService) discoveryPass(ctx context.Context) {
	sources, err := s.store.ListScheduledPAMDiscoverySources(ctx)
	if err != nil {
		return
	}
	now := s.clock()
	for _, src := range sources {
		if ctx.Err() != nil {
			return
		}
		if now.Before(src.LastFinishedAt.Add(time.Duration(src.IntervalSeconds) * time.Second)) {
			continue
		}
		// A scan the source's own run already holds, or whose event could
		// not be appended, is due again at the next pass.
		_, _ = s.scan(ctx, src.TenantID, src.ProviderID, pamDiscoveryScheduler)
	}
}

func (s *Server) SavePAMDiscoverySource(ctx context.Context, tenantID, actor, providerID string, intervalSeconds int) (api.PAMDiscoverySource, error) {
	if s.pam == nil {
		return api.PAMDiscoverySource{}, api.ErrPAMUnavailable
	}
	return s.pam.SavePAMDiscoverySource(ctx, tenantID, actor, providerID, intervalSeconds)
}

func (s *Server) ListPAMDiscoverySources(ctx context.Context, tenantID string) ([]api.PAMDiscoverySource, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMDiscoverySources(ctx, tenantID)
}

func (s *Server) DeletePAMDiscoverySource(ctx context.Context, tenantID, actor, providerID string) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.DeletePAMDiscoverySource(ctx, tenantID, actor, providerID)
}

func (s *Server) RunPAMDiscovery(ctx context.Context, tenantID, actor, providerID string) (api.PAMDiscoveryRun, error) {
	if s.pam == nil {
		return api.PAMDiscoveryRun{}, api.ErrPAMUnavailable
	}
	return s.pam.RunPAMDiscovery(ctx, tenantID, actor, providerID)
}

func (s *Server) ListPAMDiscoveryRuns(ctx context.Context, tenantID, providerID string, limit int) ([]api.PAMDiscoveryRun, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMDiscoveryRuns(ctx, tenantID, providerID, limit)
}

func (s *Server) GetPAMDiscoveryRun(ctx context.Context, tenantID, id string) (api.PAMDiscoveryRun, error) {
	if s.pam == nil {
		return api.PAMDiscoveryRun{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMDiscoveryRun(ctx, tenantID, id)
}

func (s *Server) ListPAMDiscoveredAccounts(ctx context.Context, tenantID, providerID, status string, includeRemoved bool) ([]api.PAMDiscoveredAccount, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMDiscoveredAccounts(ctx, tenantID, providerID, status, includeRemoved)
}

var _ api.PAMDiscoveryService = (*Server)(nil)
