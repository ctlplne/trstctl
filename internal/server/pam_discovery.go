// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/events"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A260: privileged account discovery. A source is one of the tenant's
// dynamic-secret providers whose administrator connection reads its target's
// accounts: PostgreSQL roles, MySQL users, SQL Server logins, Active
// Directory users (part 2), or a Linux or Unix host's local accounts, sudo
// rights and authorized keys. A scan is read-only, bounded by
// pamDiscoveryTimeout, and one per source at a time; its result is one event,
// whose projection stages the accounts and records what changed since the
// source's previous complete scan. Discovery grants nothing; an import into a
// folder needs independent review and grants nothing either (part 2).

const (
	pamDiscoveryTimeout     = 2 * time.Minute
	pamDiscoveryMinInterval = time.Hour
	pamDiscoveryMaxInterval = 30 * 24 * time.Hour
	pamDiscoveryScheduler   = "scheduler"
)

// pamDiscoveryTypes are the provider types whose targets discovery reads.
var pamDiscoveryTypes = map[string]bool{"postgresql": true, "mysql": true, "mssql": true, "unix": true, "ldap": true,
	"iosxe": true, "junos": true, "eos": true, "fortigate": true, "bigip": true, "redfish": true, "esxi": true, "vcenter-sso": true}

// pamAccountDiscoverer is a provider that can read its target's privileged
// accounts.
type pamAccountDiscoverer interface {
	DynamicSecretProviderType() string
	DynamicSecretDiscoverAccounts(ctx context.Context) ([]pamdiscovery.Account, error)
}

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
			return nil, fmt.Errorf("%w: provider %s cannot list its target's accounts (PostgreSQL, MySQL, SQL Server, Active Directory, Linux or Unix hosts, IOS-XE, Junos, EOS, FortiGate or BIG-IP devices, Redfish controllers, ESXi hosts and vCenter single sign-on can)",
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
	// The host's own scan/outbox model owns pending delivery; the generic
	// account-diff timeline is populated only by completed native observations.
	if src.ProviderType == "windows_local" {
		agentID := strings.TrimPrefix(src.ProviderID, "windows-host:")
		latest, err := s.store.LatestWindowsLocalAccountScan(ctx, tenantID, agentID)
		if err != nil {
			return view, err
		}
		if err = s.canonicalWindowsLocalAccountScan(ctx, tenantID, latest, true); err != nil {
			return view, err
		}
		if latest.Status == "queued" || latest.Status == "retrying" {
			run := discoveryRunView(store.PAMDiscoveryRun{ID: latest.ID, ProviderID: src.ProviderID, Status: "queued", Failure: latest.Failure, DeliveryStatus: latest.DeliveryStatus, StartedAt: latest.QueuedAt, RequestedBy: latest.QueuedBy})
			view.LastRun = &run
			return view, nil
		}
	}
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

// scan records a source-bound read intent; the separate outbox worker owns I/O.
func (s *pamService) scan(ctx context.Context, tenantID, providerID, requestedBy string) (string, error) {
	var id string
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		// A previously appended request must become visible before another admission.
		if err := s.projector.ProjectCatchUp(ctx, s.log); err != nil {
			return err
		}
		source, err := s.store.GetPAMDiscoverySource(ctx, tenantID, providerID)
		if err != nil {
			return err
		}
		pending, err := s.store.PendingPAMDiscoveryScan(ctx, tenantID, providerID)
		if err != nil {
			return err
		}
		if pending {
			return fmt.Errorf("%w: a scan of %s is queued", api.ErrPAMTargetConflict, providerID)
		}
		intent := pamdiscovery.ScanIntent{RunID: uuid.NewString(), CompletionEventID: uuid.NewString(), ProviderID: providerID, SourceSavedAt: source.SavedAt.UTC(), RequestedBy: requestedBy, QueuedAt: s.clock().UTC()}
		if err := intent.Validate(); err != nil {
			return fmt.Errorf("%w: discovery source metadata is invalid", api.ErrPAMInvalid)
		}
		raw, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		event, err := s.log.Append(ctx, events.Event{ID: intent.RunID, TenantID: tenantID, Type: projections.EventPAMDiscoveryScanQueued, SchemaVersion: 1, Data: raw})
		if err != nil {
			return err
		}
		if err = s.projector.Apply(ctx, event); err != nil {
			return err
		}
		id = intent.RunID
		return nil
	})
	if err == nil && s.wakeOutbox != nil {
		s.wakeOutbox()
	}
	return id, err
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
	view := api.PAMDiscoveryRun{ID: r.ID, ProviderID: r.ProviderID, Status: r.Status, Failure: r.Failure, DeliveryStatus: r.DeliveryStatus, RequestedBy: r.RequestedBy,
		StartedAt: r.StartedAt, Accounts: r.Accounts, Added: r.Added, Removed: r.Removed, Changed: r.Changed}
	if !r.FinishedAt.IsZero() {
		value := r.FinishedAt
		view.FinishedAt = &value
	}
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
