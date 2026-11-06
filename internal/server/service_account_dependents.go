// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func (s *pamService) dependentAccountBinding(ctx context.Context, tenantID, id string) (servicedependents.AccountBinding, error) {
	var binding servicedependents.AccountBinding
	if !validUUID(id) {
		return binding, store.ErrPAMDiscoveredAccountNotFound
	}
	account, err := s.store.GetPAMDiscoveredAccount(ctx, tenantID, id)
	if err != nil {
		return binding, err
	}
	source, err := s.store.GetPAMDiscoverySource(ctx, tenantID, account.ProviderID)
	if err != nil {
		return binding, err
	}
	if account.RemovedAt != nil || account.Status == "dismissed" || source.ProviderType != "ldap" || (account.Account.Kind != pamdiscovery.KindDirectoryServiceAccount && account.Account.Kind != pamdiscovery.KindDirectoryUser) {
		return binding, fmt.Errorf("%w: a current native AD account is required", api.ErrPAMInvalid)
	}
	binding = servicedependents.AccountBinding{AccountID: account.ID, ProviderID: account.ProviderID, Name: account.Account.Name, DN: account.Account.Details["dn"], SID: account.Account.Details["native_sid"], GUID: account.Account.Details["native_guid"]}
	if err := binding.Validate(); err != nil {
		return binding, fmt.Errorf("%w: native AD SID/GUID binding is incomplete", api.ErrPAMInvalid)
	}
	return binding, nil
}
func (s *pamService) SavePAMServiceDependentHost(ctx context.Context, tenantID, actor, accountID, agentID string, enabled bool) (store.ServiceDependentHost, error) {
	var saved store.ServiceDependentHost
	if actor == "" || !validUUID(agentID) {
		return saved, fmt.Errorf("%w: an authenticated author and enrolled host UUID are required", api.ErrPAMInvalid)
	}
	parsed, _ := uuid.Parse(agentID)
	agentID = parsed.String()
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		account, err := s.dependentAccountBinding(ctx, tenantID, accountID)
		if err != nil {
			return err
		}
		host, err := s.store.GetAgent(ctx, tenantID, agentID)
		if err != nil {
			return store.ErrServiceDependentHostNotFound
		}
		if host.OffboardedAt != nil || !slices.Contains(host.Roles, mtls.AgentRoleHost) {
			return fmt.Errorf("%w: the agent must be an enrolled host, never a gateway or network relay", api.ErrPAMInvalid)
		}
		old, err := s.store.GetServiceDependentHost(ctx, tenantID, accountID, agentID)
		if err == nil && old.Binding.Account == account && old.Binding.Enabled == enabled {
			saved = old
			return nil
		}
		if err != nil && !errors.Is(err, store.ErrServiceDependentHostNotFound) {
			return err
		}
		if active, e := s.store.NativeStaticRotationInFlight(ctx, tenantID, account); e != nil {
			return e
		} else if active {
			return fmt.Errorf("%w: native account rotation is active; retain its frozen dependent host set until it finishes or recovers", api.ErrPAMTargetConflict)
		}
		value := projections.ServiceDependentHostSaved{Account: account, AgentID: agentID, Enabled: enabled, Actor: actor, At: s.clock().UTC()}
		if err := s.appendServiceDependentEvent(ctx, tenantID, uuid.NewString(), projections.EventServiceDependentHostSaved, value); err != nil {
			return err
		}
		saved, err = s.store.GetServiceDependentHost(ctx, tenantID, accountID, agentID)
		return err
	})
	return saved, err
}
func (s *pamService) ListPAMServiceDependentHosts(ctx context.Context, tenantID, accountID, after string, limit int) (api.PAMServiceDependentHostList, error) {
	result := api.PAMServiceDependentHostList{Items: []store.ServiceDependentHost{}}
	if !validUUID(accountID) {
		return result, store.ErrPAMDiscoveredAccountNotFound
	}
	if _, err := s.store.GetPAMDiscoveredAccount(ctx, tenantID, accountID); err != nil {
		return result, err
	}
	if after == "" {
		after = store.ZeroUUID
	} else {
		parsed, err := uuid.Parse(after)
		if err != nil {
			return result, fmt.Errorf("%w: after must be an agent UUID", api.ErrPAMInvalid)
		}
		after = parsed.String()
	}
	if limit < 1 || limit > 256 {
		return result, fmt.Errorf("%w: limit must be 1-256", api.ErrPAMInvalid)
	}
	hosts, err := s.store.ListServiceDependentHosts(ctx, tenantID, accountID, after, limit)
	if err != nil {
		return result, err
	}
	if len(hosts) > limit {
		hosts = hosts[:limit]
		result.NextCursor = hosts[len(hosts)-1].Binding.AgentID
	}
	var agentIDs []string
	for _, host := range hosts {
		agentIDs = append(agentIDs, host.Binding.AgentID)
	}
	latest, err := s.store.LatestServiceDependentScans(ctx, tenantID, accountID, agentIDs)
	if err != nil {
		return result, err
	}
	for i := range hosts {
		if head, ok := latest[hosts[i].Binding.AgentID]; ok {
			head.Current = head.BindingDigest == hosts[i].BindingDigest && hosts[i].Binding.Enabled
			hosts[i].LatestScan = &head
		}
	}
	result.Items = append(result.Items, hosts...)
	return result, nil
}
func (s *pamService) RunPAMServiceDependentInventory(ctx context.Context, tenantID, actor, accountID, agentID string) (store.ServiceDependentScan, error) {
	var result store.ServiceDependentScan
	if actor == "" || !validUUID(agentID) {
		return result, fmt.Errorf("%w: an authenticated author and exact host are required", api.ErrPAMInvalid)
	}
	parsed, _ := uuid.Parse(agentID)
	agentID = parsed.String()
	if !s.windowsDependentInventoryEnabled {
		return result, fmt.Errorf("%w: enable host.windows_dependents.inventory in agent.claimable_job_kinds first", api.ErrPAMInvalid)
	}
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		account, err := s.dependentAccountBinding(ctx, tenantID, accountID)
		if err != nil {
			return err
		}
		host, err := s.store.GetServiceDependentHost(ctx, tenantID, accountID, agentID)
		if err != nil {
			return err
		}
		if host.Binding.Account != account {
			return fmt.Errorf("%w: native account identity changed; review and save this host binding again", api.ErrPAMInvalid)
		}
		agent, err := s.store.GetAgent(ctx, tenantID, agentID)
		if err != nil {
			return store.ErrServiceDependentHostNotFound
		}
		if agent.OffboardedAt != nil || !slices.Contains(agent.Roles, mtls.AgentRoleHost) {
			return fmt.Errorf("%w: enrolled host authority is unavailable", api.ErrPAMInvalid)
		}
		intent, err := servicedependents.NewInventoryIntent(uuid.NewString(), host.Binding)
		if err != nil {
			return fmt.Errorf("%w: host binding is disabled or incomplete", api.ErrPAMInvalid)
		}
		value := projections.ServiceDependentScanQueued{Intent: intent, Actor: actor, At: s.clock().UTC()}
		if err := s.appendServiceDependentEvent(ctx, tenantID, intent.RunID, projections.EventServiceDependentScanQueued, value); err != nil {
			return err
		}
		result, err = s.store.GetServiceDependentScan(ctx, tenantID, intent.RunID)
		return err
	})
	if err == nil && s.wakeOutbox != nil {
		s.wakeOutbox()
	}
	return result, err
}
func (s *pamService) GetPAMServiceDependentScan(ctx context.Context, tenantID, id string) (store.ServiceDependentScan, error) {
	if !validUUID(id) {
		return store.ServiceDependentScan{}, store.ErrServiceDependentScanNotFound
	}
	return s.store.GetServiceDependentScan(ctx, tenantID, id)
}
func (s *pamService) appendServiceDependentEvent(ctx context.Context, tenantID, id, kind string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	event, err := s.log.Append(ctx, events.Event{ID: id, TenantID: tenantID, Type: kind, Data: raw, SchemaVersion: 1})
	if err != nil {
		return err
	}
	return s.projector.Apply(ctx, event)
}

func (s *Server) SavePAMServiceDependentHost(ctx context.Context, tenantID, actor, accountID, agentID string, enabled bool) (store.ServiceDependentHost, error) {
	if s.pam == nil {
		return store.ServiceDependentHost{}, api.ErrPAMUnavailable
	}
	return s.pam.SavePAMServiceDependentHost(ctx, tenantID, actor, accountID, agentID, enabled)
}
func (s *Server) ListPAMServiceDependentHosts(ctx context.Context, tenantID, accountID, after string, limit int) (api.PAMServiceDependentHostList, error) {
	if s.pam == nil {
		return api.PAMServiceDependentHostList{}, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMServiceDependentHosts(ctx, tenantID, accountID, after, limit)
}
func (s *Server) RunPAMServiceDependentInventory(ctx context.Context, tenantID, actor, accountID, agentID string) (store.ServiceDependentScan, error) {
	if s.pam == nil {
		return store.ServiceDependentScan{}, api.ErrPAMUnavailable
	}
	return s.pam.RunPAMServiceDependentInventory(ctx, tenantID, actor, accountID, agentID)
}
func (s *Server) GetPAMServiceDependentScan(ctx context.Context, tenantID, id string) (store.ServiceDependentScan, error) {
	if s.pam == nil {
		return store.ServiceDependentScan{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMServiceDependentScan(ctx, tenantID, id)
}

var _ api.PAMServiceDependentDiscoveryService = (*Server)(nil)
