// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/projections"
)

var errPAMDiscoveryIntent = errors.New("server: PAM discovery source intent differs")

// Only the original source and its current physical intent can authorize work.
// Terminal failure may recover that source even when the derived payload is corrupt.
func (s *pamService) discoveryIntent(ctx context.Context, m orchestrator.Message, requirePayload bool) (pamdiscovery.ScanIntent, error) {
	var source pamdiscovery.ScanIntent
	runID := strings.TrimPrefix(m.IdempotencyKey, "pam-discovery:")
	if runID == m.IdempotencyKey || m.Destination != pamdiscovery.ScanDestination {
		return source, errPAMDiscoveryIntent
	}
	event, found, err := s.log.EventByID(ctx, runID)
	if err != nil {
		return source, err
	}
	if !found || event.ID != runID || event.TenantID != m.TenantID || event.Type != projections.EventPAMDiscoveryScanQueued || event.SchemaVersion != 1 || json.Unmarshal(event.Data, &source) != nil || source.Validate() != nil || source.RunID != runID {
		return source, errPAMDiscoveryIntent
	}
	canonical, err := json.Marshal(source)
	if err != nil || (requirePayload && (len(m.Payload) > 8192 || !bytes.Equal(canonical, m.Payload))) {
		return source, errPAMDiscoveryIntent
	}
	_, id, err := s.store.GetPAMDiscoveryScanIntent(ctx, m.TenantID, runID)
	if err != nil {
		return source, err
	}
	if id == nil || *id != m.ID {
		return source, errPAMDiscoveryIntent
	}
	return source, nil
}
func (s *pamService) recoverDiscoveryCompletion(ctx context.Context, tenantID string, intent pamdiscovery.ScanIntent) (bool, error) {
	event, found, err := s.log.EventByID(ctx, intent.CompletionEventID)
	if err != nil || !found {
		return found, err
	}
	var value projections.PAMDiscoveryRunCompleted
	if event.TenantID != tenantID || event.Type != projections.EventPAMDiscoveryRunCompleted || event.SchemaVersion != 1 || json.Unmarshal(event.Data, &value) != nil || value.RunID != intent.RunID || value.ProviderID != intent.ProviderID || !value.StartedAt.Equal(intent.QueuedAt) || value.RequestedBy != intent.RequestedBy {
		return true, errPAMDiscoveryIntent
	}
	return true, s.projector.Apply(ctx, event)
}
func (s *pamService) retainDiscoveryCompletion(ctx context.Context, tenantID string, intent pamdiscovery.ScanIntent, value projections.PAMDiscoveryRunCompleted) error {
	if found, err := s.recoverDiscoveryCompletion(ctx, tenantID, intent); found || err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err = s.log.Append(ctx, events.Event{ID: intent.CompletionEventID, TenantID: tenantID, Type: projections.EventPAMDiscoveryRunCompleted, SchemaVersion: 1, Data: raw}); err != nil {
		return err
	}
	found, err := s.recoverDiscoveryCompletion(ctx, tenantID, intent)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("server: PAM discovery completion is not retained")
	}
	return nil
}
func (s *pamService) deliverAccountDiscovery(ctx context.Context, m orchestrator.Message) error {
	intent, err := s.discoveryIntent(ctx, m, true)
	if err != nil {
		return err
	}
	if found, err := s.recoverDiscoveryCompletion(ctx, m.TenantID, intent); found || err != nil {
		return err
	}
	result := projections.PAMDiscoveryRunCompleted{RunID: intent.RunID, ProviderID: intent.ProviderID, RequestedBy: intent.RequestedBy, StartedAt: intent.QueuedAt, Status: "completed", Accounts: []pamdiscovery.Account{}}
	source, err := s.store.GetPAMDiscoverySource(ctx, m.TenantID, intent.ProviderID)
	if err != nil || !source.SavedAt.Equal(intent.SourceSavedAt) {
		result.Status = "failed"
		result.Failure = "source_changed"
	} else {
		provider, readErr := s.discoverer(m.TenantID, intent.ProviderID)
		if readErr == nil {
			bounded, cancel := context.WithTimeout(ctx, pamDiscoveryTimeout)
			result.Accounts, readErr = provider.DynamicSecretDiscoverAccounts(bounded)
			cancel()
		}
		if readErr == nil && len(result.Accounts) > pamdiscovery.MaxAccounts {
			readErr = errDiscoveryTooMany
		}
		if readErr == nil {
			result.Accounts = pamdiscovery.Normalize(result.Accounts)
			for _, account := range result.Accounts {
				if pamdiscovery.ValidateDiscoveredAccount(account) != nil {
					readErr = errors.New("invalid native account metadata")
					break
				}
			}
		}
		if readErr != nil {
			result.Status = "failed"
			result.Failure = discoveryFailure(readErr)
			result.Accounts = []pamdiscovery.Account{}
		}
	}
	result.FinishedAt = s.clock().UTC()
	return s.retainDiscoveryCompletion(ctx, m.TenantID, intent, result)
}
func (s *pamService) failAccountDiscovery(ctx context.Context, m orchestrator.Message) error {
	intent, err := s.discoveryIntent(ctx, m, false)
	if err != nil {
		return err
	}
	result := projections.PAMDiscoveryRunCompleted{RunID: intent.RunID, ProviderID: intent.ProviderID, RequestedBy: intent.RequestedBy, StartedAt: intent.QueuedAt, Status: "failed", Failure: "delivery_failed", Accounts: []pamdiscovery.Account{}, FinishedAt: time.Now().UTC()}
	return s.retainDiscoveryCompletion(ctx, m.TenantID, intent, result)
}
