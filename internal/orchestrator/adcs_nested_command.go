// SPDX-License-Identifier: BUSL-1.1
package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// BoundADCSNestedCommand binds every target, credential reference and scope to
// the immutable queued command before claim, redemption, recovery or ingestion.
func (o *Orchestrator) BoundADCSNestedCommand(ctx context.Context, tenantID, eventID string, payload []byte) (adcsdiscovery.InventoryIntent, error) {
	var empty adcsdiscovery.InventoryIntent
	if o.log == nil {
		return empty, errors.New("AD CS source log is unavailable")
	}
	event, found, err := o.log.EventByID(ctx, eventID)
	if err != nil {
		return empty, err
	}
	if !found || event.TenantID != tenantID || event.Type != projections.EventDiscoveryRunQueued || event.SchemaVersion != projections.DiscoveryEnrollmentGroupsQueuedSchemaVersion {
		return empty, errors.New("AD CS nested job has no immutable scoped command")
	}
	if err := projections.ValidateSchemaVersion(event); err != nil {
		return empty, err
	}
	decode := func(raw []byte) (adcsdiscovery.InventoryIntent, error) {
		var out adcsdiscovery.InventoryIntent
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&out); err != nil {
			return empty, err
		}
		if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return empty, errors.New("AD CS nested command has trailing JSON")
		}
		if out.JobKind != adcsdiscovery.NestedGroupsJobKind || !out.NestedGroupsEnabled || out.RequiredAgentID == "" || out.RequiredAgentRole != adcsdiscovery.RequiredRoleNetwork || out.Execution != adcsdiscovery.ExecutionRelay || out.MembershipDomainDN == "" || out.ID == "" || out.SourceID == "" {
			return empty, errors.New("AD CS nested command lacks its capability and scope")
		}
		return out, nil
	}
	source, err := decode(event.Data)
	if err != nil {
		return empty, err
	}
	candidate, err := decode(payload)
	if err != nil {
		return empty, err
	}
	a, _ := json.Marshal(source)
	b, _ := json.Marshal(candidate)
	if !bytes.Equal(a, b) {
		return empty, errors.New("AD CS nested job differs from its immutable command")
	}
	return source, nil
}

// A new source capability cannot rely on a heartbeat alone: an older binary
// silently ignores new JSON options and never claims the new kind.
func nestedADCSReaderReady(agent store.Agent, staleBefore, futureLimit time.Time) bool {
	if agent.ExecutorsReportedAt == nil || agent.ExecutorsReportedAt.Before(staleBefore) || agent.ExecutorsReportedAt.After(futureLimit) {
		return false
	}
	var census projections.AgentExecutorCensus
	if json.Unmarshal(agent.Executors, &census) != nil || census.PendingReportError != "" || census.Version == "" {
		return false
	}
	for _, kind := range census.Kinds {
		if kind.Kind == adcsdiscovery.NestedGroupsJobKind && len(kind.MissingFlags) == 0 {
			return true
		}
	}
	return false
}
