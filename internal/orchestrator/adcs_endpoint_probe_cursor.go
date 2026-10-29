// SPDX-License-Identifier: BUSL-1.1
package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/projections"
)

// The SQL row selects a run, never a cursor. Only its retained immutable
// command and validated observation can authorize the next page. Failed reads
// keep the requested cursor so retrying cannot silently skip a page.
func (o *Orchestrator) previousADCSEndpointProbeCursor(ctx context.Context, tenantID, sourceID string) (*adcs.EndpointProbeCursor, error) {
	previous, err := o.store.GetLatestDiscoveryRunForSource(ctx, tenantID, sourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	key := DiscoveryRelayEventID(tenantID, previous.ID, "adcs-endpoint-probe-queued")
	queued, found, err := o.log.EventByID(ctx, key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	} // Earlier inventory kinds have no page cursor.
	command, err := o.BoundADCSNestedCommand(ctx, tenantID, key, queued.Data)
	if err != nil {
		return nil, err
	}
	if command.ID != previous.ID || command.SourceID != sourceID || command.JobKind != adcs.EndpointProbeJobKind {
		return nil, errors.New("AD CS previous page command differs from its source/run")
	}
	observed, found, err := o.log.EventByID(ctx, DiscoveryRelayEventID(tenantID, key, "adcs-inventory-observed"))
	if err != nil {
		return nil, err
	}
	if !found {
		return command.PreviousProbePage, nil
	}
	if observed.TenantID != tenantID || observed.Type != projections.EventADCSInventoryObserved || (observed.SchemaVersion < adcs.InventoryEndpointProbeSchemaVersion || observed.SchemaVersion > adcs.InventoryEventSchemaVersion) {
		return nil, errors.New("AD CS previous page observation has the wrong identity or version")
	}
	facts, err := adcs.DecodeInventoryObservation(observed.SchemaVersion, observed.Data)
	if err != nil {
		return nil, err
	}
	if facts.RunID != previous.ID || facts.SourceID != sourceID || facts.AgentID != command.RequiredAgentID || facts.EndpointProbePage == nil || facts.DirectoryVerified == command.InsecureSkipVerify {
		return nil, errors.New("AD CS previous page observation differs from its command authority")
	}
	if err := facts.Validate(); err != nil {
		return nil, err
	}
	if err := adcs.ValidateInventoryReport(command, adcs.InventoryReport{Status: "succeeded", DirectoryVerified: facts.DirectoryVerified, Inventory: adcs.Inventory{Templates: facts.Templates, EnrollmentServices: facts.EnrollmentServices, EndpointProbePage: facts.EndpointProbePage}, Findings: facts.Findings}); err != nil {
		return nil, fmt.Errorf("AD CS previous page no longer binds its immutable command: %w", err)
	}
	return &adcs.EndpointProbeCursor{PlanDigest: facts.EndpointProbePage.PlanDigest, NextOffset: facts.EndpointProbePage.NextOffset}, nil
}
