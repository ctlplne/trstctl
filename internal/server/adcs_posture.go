// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Recording an in-domain relay's AD CS observation (epic F1).
//
// The relay reads the directory and reports immutable facts. The event
// projector is the only writer of the current posture table, so a cold replay
// rebuilds the same console state without trusting this transport callback.

// recordADCSInventory validates and projects one result while its exact agent
// lease is still held. Any error leaves the claim retryable; receipt-derived
// event IDs make a partial retry converge without duplicating state.
func (s *Server) recordADCSInventory(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	if s.store == nil || s.orch == nil {
		return errors.New("AD CS inventory receiver is not configured")
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return errors.New("AD CS inventory report exceeds the receiver bound")
	}
	var intent adcs.InventoryIntent
	if err := decodeStrictJSON(jobPayload, &intent); err != nil {
		return fmt.Errorf("decode AD CS inventory command: %w", err)
	}
	var report adcs.InventoryReport
	if err := decodeStrictJSON([]byte(reportJSON), &report); err != nil {
		return fmt.Errorf("decode AD CS inventory report: %w", err)
	}
	if err := adcs.ValidateInventoryReport(intent, report); err != nil {
		return err
	}
	if report.Status == "succeeded" && report.DirectoryVerified == intent.InsecureSkipVerify {
		return errors.New("AD CS report directory-verification claim contradicts its command")
	}
	agentID := agentRowID(tenantID, agentName)
	if intent.RequiredAgentID != "" && intent.RequiredAgentID != agentID {
		return errors.New("AD CS inventory receipt does not match the selected relay")
	}
	run, err := s.store.GetDiscoveryRun(ctx, tenantID, intent.ID)
	if err != nil {
		return err
	}
	if run.SourceID != intent.SourceID || run.Execution != adcs.ExecutionRelay ||
		run.RequiredAgentRole != intent.RequiredAgentRole || run.RequiredAgentID != intent.RequiredAgentID {
		return errors.New("AD CS inventory command does not match its projected run")
	}
	if discoveryRunTerminal(run.Status) {
		if run.ExecutedByAgentID == agentID {
			return nil
		}
		return errors.New("AD CS inventory run is already terminal under another executor")
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return errors.New("AD CS inventory claim has no durable idempotency key")
	}
	if run.Status == "queued" {
		if err := s.orch.StartDiscoveryRunWithEventID(ctx, tenantID, intent.ID,
			orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "adcs-run-started")); err != nil {
			return err
		}
	}
	if report.Status == "failed" {
		return s.orch.CompleteDiscoveryRunWithEventID(ctx, tenantID,
			orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "adcs-run-completed"), store.DiscoveryRun{
				ID: intent.ID, Status: "failed", Targets: 1, Failed: 1,
				Error: report.ErrorCode, ExecutedByAgentID: agentID,
			})
	}

	domain := adcsDomainFor(report.Inventory.Templates)
	// Compute drift before the current observation replaces the previous domain.
	if err := s.recordADCSDrift(ctx, tenantID, intent.ID, intent.SourceID, domain,
		agentID, agentName, idempotencyKey, report.Inventory.Templates); err != nil {
		return err
	}
	if err := s.orch.RecordADCSInventoryObservedWithEventID(ctx, tenantID,
		orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "adcs-inventory-observed"),
		adcs.InventoryObserved{
			RunID: intent.ID, SourceID: intent.SourceID, Domain: domain,
			AgentID: agentID, AgentName: agentName, DirectoryVerified: report.DirectoryVerified,
			Templates: report.Inventory.Templates, EnrollmentServices: report.Inventory.EnrollmentServices,
			Findings: report.Findings,
		}); err != nil {
		return err
	}
	return s.orch.CompleteDiscoveryRunWithEventID(ctx, tenantID,
		orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "adcs-run-completed"), store.DiscoveryRun{
			ID: intent.ID, Status: "succeeded", Targets: 1,
			Discovered: len(report.Inventory.Templates), ExecutedByAgentID: agentID,
		})
}

// adcsDomainFor labels the observation.
//
// A forest holds several domains and their template sets are separate. The
// publishing CA's name is the best label available from what the directory
// returned; when nothing published anything, the observation is labeled
// explicitly as unattributed rather than being silently merged into another
// domain's row set.
func adcsDomainFor(templates []adcs.Template) string {
	for _, tpl := range templates {
		for _, ca := range tpl.PublishedBy {
			if ca = strings.TrimSpace(ca); ca != "" {
				return ca
			}
		}
	}
	return "unattributed"
}

// adcsPostureView serves source lifecycle and observed template posture to the API.
func (s *Server) adcsPostureView(ctx context.Context, tenantID string) ([]api.ADCSInventorySource, []api.ADCSTemplate, []api.ADCSEnrollmentService, error) {
	if s.store == nil {
		return nil, nil, nil, nil
	}
	monitoring, err := s.store.ListDiscoveryMonitoringSources(ctx, tenantID)
	if err != nil {
		return nil, nil, nil, err
	}
	sources := make([]api.ADCSInventorySource, 0)
	for _, source := range monitoring {
		if source.Kind != adcs.SourceKind {
			continue
		}
		status := source.LastRunStatus
		if status == "" || status == "queued" {
			status = "pending"
		}
		sources = append(sources, api.ADCSInventorySource{
			SourceID: source.SourceID, Name: source.Name,
			ScheduleID: source.ScheduleID, ScheduleEnabled: source.ScheduleEnabled,
			MonitoringIntervalSeconds: source.MonitoringIntervalSeconds,
			LastRunID:                 source.LastRunID, LastRunStatus: status, LastRunError: source.LastRunError,
			LastRunCreatedAt: source.LastRunCreatedAt, LastRunCompletedAt: source.LastRunCompletedAt,
		})
	}
	rows, err := s.store.ListADCSTemplatePosture(ctx, tenantID, 500)
	if err != nil {
		return nil, nil, nil, err
	}
	out := make([]api.ADCSTemplate, 0, len(rows))
	for _, row := range rows {
		var findings []api.ADCSTemplateFinding
		if len(row.Findings) > 0 {
			// A row whose findings do not decode still shows the template: the
			// template's existence and its attributes are facts worth keeping
			// on the page even when the verdict cannot be read.
			_ = json.Unmarshal(row.Findings, &findings)
		}
		if findings == nil {
			findings = []api.ADCSTemplateFinding{}
		}
		published := row.PublishedBy
		if published == nil {
			published = []string{}
		}
		principals := []string{}
		if len(row.ObservedTemplate) > 0 {
			var observed adcs.Template
			if json.Unmarshal(row.ObservedTemplate, &observed) == nil && observed.EnrollmentPrincipals != nil {
				principals = observed.EnrollmentPrincipals
			}
		}
		out = append(out, api.ADCSTemplate{
			Domain: row.Domain, Template: row.Template, DisplayName: row.DisplayName,
			SchemaVersion: row.SchemaVersion, PublishedBy: published, EnrollmentPrincipals: principals,
			WorstSeverity: row.WorstSeverity, Findings: findings,
			ObservedBy: row.ObservedBy, ObservedAt: row.ObservedAt,
		})
	}
	serviceRows, err := s.store.ListADCSEnrollmentServicePosture(ctx, tenantID, 500)
	if err != nil {
		return nil, nil, nil, err
	}
	services := make([]api.ADCSEnrollmentService, 0, len(serviceRows))
	for _, row := range serviceRows {
		var observed adcs.EnrollmentService
		if err := json.Unmarshal(row.ObservedService, &observed); err != nil {
			return nil, nil, nil, fmt.Errorf("decode projected AD CS enrollment service %s: %w", row.Service, err)
		}
		var findings []api.ADCSTemplateFinding
		if err := json.Unmarshal(row.Findings, &findings); err != nil {
			return nil, nil, nil, fmt.Errorf("decode projected AD CS service findings %s: %w", row.Service, err)
		}
		if findings == nil {
			findings = []api.ADCSTemplateFinding{}
		}
		endpoints := make([]api.ADCSEnrollmentEndpoint, 0, len(observed.Endpoints))
		for _, endpoint := range observed.Endpoints {
			authentication := endpoint.Authentication
			if authentication == nil {
				authentication = []string{}
			}
			endpoints = append(endpoints, api.ADCSEnrollmentEndpoint{
				Kind: string(endpoint.Kind), URL: endpoint.URL, State: string(endpoint.State),
				HTTPStatus: endpoint.HTTPStatus, Authentication: authentication,
				TLSVerified: endpoint.TLSVerified, ExtendedProtection: string(endpoint.ExtendedProtection),
			})
		}
		webServices := row.EnrollmentWebServices
		if webServices == nil {
			webServices = []string{}
		}
		services = append(services, api.ADCSEnrollmentService{
			Domain: row.Domain, Service: row.Service, DNSName: row.DNSName,
			EnrollmentWebServices: webServices, Endpoints: endpoints,
			AgentRestrictionState: row.AgentRestrictionState, AgentRestrictionSource: row.AgentRestrictionSource,
			WorstSeverity: row.WorstSeverity, Findings: findings,
			ObservedBy: row.ObservedBy, ObservedAt: row.ObservedAt,
		})
	}
	return sources, out, services, nil
}

// adcsDriftView turns the immutable discovery-finding projection back into its
// purpose-built API shape. The row and metadata must agree on run/source; a
// corrupted or hand-written row fails closed instead of being served as relay
// evidence.
func (s *Server) adcsDriftView(ctx context.Context, tenantID string, limit int) ([]api.ADCSTemplateDrift, error) {
	if s.store == nil {
		return []api.ADCSTemplateDrift{}, nil
	}
	rows, err := s.store.ListADCSTemplateDrift(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]api.ADCSTemplateDrift, 0, len(rows))
	for _, row := range rows {
		var recorded projections.ADCSTemplateDriftObserved
		if err := json.Unmarshal(row.Metadata, &recorded); err != nil {
			return nil, fmt.Errorf("decode projected AD CS drift %s: %w", row.ID, err)
		}
		if recorded.RunID != row.RunID || recorded.SourceID != row.SourceID ||
			recorded.Domain != row.Ref {
			return nil, fmt.Errorf("projected AD CS drift %s disagrees with its source/run row", row.ID)
		}
		changes := make([]api.ADCSTemplateDriftChange, 0, len(recorded.Changes))
		for _, change := range recorded.Changes {
			changes = append(changes, api.ADCSTemplateDriftChange{
				Template: change.Template, Direction: string(change.Direction), Change: change.Change,
				Attribute: change.Attribute, Before: change.Before, After: change.After,
			})
		}
		lifecycle := make([]api.ADCSTemplateLifecycleChange, 0, len(recorded.Lifecycle))
		for _, change := range recorded.Lifecycle {
			lifecycle = append(lifecycle, api.ADCSTemplateLifecycleChange{
				Template: change.Template, Lifecycle: string(change.Lifecycle),
				WasDangerous: change.WasDangerous, NowDangerous: change.NowDangerous,
			})
		}
		out = append(out, api.ADCSTemplateDrift{
			ID: row.ID, RunID: row.RunID, SourceID: row.SourceID,
			Domain: recorded.Domain, AgentID: recorded.AgentID, ObservedBy: recorded.ObservedBy,
			ObservedAt: row.DiscoveredAt, Direction: string(recorded.Direction), Worsened: recorded.Worsened,
			Changes: changes, Lifecycle: lifecycle,
		})
	}
	return out, nil
}

// recordADCSDrift compares this sweep against the stored one and records the
// semantic difference (epic F2).
//
// Only a change for the WORSE produces an alerting event. An operator who has
// just hardened a template does not need waking for it, and a tool that alerts
// on improvement teaches people to mute it — after which it will not reach them
// on the day it matters. Better and neutral changes are still recorded, because
// an incident timeline needs them.
func (s *Server) recordADCSDrift(
	ctx context.Context,
	tenantID, runID, sourceID, domain, agentID, agentName, idempotencyKey string,
	current []adcs.Template,
) error {
	if s.store == nil || s.log == nil {
		return errors.New("AD CS drift recorder is not configured")
	}
	previousRows, err := s.store.ListADCSTemplatePosture(ctx, tenantID, 1000)
	if err != nil {
		return err
	}
	previous := make([]adcs.Template, 0, len(previousRows))
	for _, row := range previousRows {
		if row.Domain != domain {
			continue
		}
		// The template as the directory reported it last time. A row written
		// before 0105 has none, and is SKIPPED rather than reconstructed:
		// diffing against a template whose flags all read false would report it
		// as having just turned dangerous, which is precisely the false alarm
		// this epic must not produce. One quiet sweep to re-baseline is the
		// right cost.
		if len(row.ObservedTemplate) == 0 || string(row.ObservedTemplate) == "{}" {
			continue
		}
		var tpl adcs.Template
		if err := json.Unmarshal(row.ObservedTemplate, &tpl); err != nil {
			continue
		}
		previous = append(previous, tpl)
	}
	drift := adcs.DiffTemplates(previous, current)
	if len(drift.Changes) == 0 && len(drift.Lifecycle) == 0 {
		return nil
	}
	if drift.Changes == nil {
		drift.Changes = []adcs.TemplateChange{}
	}
	if drift.Lifecycle == nil {
		drift.Lifecycle = []adcs.LifecycleChange{}
	}
	payload := projections.ADCSTemplateDriftObserved{
		RunID: runID, SourceID: sourceID, Domain: domain,
		AgentID: agentID, ObservedBy: agentName,
		Direction: drift.Direction(), Worsened: drift.Worsened(),
		Changes: drift.Changes, Lifecycle: drift.Lifecycle,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	eventType := projections.EventADCSTemplateDriftObserved
	if drift.Worsened() {
		// A distinct type so the notify matrix can route the alerting case
		// without having to reason about the payload.
		eventType = projections.EventADCSTemplateDriftWorsened
	}
	event, err := s.log.Append(ctx, events.Event{
		ID:   orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "adcs-drift-v2"),
		Type: eventType, TenantID: tenantID, Data: encoded,
		SchemaVersion: projections.ADCSTemplateDriftEventSchemaVersion,
	})
	if err != nil {
		return err
	}
	// The drift finding and optional notification outbox row commit together in
	// this projector transaction. A crash after append is safe: the retained
	// event is replayed on retry/startup and the deterministic IDs converge.
	return projections.New(s.store).Apply(ctx, event)
}
