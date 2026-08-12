// SPDX-License-Identifier: MPL-2.0

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
	s.recordADCSDrift(ctx, tenantID, domain, agentName, idempotencyKey, report.Inventory.Templates)
	if err := s.orch.RecordADCSInventoryObservedWithEventID(ctx, tenantID,
		orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "adcs-inventory-observed"),
		adcs.InventoryObserved{
			RunID: intent.ID, SourceID: intent.SourceID, Domain: domain,
			AgentID: agentID, AgentName: agentName, DirectoryVerified: report.DirectoryVerified,
			Templates: report.Inventory.Templates, Findings: report.Findings,
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
// returned; when nothing published anything, the observation is labelled
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
func (s *Server) adcsPostureView(ctx context.Context, tenantID string) ([]api.ADCSInventorySource, []api.ADCSTemplate, error) {
	if s.store == nil {
		return nil, nil, nil
	}
	monitoring, err := s.store.ListDiscoveryMonitoringSources(ctx, tenantID)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
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
	return sources, out, nil
}

// recordADCSDrift compares this sweep against the stored one and records the
// semantic difference (epic F2).
//
// Only a change for the WORSE produces an alerting event. An operator who has
// just hardened a template does not need waking for it, and a tool that alerts
// on improvement teaches people to mute it — after which it will not reach them
// on the day it matters. Better and neutral changes are still recorded, because
// an incident timeline needs them.
func (s *Server) recordADCSDrift(ctx context.Context, tenantID, domain, agentName, idempotencyKey string, current []adcs.Template) {
	if s.store == nil || s.log == nil {
		return
	}
	previousRows, err := s.store.ListADCSTemplatePosture(ctx, tenantID, 1000)
	if err != nil {
		return
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
		return
	}
	payload := map[string]any{
		"domain": domain, "agent": agentName,
		"changes": drift.Changes, "lifecycle": drift.Lifecycle,
		"worsened": drift.Worsened(),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	eventType := "adcs.template.drift"
	if drift.Worsened() {
		// A distinct type so the notify matrix can route the alerting case
		// without having to reason about the payload.
		eventType = "adcs.template.drift.worsened"
	}
	_, _ = s.log.Append(ctx, events.Event{
		ID:   orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "adcs-drift"),
		Type: eventType, TenantID: tenantID, Data: encoded,
	})
}
