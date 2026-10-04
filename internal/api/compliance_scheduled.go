// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/cryptoreadiness"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

const ScheduledComplianceReportFormat = "trstctl.compliance.scheduled-report.v1"

// ScheduledComplianceManifest is the exact message signed for one due edge.
// Its payload is a served tenant report captured at GeneratedAt, except the
// audit summary, whose window is the schedule's preceding interval.
type ScheduledComplianceManifest struct {
	Format      string          `json:"format"`
	TenantID    string          `json:"tenant_id"`
	ScheduleID  string          `json:"schedule_id"`
	RunID       string          `json:"run_id"`
	DueAt       time.Time       `json:"due_at"`
	GeneratedAt time.Time       `json:"generated_at"`
	Framework   string          `json:"framework"`
	ReportType  string          `json:"report_type"`
	Payload     json.RawMessage `json:"payload"`
}

type scheduledInventorySnapshot struct {
	Format                 string                          `json:"format"`
	Counts                 store.ComplianceInventoryCounts `json:"counts"`
	NHIInventory           nhiInventoryResponse            `json:"nhi_inventory"`
	NHIViewLimitPerSource  int                             `json:"nhi_view_limit_per_source"`
	NHIViewMayBeIncomplete bool                            `json:"nhi_view_may_be_incomplete"`
}

type scheduledAuditTypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type scheduledAuditSummary struct {
	Format              string                    `json:"format"`
	WindowFrom          time.Time                 `json:"window_from"`
	WindowThrough       time.Time                 `json:"window_through"`
	SourceHeadSequence  uint64                    `json:"source_head_sequence"`
	RecordCount         int                       `json:"record_count"`
	TypeCounts          []scheduledAuditTypeCount `json:"type_counts"`
	FirstEventID        string                    `json:"first_event_id,omitempty"`
	LastEventID         string                    `json:"last_event_id,omitempty"`
	FirstStreamSequence uint64                    `json:"first_stream_sequence,omitempty"`
	LastStreamSequence  uint64                    `json:"last_stream_sequence,omitempty"`
}

// BuildScheduledComplianceArtifact creates one report through the same tenant
// services as on-demand routes, then asks the licensed isolated signer to bind
// tenant, schedule, due edge, run and exact payload. It does not write the
// archive or completion event; those are separate durable worker steps.
func (a *API) BuildScheduledComplianceArtifact(ctx context.Context, tenantID string, schedule store.ComplianceReportSchedule, runID string, generatedAt time.Time) (json.RawMessage, error) {
	if a == nil || a.store == nil || a.complianceEvidence == nil {
		return nil, errors.New("compliance: licensed reporting dependencies are not configured")
	}
	signer, ok := a.complianceEvidence.(ComplianceScheduledSigner)
	if !ok {
		return nil, errors.New("compliance: scheduled-report signer is not attached")
	}
	if schedule.TenantID != tenantID || !schedule.Enabled || schedule.NextRunAt.IsZero() ||
		schedule.IntervalSeconds < minComplianceReportIntervalSeconds ||
		schedule.IntervalSeconds > maxComplianceReportIntervalSeconds ||
		!validComplianceReportType(schedule.ReportType) || generatedAt.IsZero() {
		return nil, errors.New("compliance: scheduled report definition or due edge is invalid")
	}
	if _, err := googleuuid.Parse(runID); err != nil {
		return nil, errors.New("compliance: run id must be a UUID")
	}
	framework, err := ParseComplianceFramework(schedule.Framework)
	if err != nil || string(framework) != schedule.Framework {
		return nil, errors.New("compliance: schedule framework is not canonical")
	}
	payload, err := a.scheduledCompliancePayload(ctx, tenantID, schedule, framework)
	if err != nil {
		return nil, err
	}
	manifest, err := json.Marshal(ScheduledComplianceManifest{
		Format: ScheduledComplianceReportFormat, TenantID: tenantID,
		ScheduleID: schedule.ID, RunID: runID, DueAt: schedule.NextRunAt,
		GeneratedAt: generatedAt.UTC(), Framework: schedule.Framework,
		ReportType: schedule.ReportType, Payload: payload,
	})
	if err != nil {
		return nil, err
	}
	return signer.SignScheduledManifest(ctx, manifest)
}

func (a *API) scheduledCompliancePayload(ctx context.Context, tenantID string, schedule store.ComplianceReportSchedule, framework ComplianceFramework) (json.RawMessage, error) {
	switch schedule.ReportType {
	case "framework_evidence_pack":
		pack, err := a.complianceEvidence.ExportEvidencePack(ctx, tenantID, framework)
		if err != nil {
			return nil, err
		}
		if pack.Format != ComplianceEvidencePackFormat || pack.Framework != string(framework) || len(pack.SignedExport) == 0 || len(pack.PublicKeyDER) == 0 {
			return nil, errors.New("compliance: evidence-pack producer returned incomplete signed evidence")
		}
		return json.Marshal(pack)
	case "inventory_snapshot":
		counts, err := a.store.ComplianceInventoryCounts(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		inventory, err := a.nhiInventory(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		// The on-demand NHI inventory is bounded per source. The signed
		// snapshot names that limit and cannot silently claim exhaustive NHI
		// rows when the source may have been truncated.
		return json.Marshal(scheduledInventorySnapshot{
			Format: "trstctl.compliance.inventory-snapshot.v1", Counts: counts,
			NHIInventory: inventory, NHIViewLimitPerSource: maxNHIInventoryRowsPerSource,
			NHIViewMayBeIncomplete: inventorySourceMayBeTruncated(inventory),
		})
	case "cbom_posture":
		g, err := graph.Build(ctx, a.store, tenantID)
		if err != nil {
			return nil, err
		}
		readiness, err := cryptoreadiness.BuildFromGraph(ctx, a.store, tenantID, g)
		if err != nil {
			return nil, err
		}
		return json.Marshal(readiness)
	case "audit_summary":
		return a.buildScheduledAuditSummary(ctx, tenantID, schedule)
	case "nhi_compliance_mapping":
		report, err := a.buildNHIComplianceReport(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(report)
	default:
		return nil, errors.New("compliance: unsupported scheduled report type")
	}
}

func inventorySourceMayBeTruncated(inventory nhiInventoryResponse) bool {
	return inventory.RecordSummary.CertificateRecords >= maxNHIInventoryRowsPerSource ||
		inventory.RecordSummary.APITokenRecords >= maxNHIInventoryRowsPerSource ||
		inventory.RecordSummary.AgentRecords >= maxNHIInventoryRowsPerSource ||
		inventory.RecordSummary.DiscoveryFindingRecords >= maxNHIInventoryRowsPerSource
}

func (a *API) buildScheduledAuditSummary(ctx context.Context, tenantID string, schedule store.ComplianceReportSchedule) (json.RawMessage, error) {
	if a.log == nil {
		return nil, errors.New("compliance: event log is not configured")
	}
	from := schedule.NextRunAt.Add(-time.Duration(schedule.IntervalSeconds) * time.Second)
	var summary scheduledAuditSummary
	err := a.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		stream, generation, err := a.log.ActiveHistoryIdentity(readCtx)
		if err != nil {
			return err
		}
		key := tenantID + "\x00" + schedule.ID + "\x00" + schedule.NextRunAt.UTC().Format(time.RFC3339Nano) +
			"\x00" + stream + "\x00" + generation
		summary, err = a.scheduledAuditMemo.get(readCtx, a.log, key,
			func(ctx context.Context) (scheduledAuditSummary, uint64, error) {
				return a.replayScheduledAuditSummary(ctx, tenantID, from, schedule.NextRunAt)
			}, nil)
		a.scheduledAuditMemo.prune(64)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("compliance: summarize event window: %w", err)
	}
	return json.Marshal(summary)
}

// replayScheduledAuditSummary is the headMemo rebuild for one tenant's exact
// due window. ReplayThrough pins the signed source head; retries at that head
// reuse the result, while a later append invalidates it.
func (a *API) replayScheduledAuditSummary(ctx context.Context, tenantID string, from, through time.Time) (scheduledAuditSummary, uint64, error) {
	summary := scheduledAuditSummary{
		Format: "trstctl.compliance.audit-summary.v1", WindowFrom: from,
		WindowThrough: through,
	}
	head, err := a.log.LastSequence(ctx)
	if err != nil {
		return scheduledAuditSummary{}, 0, err
	}
	summary.SourceHeadSequence = head
	counts := map[string]int{}
	if head > 0 {
		err = a.log.ReplayThrough(ctx, 1, head, func(event events.Event) error {
			a.scheduledAuditMemo.scannedEvents.Add(1)
			if event.TenantID != tenantID || event.Time.Before(from) || event.Time.After(through) {
				return nil
			}
			if summary.RecordCount == 0 {
				summary.FirstEventID = event.ID
				summary.FirstStreamSequence = event.Sequence
			}
			summary.LastEventID = event.ID
			summary.LastStreamSequence = event.Sequence
			summary.RecordCount++
			counts[event.Type]++
			return nil
		})
	}
	if err != nil {
		return scheduledAuditSummary{}, 0, err
	}
	types := make([]string, 0, len(counts))
	for typ := range counts {
		types = append(types, typ)
	}
	sort.Strings(types)
	summary.TypeCounts = make([]scheduledAuditTypeCount, 0, len(types))
	for _, typ := range types {
		summary.TypeCounts = append(summary.TypeCounts, scheduledAuditTypeCount{Type: typ, Count: counts[typ]})
	}
	return summary, head, nil
}
