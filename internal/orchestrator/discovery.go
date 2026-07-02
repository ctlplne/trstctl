package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const discoveryRunDestination = "discovery.run"

var agentInventorySourceNamespace = uuid.MustParse("d5e0734a-9cc6-53a4-92f3-4f99387f8c3a")
var secretScanSourceNamespace = uuid.MustParse("f2a0de71-857b-5a96-83be-0e65a0f2f107")

// UpsertDiscoverySource records a tenant discovery source as an event and returns
// the projected source row. Config is metadata/reference JSON only; API validation
// rejects inline credential values before calling this command.
func (o *Orchestrator) UpsertDiscoverySource(ctx context.Context, tenantID string, in store.DiscoverySource) (store.DiscoverySource, error) {
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	cfg := in.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	payload, err := json.Marshal(projections.DiscoverySourceUpserted{
		ID: id, Kind: in.Kind, Name: in.Name, Config: cfg,
	})
	if err != nil {
		return store.DiscoverySource{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoverySourceUpserted, tenantID, payload)
	if err != nil {
		return store.DiscoverySource{}, err
	}
	return store.DiscoverySource{
		ID: id, TenantID: tenantID, Kind: in.Kind, Name: in.Name, Config: cfg,
		CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}

// UpsertDiscoverySchedule records a source schedule. It refuses an absent source
// before emitting anything, so the event log never contains a dangling schedule.
func (o *Orchestrator) UpsertDiscoverySchedule(ctx context.Context, tenantID string, in store.DiscoverySchedule) (store.DiscoverySchedule, error) {
	if _, err := o.store.GetDiscoverySource(ctx, tenantID, in.SourceID); err != nil {
		return store.DiscoverySchedule{}, err
	}
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	payload, err := json.Marshal(projections.DiscoveryScheduleUpserted{
		ID: id, SourceID: in.SourceID, Name: in.Name, IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled,
	})
	if err != nil {
		return store.DiscoverySchedule{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryScheduleUpserted, tenantID, payload)
	if err != nil {
		return store.DiscoverySchedule{}, err
	}
	return store.DiscoverySchedule{
		ID: id, TenantID: tenantID, SourceID: in.SourceID, Name: in.Name,
		IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled,
		CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}

// QueueDiscoveryRun records a queued run and its external scan intent together.
// The event is the source of truth (AN-2); the outbox row is enqueued in the same
// tenant-scoped transaction as the queued-run projection (AN-6), keyed by the event
// ID so boot reconciliation can recreate a lost outbox intent exactly once.
func (o *Orchestrator) QueueDiscoveryRun(ctx context.Context, tenantID string, in store.DiscoveryRun) (store.DiscoveryRun, error) {
	if _, err := o.store.GetDiscoverySource(ctx, tenantID, in.SourceID); err != nil {
		return store.DiscoveryRun{}, err
	}
	if in.ScheduleID != nil {
		sched, err := o.store.GetDiscoverySchedule(ctx, tenantID, *in.ScheduleID)
		if err != nil {
			return store.DiscoveryRun{}, err
		}
		if sched.SourceID != in.SourceID {
			return store.DiscoveryRun{}, fmt.Errorf("orchestrator: discovery schedule %s belongs to source %s, not %s", sched.ID, sched.SourceID, in.SourceID)
		}
	}
	requestedBy := in.RequestedBy
	if requestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			requestedBy = actor.Subject
		}
	}
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	payload, err := json.Marshal(projections.DiscoveryRunQueued{
		ID: id, SourceID: in.SourceID, ScheduleID: in.ScheduleID, DryRun: in.DryRun, RequestedBy: requestedBy,
	})
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: payload})
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID:       tenantID,
			Destination:    discoveryRunDestination,
			IdempotencyKey: ev.ID,
			Payload:        payload,
		})
		return err
	}); err != nil {
		return store.DiscoveryRun{}, err
	}
	return store.DiscoveryRun{
		ID: id, TenantID: tenantID, SourceID: in.SourceID, ScheduleID: in.ScheduleID,
		Status: "queued", DryRun: in.DryRun, RequestedBy: requestedBy, CreatedAt: ev.Time,
	}, nil
}

// StartDiscoveryRun records that an outbox worker began executing a run.
func (o *Orchestrator) StartDiscoveryRun(ctx context.Context, tenantID, runID string) error {
	payload, err := json.Marshal(projections.DiscoveryRunStarted{ID: runID})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventDiscoveryRunStarted, tenantID, payload)
	return err
}

// RecordDiscoveryFinding records one metadata-only finding for a run.
func (o *Orchestrator) RecordDiscoveryFinding(ctx context.Context, tenantID string, in store.DiscoveryFinding) (store.DiscoveryFinding, error) {
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	meta := in.Metadata
	if len(meta) == 0 {
		meta = json.RawMessage(`{}`)
	}
	payload, err := json.Marshal(projections.DiscoveryFindingRecorded{
		ID: id, RunID: in.RunID, SourceID: in.SourceID, Kind: in.Kind, Ref: in.Ref,
		Provenance: in.Provenance, Fingerprint: in.Fingerprint, RiskScore: in.RiskScore,
		Metadata: meta,
	})
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryFindingRecorded, tenantID, payload)
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	out := in
	out.ID, out.TenantID, out.Metadata, out.DiscoveredAt = id, tenantID, meta, ev.Time
	return out, nil
}

// ClaimDiscoveryFinding marks a tenant finding as managed by an identity. The
// event log is the source of truth; the read model changes only when the
// projection applies discovery.finding.triage_changed.
func (o *Orchestrator) ClaimDiscoveryFinding(ctx context.Context, tenantID, findingID string, managedIdentityID *string, reason string, metadataPatch json.RawMessage) (store.DiscoveryFinding, error) {
	return o.triageDiscoveryFinding(ctx, tenantID, findingID, discovery.TriageManaged, managedIdentityID, reason, metadataPatch)
}

// DismissDiscoveryFinding marks a tenant finding as dismissed.
func (o *Orchestrator) DismissDiscoveryFinding(ctx context.Context, tenantID, findingID, reason string, metadataPatch json.RawMessage) (store.DiscoveryFinding, error) {
	return o.triageDiscoveryFinding(ctx, tenantID, findingID, discovery.TriageDismissed, nil, reason, metadataPatch)
}

// InvestigateDiscoveryFinding marks a tenant finding as actively under review.
func (o *Orchestrator) InvestigateDiscoveryFinding(ctx context.Context, tenantID, findingID, reason string) (store.DiscoveryFinding, error) {
	return o.triageDiscoveryFinding(ctx, tenantID, findingID, discovery.TriageInvestigating, nil, reason, nil)
}

// TriageDiscoveryFinding records an explicit operator triage decision for a
// served workflow that already validated the finding kind and decision vocabulary.
func (o *Orchestrator) TriageDiscoveryFinding(ctx context.Context, tenantID, findingID string, status discovery.TriageStatus, managedIdentityID *string, reason string, metadataPatch json.RawMessage) (store.DiscoveryFinding, error) {
	return o.triageDiscoveryFinding(ctx, tenantID, findingID, status, managedIdentityID, reason, metadataPatch)
}

func (o *Orchestrator) triageDiscoveryFinding(ctx context.Context, tenantID, findingID string, status discovery.TriageStatus, managedIdentityID *string, reason string, metadataPatch json.RawMessage) (store.DiscoveryFinding, error) {
	current, err := o.store.GetDiscoveryFinding(ctx, tenantID, findingID)
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	if err := discovery.ValidateTriageTransition(discovery.TriageStatus(current.TriageStatus), status); err != nil {
		return store.DiscoveryFinding{}, err
	}
	if discovery.TriageStatus(current.TriageStatus) == status {
		return current, nil
	}
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	payload, err := json.Marshal(projections.DiscoveryFindingTriageChanged{
		ID: findingID, Status: string(status), ManagedIdentityID: managedIdentityID,
		Actor: actor, Reason: strings.TrimSpace(reason), MetadataPatch: metadataPatch,
	})
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryFindingTriageChanged, tenantID, payload)
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	return store.DiscoveryFinding{
		ID: findingID, TenantID: tenantID, RunID: current.RunID, SourceID: current.SourceID,
		Kind: current.Kind, Ref: current.Ref, Provenance: current.Provenance, Fingerprint: current.Fingerprint,
		RiskScore: current.RiskScore, Metadata: mergeDiscoveryFindingMetadata(current.Metadata, metadataPatch), DiscoveredAt: current.DiscoveredAt,
		TriageStatus: string(status), ManagedIdentityID: managedIdentityID, TriageActor: actor,
		TriageReason: strings.TrimSpace(reason), TriagedAt: &ev.Time,
	}, nil
}

func mergeDiscoveryFindingMetadata(current, patch json.RawMessage) json.RawMessage {
	if len(patch) == 0 {
		return current
	}
	base := map[string]any{}
	if len(current) > 0 {
		if err := json.Unmarshal(current, &base); err != nil {
			return current
		}
	}
	delta := map[string]any{}
	if err := json.Unmarshal(patch, &delta); err != nil {
		return current
	}
	for key, value := range delta {
		base[key] = value
	}
	merged, err := json.Marshal(base)
	if err != nil {
		return current
	}
	return merged
}

// RecordAgentInventory records one already-executed, metadata-only agent inventory
// batch. Unlike QueueDiscoveryRun, it does not write an outbox row: the external scan
// happened on the agent host before the report reached the control plane. The source,
// run, findings, and terminal counts are still immutable discovery events, so replay
// rebuilds the served inventory exactly.
func (o *Orchestrator) RecordAgentInventory(ctx context.Context, tenantID, agentName, sourceKind string, findings []store.DiscoveryFinding) (store.DiscoveryRun, int, int, error) {
	agentName = strings.TrimSpace(agentName)
	sourceKind = strings.TrimSpace(sourceKind)
	if sourceKind == "" {
		sourceKind = "agent"
	}
	sourceID := uuid.NewSHA1(agentInventorySourceNamespace, []byte(tenantID+"\x00"+agentName+"\x00"+sourceKind)).String()
	sourceName := "agent:" + agentName + ":" + sourceKind
	cfg, err := json.Marshal(map[string]string{"agent": agentName, "source_kind": sourceKind})
	if err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: "agent", Name: sourceName, Config: cfg,
	}); err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}

	runID := uuid.NewString()
	requestedBy := "agent:" + agentName
	payload, err := json.Marshal(projections.DiscoveryRunQueued{
		ID: runID, SourceID: sourceID, RequestedBy: requestedBy,
	})
	if err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryRunQueued, tenantID, payload)
	if err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}
	if err := o.StartDiscoveryRun(ctx, tenantID, runID); err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}

	recorded, rejected := 0, 0
	for _, f := range findings {
		f.Kind = strings.TrimSpace(f.Kind)
		f.Ref = strings.TrimSpace(f.Ref)
		if f.Kind == "" || f.Ref == "" {
			rejected++
			continue
		}
		if f.Provenance == "" {
			f.Provenance = sourceKind + ":" + f.Ref
		}
		f.RunID = runID
		f.SourceID = sourceID
		if _, err := o.RecordDiscoveryFinding(ctx, tenantID, f); err != nil {
			return store.DiscoveryRun{}, recorded, rejected, err
		}
		recorded++
	}

	status := "succeeded"
	msg := ""
	if rejected > 0 {
		status = "partial"
		msg = "some agent inventory findings were rejected"
	}
	if recorded == 0 {
		status = "failed"
		if msg == "" {
			msg = "agent inventory report contained no valid findings"
		}
	}
	if err := o.CompleteDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
		ID: runID, Status: status, Targets: len(findings), Discovered: recorded, Rejected: rejected, Error: msg,
	}); err != nil {
		return store.DiscoveryRun{}, recorded, rejected, err
	}
	return store.DiscoveryRun{
		ID: runID, TenantID: tenantID, SourceID: sourceID, Status: status,
		RequestedBy: requestedBy, Targets: len(findings), Discovered: recorded,
		Rejected: rejected, Error: msg, CreatedAt: ev.Time,
	}, recorded, rejected, nil
}

// RecordSecretScan records one already-executed code secret-scan batch. The
// Gitleaks process has already scanned the target before this method is called;
// this method records the source, run, findings, and terminal counts as immutable
// discovery events so replay rebuilds the served scan findings and graph nodes.
func (o *Orchestrator) RecordSecretScan(ctx context.Context, tenantID, scanner, target string, rulesActive int, findings []store.DiscoveryFinding) (store.DiscoveryRun, int, int, error) {
	scanner = strings.TrimSpace(scanner)
	target = strings.TrimSpace(target)
	if scanner == "" {
		scanner = "gitleaks"
	}
	sourceID := uuid.NewSHA1(secretScanSourceNamespace, []byte(tenantID+"\x00"+scanner+"\x00"+target)).String()
	sourceName := "secretscan:" + scanner
	if target != "" {
		sourceName += ":" + target
	}
	cfg, err := json.Marshal(map[string]any{"scanner": scanner, "target": target, "rules_active": rulesActive})
	if err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: "secret_scan", Name: sourceName, Config: cfg,
	}); err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}

	requestedBy := "api:secrets-scan"
	if actor, ok := events.ActorFromContext(ctx); ok && strings.TrimSpace(actor.Subject) != "" {
		requestedBy = actor.Subject
	}
	runID := uuid.NewString()
	payload, err := json.Marshal(projections.DiscoveryRunQueued{
		ID: runID, SourceID: sourceID, RequestedBy: requestedBy,
	})
	if err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryRunQueued, tenantID, payload)
	if err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}
	if err := o.StartDiscoveryRun(ctx, tenantID, runID); err != nil {
		return store.DiscoveryRun{}, 0, 0, err
	}

	recorded, rejected := 0, 0
	for _, f := range findings {
		f.Kind = strings.TrimSpace(f.Kind)
		f.Ref = strings.TrimSpace(f.Ref)
		if f.Kind == "" || f.Ref == "" {
			rejected++
			continue
		}
		if f.Provenance == "" {
			f.Provenance = scanner + ":" + f.Ref
		}
		f.RunID = runID
		f.SourceID = sourceID
		if _, err := o.RecordDiscoveryFinding(ctx, tenantID, f); err != nil {
			return store.DiscoveryRun{}, recorded, rejected, err
		}
		recorded++
	}

	status := "succeeded"
	msg := ""
	if rejected > 0 {
		status = "partial"
		msg = "some secret-scan findings were rejected"
	}
	if recorded == 0 {
		status = "succeeded"
		msg = "secret scan completed with no findings"
	}
	if err := o.CompleteDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
		ID: runID, Status: status, Targets: len(findings), Discovered: recorded, Rejected: rejected, Error: msg,
	}); err != nil {
		return store.DiscoveryRun{}, recorded, rejected, err
	}
	return store.DiscoveryRun{
		ID: runID, TenantID: tenantID, SourceID: sourceID, Status: status,
		RequestedBy: requestedBy, Targets: len(findings), Discovered: recorded,
		Rejected: rejected, Error: msg, CreatedAt: ev.Time,
	}, recorded, rejected, nil
}

// CompleteDiscoveryRun records terminal run counts. Status is usually
// "succeeded" or "failed"; partial scans use "partial".
func (o *Orchestrator) CompleteDiscoveryRun(ctx context.Context, tenantID string, in store.DiscoveryRun) error {
	payload, err := json.Marshal(projections.DiscoveryRunCompleted{
		ID: in.ID, Status: in.Status, Targets: in.Targets, Discovered: in.Discovered,
		Failed: in.Failed, Rejected: in.Rejected, Error: in.Error,
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventDiscoveryRunCompleted, tenantID, payload)
	return err
}
