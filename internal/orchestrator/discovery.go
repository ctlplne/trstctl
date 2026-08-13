// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/discovery"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const discoveryRunDestination = "discovery.run"

const (
	maxDiscoveryRunErrorBytes = 1024
	discoveryRunErrorWithheld = "withheld: discovery error still contained secret-like material after redaction"
)

// ErrDiscoveryScheduleNotDue is the benign loser of a concurrent scheduler
// race. The winner already committed the run/outbox pair; callers should not
// count or log the loser as a failed delivery.
var ErrDiscoveryScheduleNotDue = errors.New("orchestrator: discovery schedule is no longer due")

var agentInventorySourceNamespace = uuid.MustParse("d5e0734a-9cc6-53a4-92f3-4f99387f8c3a")
var secretScanSourceNamespace = uuid.MustParse("f2a0de71-857b-5a96-83be-0e65a0f2f107")
var discoverySourceNamespace = uuid.MustParse("c47d7a97-a79c-5a36-a5b4-673b5afbe3cf")
var discoverySegmentNamespace = uuid.MustParse("5afb44ec-8cfa-5e68-a135-150af6c36e87")
var discoveryRelayEventNamespace = uuid.MustParse("78899482-854a-5b4d-9276-d8d574bdd340")

// DiscoveryRelayEventID turns one durable job key plus one semantic step into
// an opaque producer identity. Concurrent or crash-retried signed receipts then
// append one immutable event per step rather than merely converging in SQL.
func DiscoveryRelayEventID(tenantID, idempotencyKey, purpose string) string {
	return uuid.NewSHA1(discoveryRelayEventNamespace,
		[]byte(tenantID+"\x00"+idempotencyKey+"\x00"+purpose)).String()
}

// UpsertDiscoverySegment records the operator's declared scan denominator as
// an event. Completing a run records freshness separately; editing the declared
// boundary never manufactures an observation.
func (o *Orchestrator) UpsertDiscoverySegment(ctx context.Context, tenantID string, in store.DiscoverySegment) (store.DiscoverySegment, error) {
	name := strings.TrimSpace(in.Name)
	id := in.ID
	if id == "" {
		id = uuid.NewSHA1(discoverySegmentNamespace, []byte(tenantID+"\x00"+name)).String()
	}
	ranges := append([]string(nil), in.Ranges...)
	if ranges == nil {
		ranges = []string{}
	}
	payload, err := json.Marshal(projections.DiscoverySegmentUpserted{
		ID: id, Name: name, Ranges: ranges, StalenessHours: in.StalenessHours,
		Excluded: in.Excluded, ExclusionReason: strings.TrimSpace(in.ExclusionReason),
	})
	if err != nil {
		return store.DiscoverySegment{}, err
	}
	if _, err := o.emit(ctx, projections.EventDiscoverySegmentUpserted, tenantID, payload); err != nil {
		return store.DiscoverySegment{}, err
	}
	return o.store.GetDiscoverySegmentByName(ctx, tenantID, name)
}

// UpsertDiscoverySource records a tenant discovery source as an event and returns
// the projected source row. Config is metadata/reference JSON only; API validation
// rejects inline credential values before calling this command.
func (o *Orchestrator) UpsertDiscoverySource(ctx context.Context, tenantID string, in store.DiscoverySource) (store.DiscoverySource, error) {
	name := strings.TrimSpace(in.Name)
	id := in.ID
	if id == "" {
		existing, err := o.store.GetDiscoverySourceByName(ctx, tenantID, name)
		switch {
		case err == nil:
			id = existing.ID
		case errors.Is(err, pgx.ErrNoRows):
			// The stable tenant+name identity also closes the concurrent-create
			// race: two first writers project the same row instead of colliding
			// on the tenant-local unique name.
			id = uuid.NewSHA1(discoverySourceNamespace, []byte(tenantID+"\x00"+name)).String()
		default:
			return store.DiscoverySource{}, err
		}
	}
	cfg := in.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	payload, err := json.Marshal(projections.DiscoverySourceUpserted{
		ID: id, Kind: in.Kind, Name: name, Config: cfg,
	})
	if err != nil {
		return store.DiscoverySource{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoverySourceUpserted, tenantID, payload)
	if err != nil {
		return store.DiscoverySource{}, err
	}
	return store.DiscoverySource{
		ID: id, TenantID: tenantID, Kind: in.Kind, Name: name, Config: cfg,
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
	source, err := o.store.GetDiscoverySource(ctx, tenantID, in.SourceID)
	if err != nil {
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
	queued := projections.DiscoveryRunQueued{
		ID: id, SourceID: in.SourceID, ScheduleID: in.ScheduleID, DryRun: in.DryRun, RequestedBy: requestedBy,
		Execution: segmentscan.ExecutionControlPlane,
	}
	destination := discoveryRunDestination
	var command any = queued
	if source.Kind == "network" || source.Kind == "ssh" {
		resolved, err := segmentscan.Resolve(source.Kind, source.Config)
		if err != nil {
			return store.DiscoveryRun{}, err
		}
		segment, err := o.store.GetDiscoverySegmentByName(ctx, tenantID, resolved.Segment)
		if err != nil {
			return store.DiscoveryRun{}, fmt.Errorf("orchestrator: resolve discovery segment: %w", err)
		}
		if segment.Excluded {
			return store.DiscoveryRun{}, fmt.Errorf("orchestrator: discovery segment %q is declared out of scope", segment.Name)
		}
		if err := o.validateDiscoveryNetworkRelay(ctx, tenantID, resolved.RequiredAgentID); err != nil {
			return store.DiscoveryRun{}, err
		}
		resolved.ID, resolved.SourceID, resolved.ScheduleID = id, in.SourceID, in.ScheduleID
		resolved.DryRun, resolved.RequestedBy = in.DryRun, requestedBy
		queued = resolved
		command = resolved
	} else if source.Kind == adcsdiscovery.SourceKind {
		if in.DryRun {
			return store.DiscoveryRun{}, errors.New("orchestrator: AD CS inventory is already read-only and does not support dry-run")
		}
		resolved, err := adcsdiscovery.ResolveInventoryIntent(source.Config)
		if err != nil {
			return store.DiscoveryRun{}, err
		}
		if err := o.validateDiscoveryNetworkRelay(ctx, tenantID, resolved.RequiredAgentID); err != nil {
			return store.DiscoveryRun{}, err
		}
		resolved.ID, resolved.SourceID, resolved.ScheduleID = id, in.SourceID, in.ScheduleID
		resolved.RequestedBy = requestedBy
		queued = projections.DiscoveryRunQueued{
			ID: id, SourceID: in.SourceID, JobKind: resolved.JobKind,
			ScheduleID: in.ScheduleID, RequestedBy: requestedBy,
			Execution: resolved.Execution, RequiredAgentRole: resolved.RequiredAgentRole,
			RequiredAgentID: resolved.RequiredAgentID,
		}
		command = resolved
		destination = adcsdiscovery.JobKind
	}
	commandPayload, err := json.Marshal(command)
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	var ev events.Event
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if in.OnlyIfDue && in.ScheduleID != nil {
			if _, err := tx.Exec(ctx,
				`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
				"discovery-schedule-due\x1f"+tenantID+"\x1f"+*in.ScheduleID); err != nil {
				return fmt.Errorf("orchestrator: lock discovery schedule due decision: %w", err)
			}
			var due bool
			if err := tx.QueryRow(ctx,
				`SELECT NOT EXISTS (
				   SELECT 1
				     FROM discovery_runs r
				     JOIN discovery_schedules s
				       ON s.tenant_id = r.tenant_id AND s.id = $2::uuid
				    WHERE r.tenant_id = $1::uuid
				      AND r.source_id = s.source_id
				      AND (r.status IN ('queued', 'running')
				           OR r.created_at > clock_timestamp() - make_interval(secs => GREATEST(s.interval_seconds, 1)))
				 )`, tenantID, *in.ScheduleID).Scan(&due); err != nil {
				return fmt.Errorf("orchestrator: recheck discovery schedule due decision: %w", err)
			}
			if !due {
				return ErrDiscoveryScheduleNotDue
			}
		}
		var err error
		ev, err = o.log.Append(ctx, events.Event{Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: commandPayload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID:          tenantID,
			Destination:       destination,
			IdempotencyKey:    ev.ID,
			Payload:           commandPayload,
			RequiredAgentRole: queued.RequiredAgentRole,
			RequiredAgentID:   queued.RequiredAgentID,
		})
		return err
	}); err != nil {
		return store.DiscoveryRun{}, err
	}
	return store.DiscoveryRun{
		ID: id, TenantID: tenantID, SourceID: in.SourceID, ScheduleID: in.ScheduleID,
		Status: "queued", DryRun: in.DryRun, RequestedBy: requestedBy,
		Execution: queued.Execution, Segment: queued.Segment, RequiredAgentRole: queued.RequiredAgentRole,
		RequiredAgentID: queued.RequiredAgentID, CreatedAt: ev.Time,
	}, nil
}

func (o *Orchestrator) validateDiscoveryNetworkRelay(ctx context.Context, tenantID, agentID string) error {
	if strings.TrimSpace(agentID) == "" {
		return nil
	}
	agent, err := o.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return fmt.Errorf("orchestrator: resolve discovery relay: %w", err)
	}
	if agent.Status == "offboarded" || !containsString(agent.Roles, segmentscan.RequiredRoleNetwork) {
		return errors.New("orchestrator: selected discovery relay is not an active network-role agent")
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// StartDiscoveryRun records that an outbox worker began executing a run.
func (o *Orchestrator) StartDiscoveryRun(ctx context.Context, tenantID, runID string) error {
	return o.startDiscoveryRun(ctx, tenantID, runID, "")
}

// StartDiscoveryRunWithEventID is the durable-receiver form. eventID is derived
// from the claimed outbox key, so two copies of one receipt share one event.
func (o *Orchestrator) StartDiscoveryRunWithEventID(ctx context.Context, tenantID, runID, eventID string) error {
	if strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: discovery start event id is required")
	}
	return o.startDiscoveryRun(ctx, tenantID, runID, eventID)
}

func (o *Orchestrator) startDiscoveryRun(ctx context.Context, tenantID, runID, eventID string) error {
	payload, err := json.Marshal(projections.DiscoveryRunStarted{ID: runID})
	if err != nil {
		return err
	}
	if eventID == "" {
		_, err = o.emit(ctx, projections.EventDiscoveryRunStarted, tenantID, payload)
	} else {
		_, err = o.emitPreparedExact(ctx, events.Event{
			ID: eventID, Type: projections.EventDiscoveryRunStarted, TenantID: tenantID, Data: payload,
		})
	}
	return err
}

// RecordDiscoveryFinding records one metadata-only finding for a run.
func (o *Orchestrator) RecordDiscoveryFinding(ctx context.Context, tenantID string, in store.DiscoveryFinding) (store.DiscoveryFinding, error) {
	return o.recordDiscoveryFinding(ctx, tenantID, in, "")
}

// RecordDiscoveryFindingWithEventID appends one receipt-bound observation.
func (o *Orchestrator) RecordDiscoveryFindingWithEventID(ctx context.Context, tenantID, eventID string, in store.DiscoveryFinding) (store.DiscoveryFinding, error) {
	if strings.TrimSpace(eventID) == "" {
		return store.DiscoveryFinding{}, errors.New("orchestrator: discovery finding event id is required")
	}
	return o.recordDiscoveryFinding(ctx, tenantID, in, eventID)
}

func (o *Orchestrator) recordDiscoveryFinding(ctx context.Context, tenantID string, in store.DiscoveryFinding, eventID string) (store.DiscoveryFinding, error) {
	id := in.ID
	if id == "" {
		id = discovery.FindingID(tenantID, in.RunID, in.Kind, in.Ref, in.Fingerprint)
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
	var ev events.Event
	if eventID == "" {
		ev, err = o.emit(ctx, projections.EventDiscoveryFindingRecorded, tenantID, payload)
	} else {
		ev, err = o.emitPreparedExact(ctx, events.Event{
			ID: eventID, Type: projections.EventDiscoveryFindingRecorded, TenantID: tenantID, Data: payload,
		})
	}
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	out := in
	out.ID, out.TenantID, out.Metadata, out.DiscoveredAt = id, tenantID, meta, ev.Time
	return out, nil
}

// RecordCertificateWithEventID records public certificate metadata with both a
// stable event ID and stable projected row ID. It is intentionally narrow: raw
// certificate/key material does not enter this receiver path.
func (o *Orchestrator) RecordCertificateWithEventID(ctx context.Context, tenantID, eventID string, in store.Certificate) (store.Certificate, error) {
	if strings.TrimSpace(eventID) == "" {
		return store.Certificate{}, errors.New("orchestrator: certificate event id is required")
	}
	rowID := uuid.NewSHA1(discoveryRelayEventNamespace, []byte("certificate-row\x00"+eventID)).String()
	payload, err := json.Marshal(certificateRecordedPayload(rowID, in, nil, nil))
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := o.emitPreparedExact(ctx, events.Event{
		ID: eventID, Type: projections.EventCertificateRecorded, TenantID: tenantID, Data: payload,
	}); err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, in.Fingerprint)
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
	return o.completeDiscoveryRun(ctx, tenantID, in, "")
}

// CompleteDiscoveryRunWithEventID is the receipt-bound terminal transition.
func (o *Orchestrator) CompleteDiscoveryRunWithEventID(ctx context.Context, tenantID, eventID string, in store.DiscoveryRun) error {
	if strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: discovery completion event id is required")
	}
	return o.completeDiscoveryRun(ctx, tenantID, in, eventID)
}

func (o *Orchestrator) completeDiscoveryRun(ctx context.Context, tenantID string, in store.DiscoveryRun, eventID string) error {
	in.Error = sanitizeDiscoveryRunError(in.Error)
	for i := range in.TargetResults {
		in.TargetResults[i].Error = sanitizeDiscoveryRunError(in.TargetResults[i].Error)
	}
	if err := validateDiscoveryTargetResults(in.TargetResults); err != nil {
		return err
	}
	targetResults := make([]projections.DiscoveryTargetResult, 0, len(in.TargetResults))
	for _, result := range in.TargetResults {
		targetResults = append(targetResults, projections.DiscoveryTargetResult{
			Kind: result.Kind, Target: result.Target, Status: result.Status,
			Cursor: result.Cursor, Error: result.Error,
		})
	}
	payload, err := json.Marshal(projections.DiscoveryRunCompleted{
		ID: in.ID, Status: in.Status, Targets: in.Targets, Discovered: in.Discovered,
		Failed: in.Failed, Rejected: in.Rejected, Blocked: in.Blocked, Error: in.Error,
		Segment: in.Segment, ExecutedByAgentID: in.ExecutedByAgentID,
		TargetResults: targetResults,
	})
	if err != nil {
		return err
	}
	schemaVersion := 0
	if len(targetResults) > 0 {
		schemaVersion = projections.DiscoveryTargetResultsEventSchemaVersion
	}
	if eventID == "" {
		_, err = o.emitVersioned(ctx, projections.EventDiscoveryRunCompleted, tenantID, schemaVersion, payload)
	} else {
		_, err = o.emitPreparedExact(ctx, events.Event{
			ID: eventID, Type: projections.EventDiscoveryRunCompleted, TenantID: tenantID,
			SchemaVersion: schemaVersion, Data: payload,
		})
	}
	return err
}

// sanitizeDiscoveryRunError keeps the operator-useful failure class while
// refusing to make an upstream body, credential echo, or unbounded transport
// transcript part of immutable tenant history. The event is the authority, so
// redaction belongs here before append rather than only in the API renderer.
func sanitizeDiscoveryRunError(detail string) string {
	detail = strings.ToValidUTF8(detail, "")
	detail = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, detail)
	detail = strings.Join(strings.Fields(detail), " ")
	if detail == "" {
		return ""
	}
	detail = aimodel.DefaultRedactor(detail)
	if aimodel.ResidualSecret(detail) {
		return discoveryRunErrorWithheld
	}
	if len(detail) <= maxDiscoveryRunErrorBytes {
		return detail
	}
	end := maxDiscoveryRunErrorBytes
	for end > 0 && !utf8.RuneStart(detail[end]) {
		end--
	}
	return strings.TrimSpace(detail[:end])
}

// SanitizeDiscoveryRunError is the shared egress guard for historical rows
// written before discovery errors were sanitized at event append time.
func SanitizeDiscoveryRunError(detail string) string {
	return sanitizeDiscoveryRunError(detail)
}

func validateDiscoveryTargetResults(results []store.DiscoveryTargetResult) error {
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		if result.Kind != "ct_log" {
			return fmt.Errorf("orchestrator: unsupported discovery target result kind %q", result.Kind)
		}
		target := strings.TrimSpace(result.Target)
		if target == "" {
			return errors.New("orchestrator: discovery target result target is required")
		}
		if target != result.Target {
			return errors.New("orchestrator: discovery target result target must be canonical")
		}
		if _, ok := seen[target]; ok {
			return fmt.Errorf("orchestrator: duplicate discovery target result %q", target)
		}
		seen[target] = struct{}{}
		if result.Status != "succeeded" && result.Status != "failed" {
			return fmt.Errorf("orchestrator: invalid discovery target result status %q", result.Status)
		}
		if result.Cursor < 0 {
			return errors.New("orchestrator: discovery target result cursor must be non-negative")
		}
		if result.Status == "succeeded" && result.Error != "" {
			return errors.New("orchestrator: successful discovery target result cannot carry an error")
		}
		if len(result.Error) > 1024 || !utf8.ValidString(result.Error) {
			return errors.New("orchestrator: discovery target result error must be valid UTF-8 and at most 1024 bytes")
		}
	}
	return nil
}

// emitPreparedExact verifies that duplicate suppression returned the same
// immutable meaning. Reusing a receipt key with changed report bytes fails
// closed instead of silently applying the earlier event.
func (o *Orchestrator) emitPreparedExact(ctx context.Context, next events.Event) (events.Event, error) {
	ev, err := o.emitPrepared(ctx, next)
	if err != nil {
		return events.Event{}, err
	}
	if ev.ID != next.ID || ev.Type != next.Type || ev.TenantID != next.TenantID || !bytes.Equal(ev.Data, next.Data) {
		return events.Event{}, fmt.Errorf("%w: canonical discovery receipt event differs", store.ErrIdempotencyConflict)
	}
	return ev, nil
}
