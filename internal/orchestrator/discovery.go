// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/discovery"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshcollection"
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

// ErrDiscoveryScheduleInactive refuses a run or resume that would cross an
// operator's retained pause/retirement decision.
var ErrDiscoveryScheduleInactive = errors.New("orchestrator: discovery schedule is paused or retired")

// ErrDiscoveryRelayUnavailable means relay-owned work has no enrolled agent that
// can claim it. Keeping this as a typed admission error lets the API return a
// truthful conflict instead of recording a queued run that cannot start.
var ErrDiscoveryRelayUnavailable = errors.New("orchestrator: no eligible network relay is enrolled")

// ErrDiscoverySourceIdentityConflict means a tenant-local source name or ID is
// already bound to a different producer identity. Changing the kind of an
// existing source would turn old runs into evidence for a different collector.
var ErrDiscoverySourceIdentityConflict = errors.New("orchestrator: discovery source identity is already bound")

// ErrDiscoveryScheduleIdentityConflict means a tenant-local schedule name or
// ID already belongs to another declaration. A second event would fail the
// unique read-model projection and obstruct ordered replay.
var ErrDiscoveryScheduleIdentityConflict = errors.New("orchestrator: discovery schedule identity is already bound")

// DiscoveryRelayReadiness is the server-owned answer to "where will this scan
// run?" Ready means an enrolled, non-offboarded agent has the network role. It
// does not promise that the agent is connected at this exact millisecond; the
// durable outbox still handles a temporary disconnect after admission.
type DiscoveryRelayReadiness struct {
	Ready            bool
	ConnectionOrigin string
	BlockedReason    string
}

var agentInventorySourceNamespace = uuid.MustParse("d5e0734a-9cc6-53a4-92f3-4f99387f8c3a")
var secretScanSourceNamespace = uuid.MustParse("f2a0de71-857b-5a96-83be-0e65a0f2f107")
var discoverySourceNamespace = uuid.MustParse("c47d7a97-a79c-5a36-a5b4-673b5afbe3cf")
var discoverySegmentNamespace = uuid.MustParse("5afb44ec-8cfa-5e68-a135-150af6c36e87")
var discoveryRelayEventNamespace = uuid.MustParse("78899482-854a-5b4d-9276-d8d574bdd340")
var discoveryScheduleControlNamespace = uuid.MustParse("3a1f15da-3d9c-5c6e-8e08-71e286d8a980")

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
// emitDiscoveryDeclaration appends a discovery declaration event and applies it
// inline. When the projection tail concurrently applies the SAME logical
// declaration (a tight declare-then-create), the inline upsert and the tail
// upsert race on the row and one aborts with a transient conflict. The event is
// durable either way, so retrying is safe: the deterministic per-tenant id and
// the projection sequence guard make the re-emitted event a no-op if the row is
// already at or past it, and a clean apply otherwise. This keeps a rapid
// declare-then-create a 201 instead of a spurious 500.
func (o *Orchestrator) emitDiscoveryDeclaration(ctx context.Context, eventType, tenantID string, payload json.RawMessage) (events.Event, error) {
	var ev events.Event
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		ev, err = o.emit(ctx, eventType, tenantID, payload)
		if err == nil || !errors.Is(err, store.ErrDiscoveryDeclarationEventConflict) {
			return ev, err
		}
		select {
		case <-ctx.Done():
			return ev, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 10 * time.Millisecond):
		}
	}
	return ev, err
}

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
	if _, err := o.emitDiscoveryDeclaration(ctx, projections.EventDiscoverySegmentUpserted, tenantID, payload); err != nil {
		return store.DiscoverySegment{}, err
	}
	return o.store.GetDiscoverySegmentByName(ctx, tenantID, name)
}

// UpsertDiscoverySource records a tenant discovery source as an event and returns
// the projected source row. Config is metadata/reference JSON only; API validation
// rejects inline credential values before calling this command.
func (o *Orchestrator) UpsertDiscoverySource(ctx context.Context, tenantID string, in store.DiscoverySource) (store.DiscoverySource, error) {
	var result store.DiscoverySource
	err := o.store.WithTenantResourceCreation(ctx, tenantID, "discovery-source", func(fenced context.Context) error {
		var err error
		result, err = o.upsertDiscoverySourceFenced(fenced, tenantID, in)
		return err
	})
	return result, err
}

// The tenant-scoped session lock spans the first identity read, source append,
// and inline projection. A separate replica cannot accept a competing first
// declaration while the winner has appended but not yet projected its event.
func (o *Orchestrator) upsertDiscoverySourceFenced(ctx context.Context, tenantID string, in store.DiscoverySource) (store.DiscoverySource, error) {
	name := strings.TrimSpace(in.Name)
	id := in.ID
	byName, nameErr := o.store.GetDiscoverySourceByName(ctx, tenantID, name)
	if nameErr != nil && !errors.Is(nameErr, pgx.ErrNoRows) {
		return store.DiscoverySource{}, nameErr
	}
	if errors.Is(nameErr, pgx.ErrNoRows) {
		if err := o.guardUnprojectedDiscoveryIdentity(ctx, tenantID, projections.EventDiscoverySourceUpserted, name, id); err != nil {
			return store.DiscoverySource{}, err
		}
	}
	if nameErr == nil {
		if byName.Kind != in.Kind || (id != "" && byName.ID != id) {
			return store.DiscoverySource{}, ErrDiscoverySourceIdentityConflict
		}
	}
	if id == "" {
		switch {
		case nameErr == nil:
			id = byName.ID
		case errors.Is(nameErr, pgx.ErrNoRows):
			// Keep an omitted ID stable across retries, while the session lock
			// and projection-head check protect the first-writer decision.
			id = uuid.NewSHA1(discoverySourceNamespace, []byte(tenantID+"\x00"+name)).String()
		default:
			return store.DiscoverySource{}, nameErr
		}
	} else {
		byID, idErr := o.store.GetDiscoverySource(ctx, tenantID, id)
		if idErr != nil && !errors.Is(idErr, pgx.ErrNoRows) {
			return store.DiscoverySource{}, idErr
		}
		if idErr == nil && byID.Kind != in.Kind {
			return store.DiscoverySource{}, ErrDiscoverySourceIdentityConflict
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
	ev, err := o.emitDiscoveryDeclaration(ctx, projections.EventDiscoverySourceUpserted, tenantID, payload)
	if err != nil {
		return store.DiscoverySource{}, err
	}
	return store.DiscoverySource{
		ID: id, TenantID: tenantID, Kind: in.Kind, Name: name, Config: cfg,
		CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}

// guardUnprojectedDiscoveryIdentity checks the finite source cut after the
// ordered relational checkpoint using JetStream's event-type subject index.
// Unrelated events never make a fresh identity look busy. The resource-creation
// session lock prevents another writer of this declaration type from appending
// while the absence decision and new append are in flight. A non-contiguous
// source stream cannot prove absence and is refused before any new event.
func (o *Orchestrator) guardUnprojectedDiscoveryIdentity(ctx context.Context, tenantID, eventType, name, id string) error {
	snapshot, err := o.log.Snapshot(ctx)
	if err != nil {
		return err
	}
	applied, err := o.store.ProjectionCheckpoint(ctx)
	if err != nil {
		return err
	}
	if applied > snapshot.LastSequence {
		return errors.New("orchestrator: discovery source projection checkpoint exceeds the event head")
	}
	if snapshot.NumDeleted != 0 || snapshot.Messages != snapshot.LastSequence ||
		(snapshot.LastSequence > 0 && snapshot.FirstSequence != 1) {
		return store.ErrResourceAdmissionBusy
	}
	if err := o.log.ReplayTenantTypesThrough(ctx, tenantID, applied+1, snapshot.LastSequence,
		[]string{eventType}, func(event events.Event) error {
			var identity struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(event.Data, &identity); err != nil {
				return fmt.Errorf("orchestrator: decode unprojected %s sequence %d: %w", eventType, event.Sequence, err)
			}
			if identity.Name == name || (id != "" && identity.ID == id) {
				return store.ErrResourceAdmissionBusy
			}
			return nil
		}); err != nil {
		return err
	}
	after, err := o.log.Snapshot(ctx)
	if err != nil {
		return err
	}
	if after.Name != snapshot.Name || after.Generation != snapshot.Generation ||
		after.FirstSequence != snapshot.FirstSequence || after.NumDeleted != snapshot.NumDeleted ||
		after.LastSequence < snapshot.LastSequence || after.Messages < snapshot.Messages ||
		after.Messages-snapshot.Messages != after.LastSequence-snapshot.LastSequence {
		return store.ErrResourceAdmissionBusy
	}
	return nil
}

// UpsertDiscoverySchedule records a source schedule. It refuses an absent source
// before emitting anything, so the event log never contains a dangling schedule.
func (o *Orchestrator) UpsertDiscoverySchedule(ctx context.Context, tenantID string, in store.DiscoverySchedule) (store.DiscoverySchedule, error) {
	var result store.DiscoverySchedule
	err := o.store.WithTenantResourceCreation(ctx, tenantID, "discovery-schedule", func(fenced context.Context) error {
		var err error
		result, err = o.upsertDiscoveryScheduleFenced(fenced, tenantID, in)
		return err
	})
	return result, err
}

func (o *Orchestrator) upsertDiscoveryScheduleFenced(ctx context.Context, tenantID string, in store.DiscoverySchedule) (store.DiscoverySchedule, error) {
	if _, err := o.store.GetDiscoverySource(ctx, tenantID, in.SourceID); err != nil {
		return store.DiscoverySchedule{}, err
	}
	name := strings.TrimSpace(in.Name)
	byName, nameErr := o.store.GetDiscoveryScheduleByName(ctx, tenantID, name)
	if nameErr != nil && !errors.Is(nameErr, pgx.ErrNoRows) {
		return store.DiscoverySchedule{}, nameErr
	}
	if nameErr == nil && (in.ID == "" || byName.ID != in.ID) {
		return store.DiscoverySchedule{}, ErrDiscoveryScheduleIdentityConflict
	}
	if nameErr == nil && byName.RetiredAt != nil {
		return store.DiscoverySchedule{}, ErrDiscoveryScheduleInactive
	}
	if nameErr == nil && in.ID != "" && byName.ControlEventSequence > 0 {
		return store.DiscoverySchedule{}, ErrDiscoveryScheduleInactive
	}
	if errors.Is(nameErr, pgx.ErrNoRows) {
		if err := o.guardUnprojectedDiscoveryIdentity(ctx, tenantID, projections.EventDiscoveryScheduleUpserted, name, in.ID); err != nil {
			return store.DiscoverySchedule{}, err
		}
	}
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	} else {
		byID, idErr := o.store.GetDiscoverySchedule(ctx, tenantID, id)
		if idErr != nil && !errors.Is(idErr, pgx.ErrNoRows) {
			return store.DiscoverySchedule{}, idErr
		}
		if idErr == nil && byID.Name != name {
			return store.DiscoverySchedule{}, ErrDiscoveryScheduleIdentityConflict
		}
	}
	payload, err := json.Marshal(projections.DiscoveryScheduleUpserted{
		ID: id, SourceID: in.SourceID, Name: name, IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled,
	})
	if err != nil {
		return store.DiscoverySchedule{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryScheduleUpserted, tenantID, payload)
	if err != nil {
		return store.DiscoverySchedule{}, err
	}
	return store.DiscoverySchedule{
		ID: id, TenantID: tenantID, SourceID: in.SourceID, Name: name,
		IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled,
		CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}

// ControlDiscoverySchedule retains a pause, resume, or retirement decision in
// the event log. The exact per-schedule lock is shared with final run admission
// so a stale scheduler due-list cannot queue after a completed pause.
func (o *Orchestrator) ControlDiscoverySchedule(ctx context.Context, tenantID, id, action, idempotencyKey, binding string) (store.DiscoverySchedule, error) {
	if idempotencyKey == "" || binding == "" {
		return store.DiscoverySchedule{}, errors.New("orchestrator: discovery schedule control requires a bound idempotency key")
	}
	eventType := map[string]string{
		"pause":  projections.EventDiscoverySchedulePaused,
		"resume": projections.EventDiscoveryScheduleResumed,
		"retire": projections.EventDiscoveryScheduleRetired,
	}[action]
	if eventType == "" {
		return store.DiscoverySchedule{}, errors.New("orchestrator: invalid discovery schedule control action")
	}
	eventID := uuid.NewSHA1(discoveryScheduleControlNamespace,
		[]byte(tenantID+"\x00"+idempotencyKey)).String()
	var result store.DiscoverySchedule
	err := o.withTenantCommand(ctx, tenantID, func(fenced context.Context, tx pgx.Tx) error {
		if err := lockDiscoveryScheduleDecisionTx(fenced, tx, tenantID, id); err != nil {
			return err
		}
		current, err := o.store.GetDiscoveryScheduleTx(fenced, tx, tenantID, id)
		if err != nil {
			return err
		}
		retained, found, err := o.log.EventByID(fenced, eventID)
		if err != nil {
			return err
		}
		if found {
			var receipt projections.DiscoveryScheduleControlledV2
			if retained.TenantID != tenantID || retained.Type != eventType || retained.SchemaVersion != 2 ||
				json.Unmarshal(retained.Data, &receipt) != nil || receipt.ID != id ||
				receipt.Action != action || receipt.Binding != binding || receipt.ReasonCode != "operator_request" ||
				receipt.Result.ID != id || receipt.Result.TenantID != tenantID {
				return store.ErrIdempotencyConflict
			}
			if retained.Sequence > math.MaxInt64 {
				return errors.New("orchestrator: discovery schedule control sequence exceeds SQL range")
			}
			if int64(retained.Sequence) > current.ControlEventSequence { // #nosec G115 -- retained sequence was checked against MaxInt64 before conversion.
				if err := o.proj.ApplyTx(fenced, tx, retained); err != nil {
					return err
				}
			}
			result = discoveryScheduleFromControlResult(receipt.Result)
			return nil
		}
		if err := o.guardUnprojectedDiscoveryScheduleControl(fenced, tenantID, id, current.ControlEventSequence); err != nil {
			return err
		}
		if current.RetiredAt != nil {
			if action == "retire" {
				// A fresh retirement key still gets an immutable no-op receipt.
			} else {
				return ErrDiscoveryScheduleInactive
			}
		}
		applied := current.RetiredAt == nil && ((action == "pause" && current.Enabled) ||
			(action == "resume" && !current.Enabled) || action == "retire")
		at := time.Now().UTC().Truncate(time.Microsecond)
		result = current
		result.CreatedAt = result.CreatedAt.UTC()
		result.UpdatedAt = result.UpdatedAt.UTC()
		if result.RetiredAt != nil {
			retired := result.RetiredAt.UTC()
			result.RetiredAt = &retired
		}
		if applied {
			result.Enabled = action == "resume"
			result.UpdatedAt = at
			if action == "retire" {
				result.RetiredAt = &at
			}
		}
		payload, err := json.Marshal(projections.DiscoveryScheduleControlledV2{
			ID: id, Action: action, ReasonCode: "operator_request", Binding: binding,
			Applied: applied, Result: discoveryScheduleControlResult(result),
		})
		if err != nil {
			return err
		}
		ev, err := o.log.Append(fenced, events.Event{
			ID: eventID, Type: eventType, TenantID: tenantID, SchemaVersion: 2, Time: at, Data: payload,
		})
		if err != nil {
			return err
		}
		if ev.ID != eventID || ev.TenantID != tenantID || ev.Type != eventType || ev.SchemaVersion != 2 ||
			!bytes.Equal(ev.Data, payload) {
			return store.ErrIdempotencyConflict
		}
		return o.proj.ApplyTx(fenced, tx, ev)
	})
	if err != nil {
		return store.DiscoverySchedule{}, err
	}
	return result, nil
}

func discoveryScheduleControlResult(s store.DiscoverySchedule) projections.DiscoveryScheduleControlResult {
	return projections.DiscoveryScheduleControlResult{
		ID: s.ID, TenantID: s.TenantID, SourceID: s.SourceID, Name: s.Name,
		IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled, RetiredAt: s.RetiredAt,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

func discoveryScheduleFromControlResult(r projections.DiscoveryScheduleControlResult) store.DiscoverySchedule {
	return store.DiscoverySchedule{
		ID: r.ID, TenantID: r.TenantID, SourceID: r.SourceID, Name: r.Name,
		IntervalSeconds: r.IntervalSeconds, Enabled: r.Enabled, RetiredAt: r.RetiredAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func lockDiscoveryScheduleDecisionTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"discovery-schedule-due\x1f"+tenantID+"\x1f"+id); err != nil {
		return fmt.Errorf("orchestrator: lock discovery schedule decision: %w", err)
	}
	return nil
}

// The SQL transaction that projects a control event may roll back after the
// JetStream append. Final run admission must then fail closed until the ordered
// tail applies that event. This finite, typed replay uses the retained subject
// index and ignores unrelated event types and schedules.
func (o *Orchestrator) guardUnprojectedDiscoveryScheduleControl(ctx context.Context,
	tenantID, id string, controlSequence int64) error {
	snapshot, err := o.log.Snapshot(ctx)
	if err != nil {
		return err
	}
	applied, err := o.store.ProjectionCheckpoint(ctx)
	if err != nil {
		return err
	}
	if applied > snapshot.LastSequence || snapshot.NumDeleted != 0 ||
		snapshot.Messages != snapshot.LastSequence ||
		(snapshot.LastSequence > 0 && snapshot.FirstSequence != 1) {
		return store.ErrResourceAdmissionBusy
	}
	if err := o.log.ReplayTenantTypesThrough(ctx, tenantID, applied+1, snapshot.LastSequence,
		[]string{projections.EventDiscoverySchedulePaused, projections.EventDiscoveryScheduleResumed,
			projections.EventDiscoveryScheduleRetired}, func(event events.Event) error {
			var payload struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(event.Data, &payload); err != nil {
				return fmt.Errorf("orchestrator: decode unprojected discovery schedule control: %w", err)
			}
			if payload.ID == id && (controlSequence < 0 || event.Sequence > uint64(controlSequence)) {
				return store.ErrResourceAdmissionBusy
			}
			return nil
		}); err != nil {
		return err
	}
	after, err := o.log.Snapshot(ctx)
	if err != nil {
		return err
	}
	if after.Name != snapshot.Name || after.Generation != snapshot.Generation ||
		after.FirstSequence != snapshot.FirstSequence || after.NumDeleted != snapshot.NumDeleted ||
		after.LastSequence < snapshot.LastSequence || after.Messages < snapshot.Messages ||
		after.Messages-snapshot.Messages != after.LastSequence-snapshot.LastSequence {
		return store.ErrResourceAdmissionBusy
	}
	return nil
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
		ID: id, SourceID: in.SourceID, ScheduleID: in.ScheduleID, RetryOfRunID: in.RetryOfRunID,
		DryRun: in.DryRun, RequestedBy: requestedBy,
		Execution: segmentscan.ExecutionControlPlane,
	}
	destination := discoveryRunDestination
	eventType := projections.EventDiscoveryRunQueued
	var command any = queued
	switch source.Kind {
	case "network", "ssh":
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
		if err := segmentscan.ValidateDeclaredSegment(resolved, segment.Ranges); err != nil {
			return store.DiscoveryRun{}, fmt.Errorf("orchestrator: discovery segment scope: %w", err)
		}
		if err := o.requireDiscoveryNetworkRelayForJob(ctx, tenantID, resolved.RequiredAgentID, discoveryRunDestination); err != nil {
			return store.DiscoveryRun{}, err
		}
		resolved.ID, resolved.SourceID, resolved.ScheduleID = id, in.SourceID, in.ScheduleID
		resolved.RetryOfRunID = in.RetryOfRunID
		resolved.DryRun, resolved.RequestedBy = in.DryRun, requestedBy
		resolved.KeepChain = o.keepScannedChains && resolved.Mode == segmentscan.ModeTLS && !resolved.DryRun
		queued = resolved
		command = resolved
	case sshcollection.SourceKind:
		if in.DryRun {
			return store.DiscoveryRun{}, errors.New("SSH trust collection is read-only; use preflight for an effect-free plan")
		}
		cfg, err := sshcollection.DecodeConfig(source.Config)
		if err != nil {
			return store.DiscoveryRun{}, err
		}
		resolved := cfg.Resolve()
		segment, err := o.store.GetDiscoverySegmentByName(ctx, tenantID, resolved.Segment)
		if err != nil {
			return store.DiscoveryRun{}, err
		}
		if segment.Excluded {
			return store.DiscoveryRun{}, errors.New("SSH collection segment is excluded")
		}
		if err := segmentscan.ValidateDeclaredSegment(resolved.ScopeIntent(), segment.Ranges); err != nil {
			return store.DiscoveryRun{}, err
		}
		if err := o.requireDiscoveryNetworkRelayForJob(ctx, tenantID, resolved.RequiredAgentID, sshcollection.Destination); err != nil {
			return store.DiscoveryRun{}, err
		}
		resolved.ID, resolved.SourceID, resolved.ScheduleID = id, in.SourceID, in.ScheduleID
		resolved.RetryOfRunID, resolved.RequestedBy = in.RetryOfRunID, requestedBy
		if err := resolved.Validate(); err != nil {
			return store.DiscoveryRun{}, err
		}
		queued = projections.DiscoveryRunQueued{ID: id, SourceID: in.SourceID, ScheduleID: in.ScheduleID, RetryOfRunID: in.RetryOfRunID, RequestedBy: requestedBy, Execution: resolved.Execution, Segment: resolved.Segment, RequiredAgentRole: resolved.RequiredAgentRole, RequiredAgentID: resolved.RequiredAgentID}
		command = resolved
		destination = sshcollection.Destination
		eventType = projections.EventSSHTrustCollectionQueued
	case adcsdiscovery.SourceKind:
		if in.DryRun {
			return store.DiscoveryRun{}, errors.New("orchestrator: AD CS inventory is already read-only and does not support dry-run")
		}
		resolved, err := adcsdiscovery.ResolveInventoryIntent(source.Config)
		if err != nil {
			return store.DiscoveryRun{}, err
		}
		if err := o.requireDiscoveryNetworkRelayForJob(ctx, tenantID, resolved.RequiredAgentID, adcsdiscovery.JobKind); err != nil {
			return store.DiscoveryRun{}, err
		}
		resolved.ID, resolved.SourceID, resolved.ScheduleID = id, in.SourceID, in.ScheduleID
		resolved.RetryOfRunID = in.RetryOfRunID
		resolved.RequestedBy = requestedBy
		queued = projections.DiscoveryRunQueued{
			ID: id, SourceID: in.SourceID, JobKind: resolved.JobKind, RetryOfRunID: in.RetryOfRunID,
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
	if err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if in.ScheduleID != nil {
			if err := lockDiscoveryScheduleDecisionTx(ctx, tx, tenantID, *in.ScheduleID); err != nil {
				return err
			}
			var enabled bool
			var retiredAt *time.Time
			var sourceID string
			var controlSequence int64
			if err := tx.QueryRow(ctx,
				`SELECT enabled, retired_at, source_id::text, control_event_sequence
				   FROM discovery_schedules WHERE tenant_id = $1::uuid AND id = $2::uuid`,
				tenantID, *in.ScheduleID).Scan(&enabled, &retiredAt, &sourceID, &controlSequence); err != nil {
				return err
			}
			if err := o.guardUnprojectedDiscoveryScheduleControl(ctx, tenantID, *in.ScheduleID, controlSequence); err != nil {
				return err
			}
			if !enabled || retiredAt != nil || sourceID != in.SourceID {
				return ErrDiscoveryScheduleInactive
			}
		}
		if in.OnlyIfDue && in.ScheduleID != nil {
			var due bool
			if err := tx.QueryRow(ctx,
				`SELECT s.enabled AND s.retired_at IS NULL AND s.source_id = $3::uuid AND NOT EXISTS (
				   SELECT 1
				     FROM discovery_runs r
				    WHERE r.tenant_id = $1::uuid
				      AND r.source_id = s.source_id
				      AND (r.status IN ('queued', 'running')
				           OR r.created_at > clock_timestamp() - make_interval(secs => GREATEST(s.interval_seconds, 1)))
				 ) FROM discovery_schedules s
				 WHERE s.tenant_id = $1::uuid AND s.id = $2::uuid`, tenantID, *in.ScheduleID, in.SourceID).Scan(&due); err != nil {
				return fmt.Errorf("orchestrator: recheck discovery schedule due decision: %w", err)
			}
			if !due {
				return ErrDiscoveryScheduleNotDue
			}
		}
		var err error
		ev, err = o.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: commandPayload})
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
		ID: id, TenantID: tenantID, SourceID: in.SourceID, ScheduleID: in.ScheduleID, RetryOfRunID: in.RetryOfRunID,
		Status: "queued", DryRun: in.DryRun, RequestedBy: requestedBy,
		Execution: queued.Execution, Segment: queued.Segment, RequiredAgentRole: queued.RequiredAgentRole,
		RequiredAgentID: queued.RequiredAgentID, CreatedAt: ev.Time,
	}, nil
}

func (o *Orchestrator) requireDiscoveryNetworkRelayForJob(ctx context.Context, tenantID, agentID, jobKind string) error {
	readiness, err := o.DiscoveryNetworkRelayReadinessForJob(ctx, tenantID, agentID, jobKind)
	if err != nil {
		return err
	}
	if !readiness.Ready {
		return fmt.Errorf("%w: %s", ErrDiscoveryRelayUnavailable, readiness.BlockedReason)
	}
	return nil
}

// DiscoveryNetworkRelayReadiness is shared by preview, saved-source preflight,
// manual runs, and scheduled runs. That prevents the console from claiming a
// different execution truth than the queue admission path enforces.
func (o *Orchestrator) DiscoveryNetworkRelayReadiness(ctx context.Context, tenantID, agentID string) (DiscoveryRelayReadiness, error) {
	return o.DiscoveryNetworkRelayReadinessForJob(ctx, tenantID, agentID, discoveryRunDestination)
}

// DiscoveryNetworkRelayReadinessForJob proves both halves of executable relay
// readiness: an eligible tenant relay exists AND the served agent channel is
// configured to hand out this exact job kind.
func (o *Orchestrator) DiscoveryNetworkRelayReadinessForJob(ctx context.Context, tenantID, agentID, jobKind string) (DiscoveryRelayReadiness, error) {
	jobKind = strings.TrimSpace(jobKind)
	if o.claimableAgentJobKindsConfigured {
		if _, enabled := o.claimableAgentJobKinds[jobKind]; !enabled {
			return DiscoveryRelayReadiness{
				ConnectionOrigin: "Agent dispatch is not enabled for " + jobKind,
				BlockedReason:    "Enable " + jobKind + " in agent_channel.claimable_job_kinds before starting this source.",
			}, nil
		}
	}
	interval := o.agentHeartbeatInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	now := time.Now().UTC()
	staleBefore := now.Add(-2 * interval)
	futureLimit := now.Add(interval)
	agentID = strings.TrimSpace(agentID)
	if agentID != "" {
		agent, err := o.store.GetAgent(ctx, tenantID, agentID)
		if err != nil {
			if store.IsNotFound(err) {
				return DiscoveryRelayReadiness{
					ConnectionOrigin: "Selected network relay is not enrolled",
					BlockedReason:    "Select an enrolled agent with the network role, or enroll one before starting this source.",
				}, nil
			}
			return DiscoveryRelayReadiness{}, fmt.Errorf("orchestrator: resolve discovery relay: %w", err)
		}
		if agent.Status == "offboarded" || !containsString(agent.Roles, segmentscan.RequiredRoleNetwork) {
			return DiscoveryRelayReadiness{
				ConnectionOrigin: "Selected agent cannot run network discovery",
				BlockedReason:    "Select a non-offboarded agent with the network role before starting this source.",
			}, nil
		}
		if agent.LastSeenAt == nil || agent.LastSeenAt.Before(staleBefore) || agent.LastSeenAt.After(futureLimit) {
			return DiscoveryRelayReadiness{
				ConnectionOrigin: "Selected network relay has no fresh authenticated heartbeat",
				BlockedReason:    "Restore the selected network relay's authenticated heartbeat or re-enroll its expired certificate before starting this source.",
			}, nil
		}
		return DiscoveryRelayReadiness{
			Ready: true, ConnectionOrigin: "Network relay " + agent.ID,
		}, nil
	}
	present, err := o.store.TenantHasFreshNetworkRelay(ctx, tenantID, staleBefore, futureLimit)
	if err != nil {
		return DiscoveryRelayReadiness{}, err
	}
	if !present {
		return DiscoveryRelayReadiness{
			ConnectionOrigin: "No network relay has a fresh authenticated heartbeat",
			BlockedReason:    "Enroll an agent with the network role, or restore its authenticated heartbeat and re-enroll an expired certificate before starting this source.",
		}, nil
	}
	return DiscoveryRelayReadiness{
		Ready: true, ConnectionOrigin: "Enrolled network-role relay selected when the run is claimed",
	}, nil
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
		if in.SourceID != "" {
			// One row per observed credential per source: a repeat observation by a
			// later run projects onto the same finding (see store.ApplyDiscoveryFindingRecordedTx).
			id = discovery.FindingIdentity(tenantID, in.SourceID, in.Kind, in.Ref, in.Fingerprint)
		} else {
			id = discovery.FindingID(tenantID, in.RunID, in.Kind, in.Ref, in.Fingerprint)
		}
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
// stable event ID and stable projected row ID. It is intentionally narrow: key
// material never enters this receiver path, and a certificate's public bytes do
// only when a scan kept them (A211).
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
func (o *Orchestrator) RecordAgentInventory(ctx context.Context, tenantID, agentName, agentID, sourceKind string, findings []store.DiscoveryFinding) (store.DiscoveryRun, int, int, error) {
	agentName = strings.TrimSpace(agentName)
	agentID = strings.TrimSpace(agentID)
	// Validate the durable agent row before emitting the first discovery event.
	// A missing/mismatched row would otherwise fail the completed-run foreign key
	// after source, run and findings had already been appended.
	agent, err := o.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return store.DiscoveryRun{}, 0, 0, fmt.Errorf("orchestrator: inventory agent is not registered: %w", err)
	}
	if agent.Name != agentName || agent.Status == "offboarded" {
		return store.DiscoveryRun{}, 0, 0, errors.New("orchestrator: inventory agent identity is not active or does not match")
	}
	sourceKind = strings.TrimSpace(sourceKind)
	if sourceKind == "" {
		sourceKind = "agent"
	}
	sourceID := uuid.NewSHA1(agentInventorySourceNamespace, []byte(tenantID+"\x00"+agentName+"\x00"+sourceKind)).String()
	sourceName := sourcecatalog.AgentSourcePrefix + agentName + ":" + sourceKind
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
		ExecutedByAgentID: agentID,
	}); err != nil {
		return store.DiscoveryRun{}, recorded, rejected, err
	}
	return store.DiscoveryRun{
		ID: runID, TenantID: tenantID, SourceID: sourceID, Status: status,
		RequestedBy: requestedBy, Targets: len(findings), Discovered: recorded,
		Rejected: rejected, Error: msg, CreatedAt: ev.Time, ExecutedByAgentID: agentID,
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
	sourceName := sourcecatalog.SecretScanSourcePrefix + scanner
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
		switch result.Kind {
		case "ct_log", "network", "ssh", "cloud_provider", "k8s_tls_auto_issuance":
		default:
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
		switch result.Status {
		case "succeeded", "failed":
		case "blocked", "rejected":
			if result.Kind == "ct_log" {
				return fmt.Errorf("orchestrator: invalid discovery target result status %q", result.Status)
			}
		case "not_delivered":
			// A Kubernetes TLS resource the run found and could not deliver to
			// (B15-L1); the reason travels with it.
			if result.Kind != "k8s_tls_auto_issuance" || strings.TrimSpace(result.Error) == "" {
				return fmt.Errorf("orchestrator: invalid discovery target result status %q", result.Status)
			}
		case "delivery_queued", "delivered":
			// A Kubernetes TLS resource handed to its source's in-cluster agent
			// (B15-L1): queued until the agent reports, delivered once deployed.
			if result.Kind != "k8s_tls_auto_issuance" || strings.TrimSpace(result.Error) != "" {
				return fmt.Errorf("orchestrator: invalid discovery target result status %q", result.Status)
			}
		default:
			return fmt.Errorf("orchestrator: invalid discovery target result status %q", result.Status)
		}
		if result.Cursor < 0 {
			return errors.New("orchestrator: discovery target result cursor must be non-negative")
		}
		if result.Kind != "ct_log" && result.Cursor != 0 {
			return errors.New("orchestrator: only CT-log target results carry a cursor")
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
// discoveryRunFinished reports whether the projection holds a run in a
// terminal status. A run it has not seen, or an id that names no run, is not
// finished.
func (o *Orchestrator) discoveryRunFinished(ctx context.Context, tenantID, runID string) (bool, error) {
	if _, err := uuid.Parse(runID); err != nil {
		return false, nil
	}
	run, err := o.store.GetDiscoveryRun(ctx, tenantID, runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch run.Status {
	case "succeeded", "partial", "failed":
		return true, nil
	}
	return false, nil
}

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
