// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"bytes"
	"context"
	"fmt"
	"reflect"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type secretSyncLifecycleJob struct {
	source    events.Event
	target    string
	sequences map[uint64]struct{}
}

type secretSyncTenantLifecycle struct {
	registered       bool
	offboarded       bool
	offboardSequence uint64
	targets          map[uint64]struct{}
	jobs             map[string]*secretSyncLifecycleJob
}

// secretSyncLifecycleAuthority is the single decision maker for whether a
// secret-bearing event belongs to an erased tenant registration. ELI5: an
// offboard is an eraser. We remember which queue and outcome lines it erased so
// a late old outcome cannot become live merely because the same tenant UUID was
// registered again.
type secretSyncLifecycleAuthority struct {
	head               uint64
	skipSequences      map[uint64]struct{}
	lifecycles         map[string]secretSyncTenantLifecycle
	erasedJobs         map[string]struct{}
	erasedAt           map[string]uint64
	terminalByIdentity map[string]events.Event
	terminalByJob      map[string]retainedSecretSyncTerminal
	activeTerminal     map[string]retainedSecretSyncTerminal
}

func newSecretSyncLifecycleAuthority() *secretSyncLifecycleAuthority {
	return &secretSyncLifecycleAuthority{
		skipSequences:      map[uint64]struct{}{},
		lifecycles:         map[string]secretSyncTenantLifecycle{},
		erasedJobs:         map[string]struct{}{},
		erasedAt:           map[string]uint64{},
		terminalByIdentity: map[string]events.Event{},
		terminalByJob:      map[string]retainedSecretSyncTerminal{},
		activeTerminal:     map[string]retainedSecretSyncTerminal{},
	}
}

func classifySecretSyncLifecycle(ctx context.Context, log *events.Log) (*secretSyncLifecycleAuthority, error) {
	var authority *secretSyncLifecycleAuthority
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := log.LastSequence(readCtx)
		if err != nil {
			return err
		}
		authority, err = classifySecretSyncLifecycleThrough(readCtx, log, head)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("projections: classify retained secret-sync lifecycle: %w", err)
	}
	return authority, nil
}

// classifySecretSyncLifecycleThrough is used while the caller already owns the
// history read wall. Rebuild and snapshot restore pin one head and use the same
// authority for both their preflight and their bounded replay.
func classifySecretSyncLifecycleThrough(
	ctx context.Context,
	log *events.Log,
	head uint64,
) (*secretSyncLifecycleAuthority, error) {
	authority := newSecretSyncLifecycleAuthority()
	authority.head = head
	if err := log.ReplayThrough(ctx, 0, head, func(event events.Event) error {
		_, err := authority.observe(event)
		return err
	}); err != nil {
		return nil, err
	}
	if err := authority.validateTargetOrder(); err != nil {
		return nil, err
	}
	return authority, nil
}

func (a *secretSyncLifecycleAuthority) skip(event events.Event) (bool, error) {
	if event.Sequence <= a.head {
		_, skip := a.skipSequences[event.Sequence]
		return skip, nil
	}
	skip, err := a.observe(event)
	if err == nil && event.Sequence > a.head {
		a.head = event.Sequence
	}
	return skip, err
}

func (a *secretSyncLifecycleAuthority) observe(event events.Event) (bool, error) {
	if event.Sequence == 0 || event.Sequence > uint64(1<<63-1) {
		if isSecretSyncLifecycleEvent(event) {
			return false, fmt.Errorf("projections: secret-sync lifecycle event sequence is outside PostgreSQL bigint")
		}
		return false, nil
	}

	lifecycle := a.lifecycles[event.TenantID]
	if lifecycle.targets == nil {
		lifecycle.targets = map[uint64]struct{}{}
	}
	if lifecycle.jobs == nil {
		lifecycle.jobs = map[string]*secretSyncLifecycleJob{}
	}

	skip := false
	switch event.Type {
	case EventTenantRegistered:
		// Registration is idempotent inside one live lifecycle. Only an actual
		// offboard followed by registration begins a new lifecycle; a duplicate
		// registration must not forget already-queued jobs.
		if !lifecycle.registered || lifecycle.offboarded {
			lifecycle = secretSyncTenantLifecycle{
				registered: true,
				targets:    map[uint64]struct{}{},
				jobs:       map[string]*secretSyncLifecycleJob{},
			}
		}
	case EventTenantOffboarded:
		for sequence := range lifecycle.targets {
			a.skipSequences[sequence] = struct{}{}
		}
		for jobID, job := range lifecycle.jobs {
			jobKey := secretSyncLifecycleJobKey(event.TenantID, jobID)
			a.erasedJobs[jobKey] = struct{}{}
			a.erasedAt[jobKey] = event.Sequence
			delete(a.activeTerminal, jobKey)
			for sequence := range job.sequences {
				a.skipSequences[sequence] = struct{}{}
			}
		}
		lifecycle.targets = map[uint64]struct{}{}
		lifecycle.jobs = map[string]*secretSyncLifecycleJob{}
		lifecycle.offboarded = true
		lifecycle.offboardSequence = event.Sequence
	case EventApplicationSecretCreated, EventApplicationSecretRotated,
		EventApplicationSecretRecovered, EventApplicationSecretDeleted:
		if schemaVersionOf(event) != ApplicationSecretMutationSchemaVersion {
			break
		}
		var payload ApplicationSecretMutation
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if lifecycle.offboarded {
			a.skipSequences[event.Sequence] = struct{}{}
			skip = true
		} else {
			lifecycle.targets[event.Sequence] = struct{}{}
		}
		if payload.Sync != nil {
			duplicate, err := a.observeQueuedJob(event, payload.Sync.ID, payload.Sync.Target, &lifecycle)
			if err != nil {
				return false, err
			}
			if duplicate {
				a.skipSequences[event.Sequence] = struct{}{}
				skip = true
			}
		}
	case EventSecretSyncQueued:
		if err := ValidateSchemaVersion(event); err != nil {
			return false, err
		}
		var payload SecretSyncQueued
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" || event.ID != store.SecretSyncQueuedEventID(event.TenantID, payload.ID) {
			return false, fmt.Errorf("%w: secret-sync queued event identity is not canonical", store.ErrIdempotencyConflict)
		}
		duplicate, err := a.observeQueuedJob(event, payload.ID, payload.Target, &lifecycle)
		if err != nil {
			return false, err
		}
		if duplicate || lifecycle.offboarded {
			a.skipSequences[event.Sequence] = struct{}{}
			skip = true
		} else {
			lifecycle.targets[event.Sequence] = struct{}{}
		}
	case EventSecretSyncDelivered, EventSecretSyncFailed:
		terminal, duplicate, err := a.decodeTerminal(event)
		if err != nil {
			return false, err
		}
		jobKey := secretSyncLifecycleJobKey(event.TenantID, terminal.row.JobID)
		if duplicate {
			a.skipSequences[event.Sequence] = struct{}{}
			skip = true
			break
		}
		if _, erased := a.erasedJobs[jobKey]; erased {
			a.skipSequences[event.Sequence] = struct{}{}
			skip = true
			break
		}
		job, current := lifecycle.jobs[terminal.row.JobID]
		if current && !lifecycle.offboarded {
			job.sequences[event.Sequence] = struct{}{}
			a.activeTerminal[jobKey] = terminal
			break
		}
		if lifecycle.offboarded {
			a.erasedJobs[jobKey] = struct{}{}
			a.erasedAt[jobKey] = lifecycle.offboardSequence
			a.skipSequences[event.Sequence] = struct{}{}
			skip = true
			break
		}
		return false, fmt.Errorf("%w: secret-sync terminal job %s has no queued command in its tenant lifecycle", store.ErrIdempotencyConflict, terminal.row.JobID)
	}
	a.lifecycles[event.TenantID] = lifecycle
	return skip, nil
}

func (a *secretSyncLifecycleAuthority) observeQueuedJob(
	event events.Event,
	jobID, target string,
	lifecycle *secretSyncTenantLifecycle,
) (bool, error) {
	if jobID == "" || target == "" {
		return false, fmt.Errorf("projections: %s secret-sync job identity or target is empty", event.Type)
	}
	jobKey := secretSyncLifecycleJobKey(event.TenantID, jobID)
	if _, erased := a.erasedJobs[jobKey]; erased && !lifecycle.offboarded {
		return false, fmt.Errorf("%w: secret-sync job %s reuses an erased tenant lifecycle identity", store.ErrIdempotencyConflict, jobID)
	}
	if lifecycle.offboarded {
		a.erasedJobs[jobKey] = struct{}{}
		a.erasedAt[jobKey] = lifecycle.offboardSequence
		return false, nil
	}
	if prior, exists := lifecycle.jobs[jobID]; exists {
		if !sameSecretSyncLifecycleEnvelope(prior.source, event) {
			return false, fmt.Errorf("%w: secret-sync job %s has conflicting queued sources", store.ErrIdempotencyConflict, jobID)
		}
		return true, nil
	}
	lifecycle.jobs[jobID] = &secretSyncLifecycleJob{
		source:    event,
		target:    target,
		sequences: map[uint64]struct{}{event.Sequence: {}},
	}
	return false, nil
}

// validateTargetOrder rejects a retained history that has already executed a
// newer command while an older command for the same receiver target is still
// live. ELI5: event sequence is the queue number. If ticket 3 has a terminal
// receipt while ticket 2 can still run, replay cannot safely guess whether
// ticket 2 would overwrite ticket 3, so startup stops before creating workers.
func (a *secretSyncLifecycleAuthority) validateTargetOrder() error {
	for tenantID, lifecycle := range a.lifecycles {
		for olderID, older := range lifecycle.jobs {
			olderKey := secretSyncLifecycleJobKey(tenantID, olderID)
			if _, terminal := a.activeTerminal[olderKey]; terminal {
				continue
			}
			for newerID, newer := range lifecycle.jobs {
				if newer.target != older.target || newer.source.Sequence <= older.source.Sequence {
					continue
				}
				newerKey := secretSyncLifecycleJobKey(tenantID, newerID)
				if _, terminal := a.activeTerminal[newerKey]; !terminal {
					continue
				}
				return fmt.Errorf(
					"%w: retained secret-sync target %s has active older command %s at sequence %d overtaken by terminal command %s at sequence %d",
					store.ErrIdempotencyConflict, older.target, olderID, older.source.Sequence,
					newerID, newer.source.Sequence,
				)
			}
		}
	}
	return nil
}

func (a *secretSyncLifecycleAuthority) decodeTerminal(
	event events.Event,
) (retainedSecretSyncTerminal, bool, error) {
	if err := ValidateSchemaVersion(event); err != nil {
		return retainedSecretSyncTerminal{}, false, err
	}
	if prior, ok := a.terminalByIdentity[event.ID]; ok {
		if !sameSecretSyncLifecycleEnvelope(prior, event) {
			return retainedSecretSyncTerminal{}, false, fmt.Errorf("%w: secret-sync terminal event id %q has conflicting retained envelopes", events.ErrConflictingEventIdentity, event.ID)
		}
		for _, terminal := range a.terminalByJob {
			if terminal.event.ID == event.ID {
				return terminal, true, nil
			}
		}
		return retainedSecretSyncTerminal{}, false, fmt.Errorf("%w: secret-sync terminal event id %q lost its job binding", store.ErrIdempotencyConflict, event.ID)
	}

	terminal := store.SecretSyncTerminalEvent{
		TenantID: event.TenantID, OccurredAt: event.Time,
		EventID: event.ID, EventType: event.Type,
		EventSequence: int64(event.Sequence), // #nosec G115 -- observe checked the explicit PostgreSQL bigint bound.
		PayloadDigest: crypto.SHA256Hex(event.Data),
	}
	switch event.Type {
	case EventSecretSyncDelivered:
		var payload SecretSyncDelivered
		if err := decode(event, &payload); err != nil {
			return retainedSecretSyncTerminal{}, false, err
		}
		if payload.ID == "" || payload.Attempts < 1 || event.ID != store.SecretSyncDeliveredEventID(event.TenantID, payload.ID) {
			return retainedSecretSyncTerminal{}, false, fmt.Errorf("%w: secret-sync delivered event identity is not canonical", store.ErrIdempotencyConflict)
		}
		if schemaVersionOf(event) >= SecretSyncEventSchemaVersion && payload.TenantEpoch == "" {
			return retainedSecretSyncTerminal{}, false, fmt.Errorf("projections: %s v%d requires tenant_epoch", event.Type, schemaVersionOf(event))
		}
		terminal.TenantEpoch, terminal.JobID = payload.TenantEpoch, payload.ID
		terminal.Status, terminal.Attempts = store.SecretSyncJobDelivered, payload.Attempts
		terminal.RemoteVersion = payload.RemoteVersion
	case EventSecretSyncFailed:
		var payload SecretSyncFailed
		if err := decode(event, &payload); err != nil {
			return retainedSecretSyncTerminal{}, false, err
		}
		if payload.ID == "" || payload.Attempts < 1 || payload.Error == "" || event.ID != store.SecretSyncFailedEventID(event.TenantID, payload.ID) {
			return retainedSecretSyncTerminal{}, false, fmt.Errorf("%w: secret-sync failed event identity is not canonical", store.ErrIdempotencyConflict)
		}
		if schemaVersionOf(event) >= SecretSyncEventSchemaVersion && payload.TenantEpoch == "" {
			return retainedSecretSyncTerminal{}, false, fmt.Errorf("projections: %s v%d requires tenant_epoch", event.Type, schemaVersionOf(event))
		}
		terminal.TenantEpoch, terminal.JobID = payload.TenantEpoch, payload.ID
		terminal.Status, terminal.Attempts = store.SecretSyncJobFailed, payload.Attempts
		terminal.LastError = payload.Error
		terminal.FailureDefinitelyNoEffect = schemaVersionOf(event) >= SecretSyncEventSchemaVersion
	default:
		return retainedSecretSyncTerminal{}, false, fmt.Errorf("projections: %s is not a secret-sync terminal event", event.Type)
	}

	jobKey := secretSyncLifecycleJobKey(event.TenantID, terminal.JobID)
	if prior, ok := a.terminalByJob[jobKey]; ok {
		if prior.row.Status != terminal.Status {
			return retainedSecretSyncTerminal{}, false, fmt.Errorf("%w: secret-sync job %s has both delivered and failed retained outcomes", store.ErrIdempotencyConflict, terminal.JobID)
		}
		return retainedSecretSyncTerminal{}, false, fmt.Errorf("%w: secret-sync job %s has two terminal event identities", store.ErrIdempotencyConflict, terminal.JobID)
	}
	retained := retainedSecretSyncTerminal{event: event, row: terminal}
	a.terminalByIdentity[event.ID] = event
	a.terminalByJob[jobKey] = retained
	return retained, false, nil
}

func sameSecretSyncLifecycleEnvelope(left, right events.Event) bool {
	left.Sequence = 0
	right.Sequence = 0
	return left.ID == right.ID && left.Type == right.Type && left.TenantID == right.TenantID &&
		left.Time.Equal(right.Time) && left.SchemaVersion == right.SchemaVersion &&
		bytes.Equal(left.Data, right.Data) && reflect.DeepEqual(left.Actor, right.Actor)
}

func secretSyncLifecycleJobKey(tenantID, jobID string) string {
	return tenantID + "\x1f" + jobID
}

func isSecretSyncLifecycleEvent(event events.Event) bool {
	switch event.Type {
	case EventTenantRegistered, EventTenantOffboarded,
		EventApplicationSecretCreated, EventApplicationSecretRotated,
		EventApplicationSecretRecovered, EventApplicationSecretDeleted,
		EventSecretSyncQueued, EventSecretSyncDelivered, EventSecretSyncFailed:
		return true
	default:
		return false
	}
}
