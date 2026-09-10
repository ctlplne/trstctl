// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var migrationEventNamespace = uuid.MustParse("c6bf2f04-3314-5ed8-926d-64fc97f0aa40")

// DestinationIncidentMigrationRevoke is H3's bounded control-plane effect. It
// is released only by H2 after every member in the cohort has a signed live
// listener verdict.
const DestinationIncidentMigrationRevoke = "incident.fleet_reissuance.revoke"

// MigrationEventID gives API commands and signed receipts a retry-stable event
// identity without retaining a raw Idempotency-Key in the event stream.
func MigrationEventID(tenantID, runID, purpose string) string {
	return uuid.NewSHA1(migrationEventNamespace,
		[]byte(tenantID+"\x00"+runID+"\x00"+purpose)).String()
}

// MigrationRunID derives the same run UUID after an API crash and retry.
func MigrationRunID(tenantID, idempotencyKey string) string {
	return uuid.NewSHA1(migrationEventNamespace,
		[]byte("run\x00"+tenantID+"\x00"+idempotencyKey)).String()
}

// RecordMigrationRun appends one complete aggregate snapshot, projects it, and
// publishes only the effects this transition newly licensed in one tenant SQL
// transaction. The append may win before SQL; ReconcileOutbox replays Actions.
func (o *Orchestrator) RecordMigrationRun(
	ctx context.Context,
	tenantID, eventID string,
	run migration.Run,
	actions []migration.Action,
) (store.MigrationRun, error) {
	if o == nil || o.store == nil || o.log == nil || o.proj == nil || o.outbox == nil {
		return store.MigrationRun{}, errors.New("orchestrator: migration run spine is not configured")
	}
	if strings.TrimSpace(eventID) == "" {
		return store.MigrationRun{}, errors.New("orchestrator: migration event id is required")
	}
	if err := migration.ValidateExecutableRun(run); err != nil {
		return store.MigrationRun{}, err
	}
	if err := migration.ValidateActions(run, actions); err != nil {
		return store.MigrationRun{}, err
	}
	for _, action := range actions {
		if _, err := migrationActionEntry(tenantID, run, action); err != nil {
			return store.MigrationRun{}, err
		}
	}
	payload, err := json.Marshal(projections.MigrationRunRecorded{Run: run, Actions: actions})
	if err != nil {
		return store.MigrationRun{}, err
	}
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventMigrationRunRecorded,
			TenantID: tenantID, Data: payload,
		})
		if err != nil {
			return err
		}
		if ev.ID != eventID || ev.Type != projections.EventMigrationRunRecorded ||
			ev.TenantID != tenantID || !bytes.Equal(ev.Data, payload) {
			return fmt.Errorf("%w: canonical migration run differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		for _, action := range actions {
			entry, err := migrationActionEntry(tenantID, run, action)
			if err != nil {
				return err
			}
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return store.MigrationRun{}, err
	}
	return o.store.GetMigrationRun(ctx, tenantID, run.ID)
}

// UpdateMigrationRun serializes one state transition under the tenant row lock.
// A retained event with the same identity is replayed into SQL/outbox first,
// closing the append-won/transaction-lost retry window without re-running fn.
func (o *Orchestrator) UpdateMigrationRun(
	ctx context.Context,
	tenantID, runID, eventID string,
	fn func(migration.Run) (migration.Run, []migration.Action, error),
) (store.MigrationRun, error) {
	if o == nil || o.store == nil || o.log == nil || o.proj == nil || o.outbox == nil || fn == nil {
		return store.MigrationRun{}, errors.New("orchestrator: migration run spine is not configured")
	}
	if canonical, found, err := o.log.EventByID(ctx, eventID); err != nil {
		return store.MigrationRun{}, err
	} else if found {
		if err := validateMigrationEventBinding(canonical, tenantID, runID); err != nil {
			return store.MigrationRun{}, fmt.Errorf("%w: migration event identity is already bound", store.ErrIdempotencyConflict)
		}
		if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			if err := o.store.LockCertificateMetadataOrderTx(ctx, tx, tenantID); err != nil {
				return err
			}
			current, err := o.store.MigrationRunForUpdateTx(ctx, tx, tenantID, runID)
			if err != nil {
				return err
			}
			return o.catchUpMigrationRunTx(ctx, tx, tenantID, runID, current.LastEventSequence)
		}); err != nil {
			return store.MigrationRun{}, err
		}
		return o.store.GetMigrationRun(ctx, tenantID, runID)
	}

	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Cover catch-up and rollback decisions before the aggregate row lock;
		// projection may read successor state before its first certificate write.
		if err := o.store.LockCertificateMetadataOrderTx(ctx, tx, tenantID); err != nil {
			return err
		}
		current, err := o.store.MigrationRunForUpdateTx(ctx, tx, tenantID, runID)
		if err != nil {
			return err
		}
		if err := o.catchUpMigrationRunTx(ctx, tx, tenantID, runID, current.LastEventSequence); err != nil {
			return err
		}
		current, err = o.store.MigrationRunForUpdateTx(ctx, tx, tenantID, runID)
		if err != nil {
			return err
		}
		// Another writer may have appended this exact receipt while this writer
		// waited for the row lock. Catch-up projected it, so return without
		// executing fn against its already-advanced state.
		if canonical, found, err := o.log.EventByID(ctx, eventID); err != nil {
			return err
		} else if found {
			return validateMigrationEventBinding(canonical, tenantID, runID)
		}
		next, actions, err := fn(current.Run)
		if err != nil {
			return err
		}
		if next.ID != runID {
			return errors.New("orchestrator: migration mutation changed the aggregate identity")
		}
		if err := migration.ValidateExecutableRun(next); err != nil {
			return err
		}
		if err := migration.ValidateActions(next, actions); err != nil {
			return err
		}
		for _, action := range actions {
			if _, err := migrationActionEntry(tenantID, next, action); err != nil {
				return err
			}
		}
		payload, err := json.Marshal(projections.MigrationRunRecorded{Run: next, Actions: actions})
		if err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventMigrationRunRecorded,
			TenantID: tenantID, Data: payload,
		})
		if err != nil {
			return err
		}
		if ev.ID != eventID || ev.TenantID != tenantID || ev.Type != projections.EventMigrationRunRecorded ||
			!bytes.Equal(ev.Data, payload) {
			return fmt.Errorf("%w: canonical migration mutation differs", store.ErrIdempotencyConflict)
		}
		return o.applyMigrationEventTx(ctx, tx, ev)
	})
	if err != nil {
		return store.MigrationRun{}, err
	}
	return o.store.GetMigrationRun(ctx, tenantID, runID)
}

// catchUpMigrationRunTx repairs every retained transition for one aggregate
// after the locked SQL snapshot. The row lock spans replay, projection, and
// outbox reconstruction. A different receipt therefore cannot append from an
// older snapshot after a previous append won but its SQL transaction lost.
func (o *Orchestrator) catchUpMigrationRunTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, runID string,
	after uint64,
) error {
	from := after + 1
	if from == 0 {
		return errors.New("orchestrator: migration event sequence overflow")
	}
	return o.log.Replay(ctx, from, func(ev events.Event) error {
		if ev.Type != projections.EventMigrationRunRecorded || ev.TenantID != tenantID {
			return nil
		}
		var recorded projections.MigrationRunRecorded
		if err := json.Unmarshal(ev.Data, &recorded); err != nil {
			return fmt.Errorf("orchestrator: decode retained migration run: %w", err)
		}
		if recorded.Run.ID != runID {
			return nil
		}
		return o.applyMigrationEventTx(ctx, tx, ev)
	})
}

func validateMigrationEventBinding(ev events.Event, tenantID, runID string) error {
	if ev.Type != projections.EventMigrationRunRecorded || ev.TenantID != tenantID {
		return errors.New("orchestrator: retained migration event has a different envelope binding")
	}
	var recorded projections.MigrationRunRecorded
	if err := json.Unmarshal(ev.Data, &recorded); err != nil {
		return fmt.Errorf("orchestrator: decode retained migration event: %w", err)
	}
	if recorded.Run.ID != runID {
		return errors.New("orchestrator: retained migration event has a different aggregate binding")
	}
	return nil
}

func (o *Orchestrator) applyMigrationEventTx(ctx context.Context, tx pgx.Tx, ev events.Event) error {
	var recorded projections.MigrationRunRecorded
	if err := json.Unmarshal(ev.Data, &recorded); err != nil {
		return err
	}
	if err := migration.ValidateExecutableRun(recorded.Run); err != nil {
		return err
	}
	if err := migration.ValidateActions(recorded.Run, recorded.Actions); err != nil {
		return err
	}
	if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
		return err
	}
	for _, action := range recorded.Actions {
		entry, err := migrationActionEntry(ev.TenantID, recorded.Run, action)
		if err != nil {
			return err
		}
		if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry); err != nil {
			return err
		}
	}
	return nil
}

type migrationEndpointRenewIntent struct {
	IssuingAuthorityID       string          `json:"issuing_authority_id"`
	Connector                string          `json:"connector"`
	Target                   string          `json:"target"`
	TargetID                 string          `json:"target_id"`
	Revision                 string          `json:"target_revision"`
	IdentityID               string          `json:"identity_id"`
	TargetConfig             json.RawMessage `json:"target_config"`
	VerifyAddress            string          `json:"verify_address"`
	VerifyServerName         string          `json:"verify_server_name,omitempty"`
	SubjectCommonName        string          `json:"subject_common_name"`
	SubjectDNSNames          []string        `json:"subject_dns_names"`
	PredecessorCertificateID string          `json:"predecessor_certificate_id"`
	MigrationRunID           string          `json:"migration_run_id"`
	MigrationWaveID          string          `json:"migration_wave_id"`
	RequiredAgentID          string          `json:"required_agent_id"`
}

// IncidentPredecessorRevocationIntent contains only immutable public identity.
// The worker re-loads the certificate row and refuses any mismatch before it
// appends the stable revocation event.
type IncidentPredecessorRevocationIntent struct {
	RunID                    string `json:"run_id"`
	WaveID                   string `json:"wave_id"`
	IdentityID               string `json:"identity_id"`
	PredecessorCertificateID string `json:"predecessor_certificate_id"`
	PredecessorFingerprint   string `json:"predecessor_fingerprint"`
	PredecessorCAID          string `json:"predecessor_ca_id"`
}

func migrationActionEntry(tenantID string, run migration.Run, action migration.Action) (Entry, error) {
	member, ok := migration.Member(run, action.WaveID, action.IdentityID)
	if !ok {
		return Entry{}, errors.New("orchestrator: migration action does not name a run member")
	}
	b := member.Binding
	var (
		destination string
		payload     []byte
		err         error
	)
	switch action.Kind {
	case migration.ActionDistributeTrust, migration.ActionRemoveTrust:
		operation := relay.TrustInstall
		anchor := append([]byte(nil), b.TrustAnchorPEM...)
		if action.Kind == migration.ActionRemoveTrust {
			operation = relay.TrustRemove
		}
		destination = relay.KindTrustDistribute
		payload, err = json.Marshal(relay.TrustDistributionIntent{
			RunID: run.ID, WaveID: action.WaveID, IdentityID: action.IdentityID,
			Operation: operation, AnchorPath: b.TrustAnchorPath, AnchorPEM: anchor,
			AnchorFingerprint: b.TrustAnchorFingerprint, RequiredAgentID: b.RequiredAgentID,
		})
	case migration.ActionIssueSuccessor:
		destination = relay.KindEndpointRenew
		payload, err = json.Marshal(migrationEndpointRenewIntent{
			IssuingAuthorityID: b.IssuingAuthorityID,
			Connector:          b.Connector, Target: b.Target, TargetID: b.TargetID,
			Revision: b.TargetRevision, IdentityID: action.IdentityID, TargetConfig: b.TargetConfig,
			VerifyAddress: b.VerifyAddress, VerifyServerName: b.VerifyServerName,
			SubjectCommonName: b.SubjectCommonName, SubjectDNSNames: b.SubjectDNSNames,
			PredecessorCertificateID: b.PredecessorCertificateID,
			MigrationRunID:           run.ID, MigrationWaveID: action.WaveID,
			RequiredAgentID: b.RequiredAgentID,
		})
	case migration.ActionRevokePredecessor:
		if run.Incident == nil {
			return Entry{}, errors.New("orchestrator: predecessor revocation requires an incident plan")
		}
		destination = DestinationIncidentMigrationRevoke
		payload, err = json.Marshal(IncidentPredecessorRevocationIntent{
			RunID: run.ID, WaveID: action.WaveID, IdentityID: action.IdentityID,
			PredecessorCertificateID: b.PredecessorCertificateID,
			PredecessorFingerprint:   b.PredecessorFingerprint, PredecessorCAID: b.PredecessorCAID,
		})
	case migration.ActionRollbackSuccessor:
		destination = relay.KindConnectorRollback
		payload, err = json.Marshal(relay.RollbackIntent{
			Connector: b.Connector, Target: b.Target, TargetID: b.TargetID,
			IdentityID: action.IdentityID, TargetConfig: b.TargetConfig,
			PredecessorFingerprint: b.PredecessorFingerprint,
			SuccessorFingerprint:   b.SuccessorFingerprint,
			VerifyAddress:          b.VerifyAddress, VerifyServerName: b.VerifyServerName,
			Reason:         "migration rollback: restore verified predecessor before removing successor trust",
			MigrationRunID: run.ID, MigrationWaveID: action.WaveID,
			RequiredAgentID: b.RequiredAgentID,
		})
	default:
		return Entry{}, fmt.Errorf("orchestrator: unsupported migration action %q", action.Kind)
	}
	if err != nil {
		return Entry{}, err
	}
	effectLane := "migration:identity:" + action.IdentityID
	if action.Kind == migration.ActionDistributeTrust || action.Kind == migration.ActionRemoveTrust {
		effectLane = "migration:trust:" + uuid.NewSHA1(migrationEventNamespace,
			[]byte(b.RequiredAgentID+"\x00"+b.TrustAnchorPath)).String()
	}
	entry := Entry{
		TenantID: tenantID, Destination: destination,
		IdempotencyKey: migrationActionKey(run, action), Payload: payload,
		EffectLane:        effectLane,
		RequiredAgentRole: mtls.AgentRoleHost, RequiredAgentID: b.RequiredAgentID,
	}
	if action.Kind == migration.ActionRevokePredecessor {
		entry.RequiredAgentRole = "control_plane"
		entry.RequiredAgentID = ""
	}
	return entry, nil
}

func migrationActionKey(run migration.Run, action migration.Action) string {
	key := "migration:" + run.ID + ":" + action.WaveID + ":" + action.IdentityID + ":" + string(action.Kind)
	if action.Kind == migration.ActionRollbackSuccessor || action.Kind == migration.ActionRemoveTrust {
		key += fmt.Sprintf(":attempt:%d", run.RollbackAttempt)
	}
	return key
}

func (o *Orchestrator) reconcileMigrationRun(ctx context.Context, ev events.Event) (int, error) {
	if err := projections.ValidateSchemaVersion(ev); err != nil {
		return 0, err
	}
	var recorded projections.MigrationRunRecorded
	if err := json.Unmarshal(ev.Data, &recorded); err != nil {
		return 0, fmt.Errorf("orchestrator: reconcile decode %s (seq %d): %w", ev.Type, ev.Sequence, err)
	}
	if err := migration.ValidateExecutableRun(recorded.Run); err != nil {
		return 0, err
	}
	if err := migration.ValidateActions(recorded.Run, recorded.Actions); err != nil {
		return 0, err
	}
	inserted := 0
	err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		for _, action := range recorded.Actions {
			entry, err := migrationActionEntry(ev.TenantID, recorded.Run, action)
			if err != nil {
				return err
			}
			created, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
			if err != nil {
				return err
			}
			if created {
				inserted++
			}
		}
		return nil
	})
	return inserted, err
}
