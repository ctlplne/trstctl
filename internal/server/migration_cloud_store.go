// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A cloud-store member's live gate (A166).
//
// An appliance member's gate is the relay's signed listener handshake. A
// cloud certificate store has no listener the control plane can reach on the
// member's behalf: the store is what the provider's load balancers read, and
// they pick a change up on the provider's schedule. So the gate asks the store
// itself, through the same readback an operator's drift check uses: after the
// control plane's own client installs the successor, the store must report the
// successor's certificate as the one its binding serves, and after a rollback
// re-binds the predecessor, the store must report the predecessor. Anything
// else is a failed verdict, which starts the run's automatic rollback; a store
// that cannot be asked at all leaves the row to retry rather than fail the
// member on a transient error.

// cloudStoreClaim is what one control-plane row asserts about a member.
type cloudStoreClaim struct {
	runID, waveID, identityID string
	stage                     migration.ObservationStage
	targetID, revision        string
	connector, target         string
	config                    json.RawMessage
	// want is the certificate the store must now serve: the successor after a
	// deploy, the predecessor after a rollback.
	want string
}

// cloudStoreMigrationRow reports whether a row is a cloud-store member's work:
// stamped for the control plane and carrying a migration run.
func cloudStoreMigrationRow(m orchestrator.Message, migrationRunID string) bool {
	return m.RequiredAgentRole == string(connector.VantageControlPlane) && strings.TrimSpace(migrationRunID) != ""
}

// deferDeployUnlessBound applies the A59 relay deferral to every deploy except
// a cloud-store member's: its row is stamped for the control plane, no agent
// can claim it, and the run bound the control plane as its executor when it
// started, so a relay enrolled since then does not strand it.
func (d *issuanceDispatcher) deferDeployUnlessBound(ctx context.Context, m orchestrator.Message, p *connector.DeployPayload) error {
	if cloudStoreMigrationRow(m, p.MigrationRunID) {
		return nil
	}
	return d.deferDeployToEnrolledRelay(ctx, m.TenantID, p.Connector)
}

// closeCloudStoreGate runs after a control-plane deploy, fresh or already
// committed: a cloud-store member's deploy is followed by the store readback
// that closes its live gate. Any other deploy returns its own result.
func (d *issuanceDispatcher) closeCloudStoreGate(ctx context.Context, m orchestrator.Message, p *connector.DeployPayload, deployErr error) error {
	if deployErr != nil || !cloudStoreMigrationRow(m, p.MigrationRunID) {
		return deployErr
	}
	return d.observeCloudStoreMigration(ctx, m.TenantID, m.IdempotencyKey, cloudStoreClaim{
		runID: p.MigrationRunID, waveID: p.MigrationWaveID, identityID: p.IdentityID, stage: migration.StageSuccessor,
		targetID: p.TargetID, revision: p.TargetRevision, connector: p.Connector, target: p.Target,
		config: append(json.RawMessage(nil), p.TargetConfig...), want: p.Fingerprint,
	})
}

// closeCloudStoreRollbackGate runs after a control-plane rollback, fresh or
// already committed, and records the re-bind against the run when the command
// belongs to a cloud-store member.
func (d *issuanceDispatcher) closeCloudStoreRollbackGate(ctx context.Context, m orchestrator.Message) error {
	var req struct {
		controlPlaneRollbackCommand
		MigrationRunID  string `json:"migration_run_id"`
		MigrationWaveID string `json:"migration_wave_id"`
	}
	if json.Unmarshal(m.Payload, &req) != nil || !cloudStoreMigrationRow(m, req.MigrationRunID) {
		return nil
	}
	return d.observeCloudStoreMigration(ctx, m.TenantID, m.IdempotencyKey, cloudStoreClaim{
		runID: req.MigrationRunID, waveID: req.MigrationWaveID, identityID: req.IdentityID,
		stage: migration.StageRollbackSuccessor, targetID: req.TargetID, connector: req.Connector, target: req.Target,
		config: append(json.RawMessage(nil), req.TargetConfig...), want: req.PredecessorFingerprint,
	})
}

// observeCloudStoreMigration reads the store back and records the verdict
// against the immutable member binding, idempotently per row.
func (d *issuanceDispatcher) observeCloudStoreMigration(ctx context.Context, tenantID, idempotencyKey string, claim cloudStoreClaim) error {
	if d.store == nil || d.orch == nil || d.connectorRegistry == nil {
		return errors.New("server: the cloud-store migration gate is not configured")
	}
	record, err := d.store.GetMigrationRun(ctx, tenantID, claim.runID)
	if err != nil {
		return err
	}
	member, found := migration.Member(record.Run, claim.waveID, claim.identityID)
	if !found {
		return orchestrator.DefiniteNoEffect(errors.New("server: cloud-store migration row names no run member"))
	}
	if err := validateCloudStoreClaim(member.Binding, claim); err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	b := member.Binding
	installed, err := d.connectorRegistry.Readback(ctx, connector.DeployPayload{
		TenantID: tenantID, IdentityID: claim.identityID, TargetID: b.TargetID, TargetRevision: b.TargetRevision,
		Connector: b.Connector, Target: b.Target, TargetConfig: append(json.RawMessage(nil), b.TargetConfig...),
	})
	if err != nil && !errors.Is(err, connector.ErrReadbackNotConfigured) && !errors.Is(err, connector.ErrReadbackUnsupported) {
		return fmt.Errorf("server: read back the cloud store for the migration gate: %w", err)
	}
	obs := cloudStoreObservation(claim, installed, err)
	if obs.Verdict == migration.VerdictVerified && claim.stage == migration.StageSuccessor {
		obs.SuccessorFingerprint = b.SuccessorFingerprint
	}
	eventID := orchestrator.MigrationEventID(tenantID, claim.runID, "receipt:"+idempotencyKey)
	updated, err := d.orch.UpdateMigrationRun(ctx, tenantID, claim.runID, eventID,
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			return migration.Observe(current, obs)
		})
	if err != nil {
		return err
	}
	return syncIncidentMigrationState(ctx, d.store, d.orch, d.audit, tenantID, updated)
}

// cloudStoreObservation turns the store's answer into the member's verdict:
// verified only when the store serves exactly the certificate the row
// installed or restored. A store that cannot report what it serves fails the
// gate rather than pass it on silence.
func cloudStoreObservation(claim cloudStoreClaim, installed connector.Installed, readErr error) migration.Observation {
	obs := migration.Observation{WaveID: claim.waveID, IdentityID: claim.identityID, Stage: claim.stage, Verdict: migration.VerdictFailed}
	if readErr == nil && connector.ClassifyReadback(installed, cleanFingerprint(claim.want)) == connector.ReadbackServing {
		obs.Verdict = migration.VerdictVerified
	}
	return obs
}

// validateCloudStoreClaim binds a control-plane row to the member it names: the
// row must carry the member's exact route and configuration, and the
// certificate it installed or restored must be the one the binding names.
func validateCloudStoreClaim(b migration.MemberBinding, claim cloudStoreClaim) error {
	want := b.SuccessorFingerprint
	if claim.stage == migration.StageRollbackSuccessor {
		want = b.PredecessorFingerprint
	}
	switch {
	case !b.OnControlPlane():
		return errors.New("server: a control-plane migration row names a member another executor runs")
	case claim.targetID != b.TargetID || (claim.revision != "" && claim.revision != b.TargetRevision):
		return errors.New("server: cloud-store migration row drifted from the member's target revision")
	case claim.connector != b.Connector || claim.target != b.Target:
		return errors.New("server: cloud-store migration row drifted from the member's route")
	case !sameMigrationJSON(claim.config, b.TargetConfig):
		return errors.New("server: cloud-store migration row drifted from the member's target configuration")
	case strings.TrimSpace(want) == "" || cleanFingerprint(claim.want) != cleanFingerprint(want):
		return errors.New("server: cloud-store migration row does not carry the certificate the member binds")
	}
	return nil
}
