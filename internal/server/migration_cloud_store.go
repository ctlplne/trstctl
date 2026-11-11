// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/netsec"
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

// A166-L3: the store serving a certificate is not yet the load balancer
// serving it; the provider propagates a change to its load balancers on its
// own schedule. A member whose target names the endpoint its load balancer
// answers on (verify_address, with verify_server_name) has its gate closed by
// a handshake there as well: after the store serves the certificate, the
// endpoint must present it. Until it does, the row waits, rechecking without
// spending its retries, for up to the propagation window from when the row
// was queued; an endpoint still presenting another certificate after that
// fails the gate. The control plane dials the endpoint under its egress rules:
// public addresses only, unless the target grants private ranges
// (verify_private_egress_cidrs).

// Propagation defaults: how long a load balancer may keep serving the old
// certificate, and how often the gate looks again.
const (
	defaultCloudStorePropagationWindow = 30 * time.Minute
	cloudStorePropagationRecheck       = 30 * time.Second
	cloudStoreHandshakeTimeout         = 10 * time.Second
)

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
	return d.observeCloudStoreMigration(ctx, m, cloudStoreClaim{
		runID: p.MigrationRunID, waveID: p.MigrationWaveID, identityID: p.IdentityID, stage: migration.StageSuccessor,
		targetID: p.TargetID, revision: p.TargetRevision, connector: p.Connector, target: p.Target,
		config: append(json.RawMessage(nil), p.TargetConfig...), want: p.Fingerprint,
	})
}

// closeCloudStoreRollbackGate runs after a control-plane rollback, fresh or
// already committed, and records the re-bind against the run when the command
// belongs to a cloud-store member.
func (d *issuanceDispatcher) closeCloudStoreRollbackGate(ctx context.Context, m orchestrator.Message) error {
	claim, ok := cloudStoreRollbackClaim(m)
	if !ok {
		return nil
	}
	return d.observeCloudStoreMigration(ctx, m, claim)
}

// cloudStoreRollbackClaim reads a control-plane rollback command's member
// claim; ok is false for any row that is not a cloud-store member's.
func cloudStoreRollbackClaim(m orchestrator.Message) (cloudStoreClaim, bool) {
	var req struct {
		controlPlaneRollbackCommand
		MigrationRunID  string `json:"migration_run_id"`
		MigrationWaveID string `json:"migration_wave_id"`
	}
	if json.Unmarshal(m.Payload, &req) != nil || !cloudStoreMigrationRow(m, req.MigrationRunID) {
		return cloudStoreClaim{}, false
	}
	return cloudStoreClaim{
		runID: req.MigrationRunID, waveID: req.MigrationWaveID, identityID: req.IdentityID,
		stage: migration.StageRollbackSuccessor, targetID: req.TargetID, connector: req.Connector, target: req.Target,
		config: append(json.RawMessage(nil), req.TargetConfig...), want: req.PredecessorFingerprint,
	}, true
}

// cloudStoreDeployClaim reads a control-plane deploy row's member claim from
// its public routing, so a row that spent its retries is matched to its
// member without opening the sealed key it carried. A row sealed nothing when
// it held no key, and its plain payload names the same routing under the same
// field names.
func cloudStoreDeployClaim(m orchestrator.Message) (cloudStoreClaim, bool) {
	var routing sealedConnectorDeployPayload
	if json.Unmarshal(m.Payload, &routing) != nil ||
		(routing.Format != "" && routing.Format != connectorDeploySealedFormat) ||
		!cloudStoreMigrationRow(m, routing.MigrationRunID) {
		return cloudStoreClaim{}, false
	}
	return cloudStoreClaim{
		runID: routing.MigrationRunID, waveID: routing.MigrationWaveID, identityID: routing.IdentityID,
		stage: migration.StageSuccessor, targetID: routing.TargetID, revision: routing.Revision,
		connector: routing.Connector, target: routing.Target,
		config: append(json.RawMessage(nil), routing.TargetConfig...), want: routing.Fingerprint,
	}, true
}

// A cloud-store member's row that spends its retries (A166-L4).
//
// A relay that cannot install or restore a member says so in a signed failed
// receipt, and the failed verdict rolls the run back or halts it. A
// control-plane row has no relay to report for it: when the store stays
// unreachable, or keeps refusing the change, until the outbox stops retrying,
// the spent row is the member's receipt. It records the failed verdict for the
// stage it carried, under the same per-row event a readback would have used,
// so the run rolls back (or, for a rollback row, halts naming the member) as
// it would on a relay's failed receipt instead of waiting at its gate for an
// operator nobody told. A row that names no member or drifted from its
// binding fails no member; a verdict the member already holds, or one the
// run's phase no longer takes, is left as the run decided it.

// errCloudStoreGateMovedOn marks a spent row whose member the run has already
// decided: nothing is recorded and the row ends failed.
var errCloudStoreGateMovedOn = errors.New("server: the cloud-store member's gate has already moved on")

// failCloudStoreMigrationTerminal handles a spent cloud-store member row;
// handled is false for every other row.
func (d *issuanceDispatcher) failCloudStoreMigrationTerminal(ctx context.Context, m orchestrator.Message) (handled bool, err error) {
	var claim cloudStoreClaim
	var ok bool
	switch m.Destination {
	case "connector.deploy":
		claim, ok = cloudStoreDeployClaim(m)
	case orchestrator.DestinationConnectorRollback:
		claim, ok = cloudStoreRollbackClaim(m)
	}
	if !ok {
		return false, nil
	}
	if d.store == nil || d.orch == nil {
		return true, errors.New("server: the cloud-store migration gate is not configured")
	}
	record, err := d.store.GetMigrationRun(ctx, m.TenantID, claim.runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	member, found := migration.Member(record.Run, claim.waveID, claim.identityID)
	if !found || validateCloudStoreClaim(member.Binding, claim) != nil {
		return true, nil
	}
	obs := migration.Observation{WaveID: claim.waveID, IdentityID: claim.identityID, Stage: claim.stage, Verdict: migration.VerdictFailed}
	eventID := orchestrator.MigrationEventID(m.TenantID, claim.runID, "receipt:"+m.IdempotencyKey)
	updated, err := d.orch.UpdateMigrationRun(ctx, m.TenantID, claim.runID, eventID,
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			bound, found := migration.Member(current, claim.waveID, claim.identityID)
			if !found || memberStageVerdict(bound, claim.stage) != "" {
				return current, nil, errCloudStoreGateMovedOn
			}
			next, actions, err := migration.Observe(current, obs)
			if err != nil {
				return current, nil, fmt.Errorf("%w: %w", errCloudStoreGateMovedOn, err)
			}
			return next, actions, nil
		})
	if errors.Is(err, errCloudStoreGateMovedOn) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	return true, syncIncidentMigrationState(ctx, d.store, d.orch, d.audit, m.TenantID, updated)
}

// memberStageVerdict is the verdict a member already holds for the stage a
// cloud-store row carries.
func memberStageVerdict(member migration.RunMember, stage migration.ObservationStage) migration.Verdict {
	if stage == migration.StageRollbackSuccessor {
		return member.RollbackSuccessorVerdict
	}
	return member.SuccessorVerdict
}

// observeCloudStoreMigration reads the store back, and the member's load
// balancer when its target names one, and records the verdict against the
// immutable member binding, idempotently per row.
func (d *issuanceDispatcher) observeCloudStoreMigration(ctx context.Context, m orchestrator.Message, claim cloudStoreClaim) error {
	tenantID, idempotencyKey := m.TenantID, m.IdempotencyKey
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
	if obs.Verdict == migration.VerdictVerified && strings.TrimSpace(b.VerifyAddress) != "" {
		served, probeErr := cloudStoreServedFingerprint(ctx, b)
		if probeErr != nil || served != cleanFingerprint(claim.want) {
			queued, err := d.store.OutboxRowQueuedAt(ctx, tenantID, m.ID)
			if err != nil {
				return fmt.Errorf("server: read when the cloud-store migration row was queued: %w", err)
			}
			window := d.cloudStorePropagationWindow
			if window <= 0 {
				window = defaultCloudStorePropagationWindow
			}
			if time.Since(queued) < window {
				why := "presents " + served
				if probeErr != nil {
					why = "did not answer: " + probeErr.Error()
				}
				return orchestrator.DeferDeliveryUntil(fmt.Errorf(
					"server: the store serves the certificate, but %s %s; waiting for the provider to propagate it", b.VerifyAddress, why),
					time.Now().Add(cloudStorePropagationRecheck))
			}
			obs.Verdict = migration.VerdictFailed
		}
	}
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

// cloudStoreServedFingerprint is the SHA-256 of the leaf the member's load
// balancer presents at its verify address, dialed under the egress rules and
// any private ranges the target grants for it.
func cloudStoreServedFingerprint(ctx context.Context, b migration.MemberBinding) (string, error) {
	control := netsec.SafeDialControl
	var cfg struct {
		PrivateCIDRs []string `json:"verify_private_egress_cidrs"`
	}
	if json.Unmarshal(b.TargetConfig, &cfg) == nil && len(cfg.PrivateCIDRs) > 0 {
		opts, err := privateEgressSafeClientOptions(cfg.PrivateCIDRs)
		if err != nil {
			return "", err
		}
		control = netsec.SafeDialControlWithOptions(opts)
	}
	options := []tlsprobe.Option{tlsprobe.WithDialControl(control), tlsprobe.WithTimeout(cloudStoreHandshakeTimeout)}
	if name := strings.TrimSpace(b.VerifyServerName); name != "" {
		options = append(options, tlsprobe.WithServerName(name))
	}
	res, err := tlsprobe.Probe(ctx, strings.TrimSpace(b.VerifyAddress), options...)
	if err != nil {
		return "", err
	}
	if len(res.PeerCertificates) == 0 {
		return "", errors.New("the endpoint presented no certificate")
	}
	return crypto.SHA256Hex(res.PeerCertificates[0]), nil
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
