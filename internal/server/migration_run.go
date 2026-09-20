// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
)

type migrationReceiptClaim struct {
	runID, waveID, identityID string
	stage                     migration.ObservationStage
	trust                     *relay.TrustDistributionIntent
	renew                     *RelayDeployIntent
	rollback                  *relay.RollbackIntent
}

// recordMigrationResult applies only results whose immutable payload carries a
// migration run. It is called after receipt-signature and lease verification,
// but before the outbox claim is closed, so projection failure remains retryable.
func (s *Server) recordMigrationResult(
	ctx context.Context,
	tenantID, agentID, destination, idempotencyKey string,
	payload []byte,
	outcome, report, evidenceDigest string,
) (bool, error) {
	claim, handled, err := decodeMigrationReceiptClaim(destination, payload)
	if err != nil || !handled {
		return handled, err
	}
	if s.orch == nil {
		return true, errors.New("server: migration orchestrator is not configured")
	}
	obs := migration.Observation{
		WaveID: claim.waveID, IdentityID: claim.identityID, Stage: claim.stage,
		Verdict: migration.VerdictFailed,
	}
	if outcome != transport.JobOutcomeFailed && outcome != transport.JobOutcomeVerifyFailed {
		if err := validateVerifiedMigrationReport(claim, outcome, report, evidenceDigest, &obs); err != nil {
			return true, err
		}
		obs.Verdict = migration.VerdictVerified
	}
	eventID := orchestrator.MigrationEventID(tenantID, claim.runID, "receipt:"+idempotencyKey)
	updated, err := s.orch.UpdateMigrationRun(ctx, tenantID, claim.runID, eventID,
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			member, ok := migration.Member(current, claim.waveID, claim.identityID)
			if !ok {
				return current, nil, errors.New("server: migration receipt names no current run member")
			}
			if err := validateMigrationClaimBinding(member.Binding, agentID, claim); err != nil {
				return current, nil, err
			}
			return migration.Observe(current, obs)
		})
	if err != nil {
		return true, err
	}
	return true, syncIncidentMigrationState(ctx, s.store, s.orch, s.audit, tenantID, updated)
}

func decodeMigrationReceiptClaim(destination string, payload []byte) (migrationReceiptClaim, bool, error) {
	var claim migrationReceiptClaim
	switch destination {
	case relay.KindTrustDistribute:
		var intent relay.TrustDistributionIntent
		if err := json.Unmarshal(payload, &intent); err != nil {
			return claim, true, fmt.Errorf("server: decode migration trust claim: %w", err)
		}
		claim = migrationReceiptClaim{runID: intent.RunID, waveID: intent.WaveID, identityID: intent.IdentityID, trust: &intent}
		switch intent.Operation {
		case relay.TrustInstall:
			claim.stage = migration.StageTrust
		case relay.TrustRemove:
			claim.stage = migration.StageRollbackTrust
		default:
			return claim, true, errors.New("server: migration trust claim has an unsupported operation")
		}
	case relay.KindEndpointRenew:
		var intent RelayDeployIntent
		if err := json.Unmarshal(payload, &intent); err != nil {
			return claim, false, nil
		}
		if strings.TrimSpace(intent.MigrationRunID) == "" {
			return claim, false, nil
		}
		claim = migrationReceiptClaim{
			runID: intent.MigrationRunID, waveID: intent.MigrationWaveID,
			identityID: intent.IdentityID, stage: migration.StageSuccessor, renew: &intent,
		}
	case relay.KindConnectorRollback:
		var intent relay.RollbackIntent
		if err := json.Unmarshal(payload, &intent); err != nil {
			return claim, false, nil
		}
		if strings.TrimSpace(intent.MigrationRunID) == "" {
			return claim, false, nil
		}
		claim = migrationReceiptClaim{
			runID: intent.MigrationRunID, waveID: intent.MigrationWaveID,
			identityID: intent.IdentityID, stage: migration.StageRollbackSuccessor, rollback: &intent,
		}
	default:
		return claim, false, nil
	}
	if strings.TrimSpace(claim.runID) == "" || strings.TrimSpace(claim.waveID) == "" ||
		strings.TrimSpace(claim.identityID) == "" {
		return claim, true, errors.New("server: migration claim omits run, wave, or identity")
	}
	return claim, true, nil
}

func validateVerifiedMigrationReport(
	claim migrationReceiptClaim,
	outcome, report, evidenceDigest string,
	obs *migration.Observation,
) error {
	switch claim.stage {
	case migration.StageTrust, migration.StageRollbackTrust:
		if outcome != transport.JobOutcomeExecuted {
			return errors.New("server: trust mutation did not report its closed executed outcome")
		}
		var observed relay.TrustDistributionReport
		if err := json.Unmarshal([]byte(report), &observed); err != nil {
			return errors.New("server: signed trust result is not a typed report")
		}
		if observed.RunID != claim.runID || observed.WaveID != claim.waveID ||
			observed.IdentityID != claim.identityID || observed.Verdict != relay.TrustVerified ||
			claim.trust == nil || observed.Operation != claim.trust.Operation ||
			cleanFingerprint(observed.ObservedFingerprint) != cleanFingerprint(claim.trust.AnchorFingerprint) ||
			crypto.SHA256Hex([]byte(report)) != strings.ToLower(strings.TrimSpace(evidenceDigest)) {
			return errors.New("server: signed trust result does not match the immutable claim")
		}
	case migration.StageSuccessor, migration.StageRollbackSuccessor:
		if outcome != transport.JobOutcomeVerified {
			return errors.New("server: migration leaf action lacks a verified listener outcome")
		}
		var observed relay.EndpointVerifyReport
		if err := json.Unmarshal([]byte(report), &observed); err != nil || len(observed.Results) != 1 {
			return errors.New("server: signed migration leaf result is not one typed verification")
		}
		result := observed.Results[0]
		if !result.Transcript.Reached || result.Transcript.Mismatch != "" ||
			result.Transcript.Digest() != strings.ToLower(strings.TrimSpace(evidenceDigest)) {
			return errors.New("server: migration listener transcript is not a verified signed observation")
		}
		if claim.stage == migration.StageSuccessor {
			if claim.renew == nil || result.EndpointID != claim.renew.TargetID ||
				cleanFingerprint(result.Transcript.ExpectedFingerprint) != cleanFingerprint(result.Transcript.ObservedFingerprint) {
				return errors.New("server: successor listener result does not match the renewal target")
			}
			obs.SuccessorFingerprint = cleanFingerprint(result.Transcript.ObservedFingerprint)
			if obs.SuccessorFingerprint == "" {
				return errors.New("server: successor verification carries no observed fingerprint")
			}
		} else if claim.rollback == nil || result.EndpointID != claim.rollback.TargetID ||
			cleanFingerprint(result.Transcript.ExpectedFingerprint) != cleanFingerprint(claim.rollback.PredecessorFingerprint) ||
			cleanFingerprint(result.Transcript.ObservedFingerprint) != cleanFingerprint(claim.rollback.PredecessorFingerprint) {
			return errors.New("server: rollback listener result does not show the predecessor")
		}
	default:
		return errors.New("server: unsupported migration receipt stage")
	}
	return nil
}

func validateMigrationClaimBinding(binding migration.MemberBinding, agentID string, claim migrationReceiptClaim) error {
	if binding.RequiredAgentID != agentID {
		return errors.New("server: migration result came from an agent outside the immutable member binding")
	}
	switch {
	case claim.trust != nil:
		intent := claim.trust
		if intent.RequiredAgentID != binding.RequiredAgentID || intent.AnchorPath != binding.TrustAnchorPath ||
			cleanFingerprint(intent.AnchorFingerprint) != cleanFingerprint(binding.TrustAnchorFingerprint) ||
			!bytes.Equal(intent.AnchorPEM, binding.TrustAnchorPEM) {
			return errors.New("server: trust claim drifted from the migration member binding")
		}
	case claim.renew != nil:
		intent := claim.renew
		switch {
		case intent.IssuingAuthorityID != binding.IssuingAuthorityID:
			return errors.New("server: renewal claim drifted from the migration issuing authority")
		case intent.RequiredAgentID != binding.RequiredAgentID:
			return errors.New("server: renewal claim drifted from the migration agent binding")
		case intent.TargetID != binding.TargetID || intent.Revision != binding.TargetRevision:
			return errors.New("server: renewal claim drifted from the migration target revision")
		case intent.Connector != binding.Connector || intent.Target != binding.Target:
			return errors.New("server: renewal claim drifted from the migration route binding")
		case intent.VerifyAddress != binding.VerifyAddress || intent.VerifyServerName != binding.VerifyServerName:
			return errors.New("server: renewal claim drifted from the migration verification binding")
		case intent.PredecessorCertificateID != binding.PredecessorCertificateID:
			return errors.New("server: renewal claim drifted from the migration predecessor binding")
		case !sameMigrationJSON(intent.TargetConfig, binding.TargetConfig):
			return errors.New("server: renewal claim drifted from the migration target configuration")
		}
	case claim.rollback != nil:
		intent := claim.rollback
		if intent.RequiredAgentID != binding.RequiredAgentID || intent.TargetID != binding.TargetID ||
			intent.Connector != binding.Connector || intent.Target != binding.Target ||
			cleanFingerprint(intent.PredecessorFingerprint) != cleanFingerprint(binding.PredecessorFingerprint) ||
			(strings.TrimSpace(intent.SuccessorFingerprint) != "" &&
				cleanFingerprint(intent.SuccessorFingerprint) != cleanFingerprint(binding.SuccessorFingerprint)) ||
			!sameMigrationJSON(intent.TargetConfig, binding.TargetConfig) {
			return errors.New("server: rollback claim drifted from the migration member binding")
		}
	default:
		return errors.New("server: migration receipt has no typed claim")
	}
	return nil
}

func cleanFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "sha256:")
	return strings.ReplaceAll(value, ":", "")
}

// sameMigrationJSON compares the meaning of a retained target config, not its
// object-key order. PostgreSQL jsonb deliberately normalizes object storage, so
// byte comparison would reject an unchanged config after the first projection.
func sameMigrationJSON(left, right json.RawMessage) bool {
	var l, r any
	if json.Unmarshal(left, &l) != nil || json.Unmarshal(right, &r) != nil {
		return false
	}
	lc, lerr := json.Marshal(l)
	rc, rerr := json.Marshal(r)
	return lerr == nil && rerr == nil && bytes.Equal(lc, rc)
}
