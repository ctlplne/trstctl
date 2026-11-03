// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rehearsal"
)

// The two rehearsal modes that touch real records (A247). A live observation
// runs nothing: it reads what production recorded — the latest signed restore
// drill. A sandbox execution runs a
// step for real against a target the guard has already shown is
// non-production, with nothing read from the secret store. A step the mode has
// no reader or executor for is reported, and the run is blocked rather than
// passed.

// rehearsalLive observes each step from production's own records.
func (a *API) rehearsalLive(ctx context.Context, tenantID string, sc rehearsalScenarioResponse) ([]rehearsal.Observation, []rehearsal.Unsupported, error) {
	var observations []rehearsal.Observation
	var unsupported []rehearsal.Unsupported
	for i, s := range sc.Steps {
		step := i + 1
		switch s.Action {
		case "restore_backup_into_isolated_target":
			effect, receipt, reason, err := a.observeLatestRestoreDrill(ctx, tenantID)
			if err != nil {
				return nil, nil, err
			}
			if reason != "" {
				unsupported = append(unsupported, rehearsal.Unsupported{Step: step, Reason: reason})
				continue
			}
			observations = append(observations, rehearsal.Observation{Step: step, Effect: effect, Source: rehearsal.SourceLiveReceipt, Receipt: receipt})
		default:
			unsupported = append(unsupported, rehearsal.Unsupported{Step: step, Reason: "no live reader for " + s.Action + " yet"})
		}
	}
	return observations, unsupported, nil
}

// observeLatestRestoreDrill reads the newest signed restore-drill attestation
// and verifies its signature. A drill that restored and read its events back
// is observed as restored_and_read_back.
func (a *API) observeLatestRestoreDrill(ctx context.Context, tenantID string) (effect, receipt, unsupported string, err error) {
	if a.restoreDrillKeys == nil {
		return "", "", "restore-drill verification keys are not configured", nil
	}
	rows, err := a.store.ListAttestationsByKind(ctx, tenantID, projections.RestoreDrillAttestationKind, 1)
	if err != nil {
		return "", "", "", err
	}
	if len(rows) == 0 {
		return "no_drill_recorded", "", "", nil
	}
	var evidence backup.SignedDrillEvidence
	if err := json.Unmarshal(rows[0].Evidence, &evidence); err != nil {
		return "", "", "", err
	}
	if err := backup.VerifyDrillEvidence(evidence, a.restoreDrillKeys); err != nil {
		return "", "", "", fmt.Errorf("restore-drill evidence %s does not verify: %w", rows[0].ID, err)
	}
	att := evidence.Attestation
	effect = "restore_" + string(att.Outcome)
	if att.Outcome == backup.DrillRestored && att.EventsVerified > 0 && att.EventsVerified == att.EventsRestored {
		effect = "restored_and_read_back"
	}
	return effect, "attestation:" + rows[0].ID, "", nil
}

// rehearsalSandbox runs each step against a non-production target.
func (a *API) rehearsalSandbox(ctx context.Context, tenantID, runID string, sc rehearsalScenarioResponse) ([]rehearsal.Observation, []rehearsal.Unsupported, error) {
	var observations []rehearsal.Observation
	var unsupported []rehearsal.Unsupported
	for i, s := range sc.Steps {
		step := i + 1
		switch {
		case s.Action == "repeat_request_with_same_key" && s.Target != "" && a.idem != nil:
			effect, receipt, err := a.rehearseRetry(ctx, tenantID, fmt.Sprintf("rehearsal:%s:%d", runID, step), s.Target)
			if err != nil {
				return nil, nil, err
			}
			observations = append(observations, rehearsal.Observation{Step: step, Effect: effect, Source: rehearsal.SourceSandboxReceipt, Receipt: receipt})
		default:
			unsupported = append(unsupported, rehearsal.Unsupported{Step: step, Reason: "no sandbox executor for " + s.Action + " yet"})
		}
	}
	return observations, unsupported, nil
}

// rehearseRetry runs the target's dry-run test twice through the production
// idempotency layer with one key, as a client retrying would: one effect and
// the same answer twice is one_effect.
func (a *API) rehearseRetry(ctx context.Context, tenantID, key, targetID string) (effect, receipt string, err error) {
	effects := 0
	run := func(ctx context.Context) ([]byte, error) {
		effects++
		_, response, err := a.runConnectorTargetTest(ctx, tenantID, targetID, key)
		if err != nil {
			return nil, err
		}
		return json.Marshal(response)
	}
	first, err := a.idem.Do(ctx, tenantID, key, run)
	if err != nil {
		return "", "", err
	}
	second, err := a.idem.Do(ctx, tenantID, key, run)
	if err != nil {
		return "", "", err
	}
	switch {
	case effects == 1 && bytes.Equal(first, second):
		effect = "one_effect"
	case effects == 1:
		effect = "one_effect_different_answer"
	default:
		effect = fmt.Sprintf("%d_effects", effects)
	}
	return effect, "idempotency:" + key, nil
}
