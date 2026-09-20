// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/eventspec"
)

// TypeRevocationEffectRecorded is the AN-2 event type appended when a revocation
// job's effect is performed and its signed completion evidence recorded (§7.3 /
// INV-A9). It is a NEW event type owned by this cascade (the AGID-01 delegation event
// set is closed to the four lifecycle types); a projector that does not know it skips
// it (forward-compatible). Dotted-lowercase per repo convention.
const TypeRevocationEffectRecorded = "agent.revocation.effect"

// RevocationEffectSchemaV1 is the baseline payload-shape version for the effect event.
const RevocationEffectSchemaV1 = 1

// appendEvidenceEvent appends the signed completion evidence for a job to the AN-2
// log durable-first. The event payload is the signed evidence (body fields +
// signature + public key), so the evidence is replayable and offline-verifiable from
// the ledger alone. It is appended AFTER the effect row commits, so the effect row is
// the idempotency guard and a retried job re-appends the same evidence without a
// second effect (harmless; the terminal gate reads effect rows, not events).
func (e *Executor) appendEvidenceEvent(ctx context.Context, p JobPayload, evidence CompletionEvidence, _ []byte) error {
	data, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("revoke: marshal completion-evidence event: %w", err)
	}
	_, err = e.log.Append(ctx, eventspec.Event{
		Type:          TypeRevocationEffectRecorded,
		TenantID:      p.TenantID,
		SchemaVersion: RevocationEffectSchemaV1,
		Data:          data,
	})
	if err != nil {
		return fmt.Errorf("revoke: append completion-evidence event: %w", err)
	}
	return nil
}

// recordEffectTx records a job's effect + signed completion evidence on the caller's
// tx via the AGID-02 store's conditional insert, and reports whether it inserted. It
// is the thin bridge from the executor's per-effect values to the store row; the
// store's WHERE-NOT-EXISTS insert is the at-most-one-per-key guard (AGID-claim-21).
func recordEffectTx(ctx context.Context, tx pgx.Tx, p JobPayload, idempotencyKey string, effect EffectClass, executor string, completedAt int64, body, sig, pub []byte) (bool, error) {
	return agidstore.RecordEffectIfAbsentTx(ctx, tx, agidstore.RevocationEffect{
		DirectiveID:    p.DirectiveID,
		IdempotencyKey: idempotencyKey,
		CredentialID:   p.CredentialID,
		EffectClass:    string(effect),
		Executor:       executor,
		CompletedAt:    completedAt,
		EvidenceBody:   body,
		EvidenceSig:    sig,
		EvidencePub:    pub,
	})
}

// LoadEvidence reads the recorded completion evidence for one job (directive,
// idempotency key) back from the store and reconstructs the verifiable
// CompletionEvidence. found is false when the job has not been evidenced yet. It is
// how AGID-11's terminal gate (and tests) read + verify the per-job proof.
func LoadEvidence(ctx context.Context, repo *agidstore.Repo, tenantID, directiveID, idempotencyKey string) (CompletionEvidence, bool, error) {
	eff, found, err := repo.FetchEffect(ctx, tenantID, directiveID, idempotencyKey)
	if err != nil || !found {
		return CompletionEvidence{}, found, err
	}
	ev, err := decodeCompletionEvidence(eff.EvidenceBody, eff.EvidenceSig, eff.EvidencePub)
	if err != nil {
		return CompletionEvidence{}, true, err
	}
	return ev, true, nil
}
