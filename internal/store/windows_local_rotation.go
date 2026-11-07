// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/hostaccounts"
)

var ErrWindowsLocalRotationNotFound = errors.New("store: native local account rotation not found")

type WindowsLocalRotationObservation struct {
	JobID             int64                       `json:"job_id"`
	Attempt           int                         `json:"attempt"`
	Report            hostaccounts.RotationReport `json:"report"`
	EvidenceDigest    string                      `json:"evidence_digest"`
	ReceiptStatement  string                      `json:"receipt_statement"`
	ReceiptSignature  string                      `json:"receipt_signature_base64"`
	SignerFingerprint string                      `json:"signer_fingerprint"`
	At                time.Time                   `json:"at"`
}
type WindowsLocalRotation struct {
	Intent          hostaccounts.RotationIntent      `json:"intent"`
	PreparedEventID string                           `json:"prepared_event_id"`
	PreparedAt      time.Time                        `json:"prepared_at"`
	OutboxID        *int64                           `json:"outbox_id,omitempty"`
	ObservedEventID string                           `json:"observed_event_id"`
	Observation     *WindowsLocalRotationObservation `json:"observation,omitempty"`
}

const windowsLocalRotationColumns = `intent,prepared_event_id,prepared_at,outbox_id,observed_event_id,observation`

func scanWindowsLocalRotation(row pgx.Row) (WindowsLocalRotation, error) {
	var v WindowsLocalRotation
	var intent, observation []byte
	e := row.Scan(&intent, &v.PreparedEventID, &v.PreparedAt, &v.OutboxID, &v.ObservedEventID, &observation)
	if errors.Is(e, pgx.ErrNoRows) {
		return v, ErrWindowsLocalRotationNotFound
	}
	if e != nil {
		return v, e
	}
	if e = json.Unmarshal(intent, &v.Intent); e != nil {
		return v, e
	}
	if e = v.Intent.Validate(); e != nil {
		return v, e
	}
	if len(observation) > 0 {
		v.Observation = new(WindowsLocalRotationObservation)
		if e = json.Unmarshal(observation, v.Observation); e != nil {
			return v, e
		}
		if e = v.Observation.Report.Validate(v.Intent); e != nil {
			return v, e
		}
	}
	return v, nil
}
func (s *Store) GetWindowsLocalRotation(ctx context.Context, tenantID, id string) (WindowsLocalRotation, error) {
	var v WindowsLocalRotation
	e := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var e error
		v, e = scanWindowsLocalRotation(tx.QueryRow(ctx, "SELECT "+windowsLocalRotationColumns+" FROM windows_local_account_rotations WHERE tenant_id=$1 AND id=$2", tenantID, id))
		return e
	})
	return v, e
}
func (s *Store) LatestWindowsLocalRotation(ctx context.Context, tenantID, agentID, sid string) (WindowsLocalRotation, error) {
	var v WindowsLocalRotation
	e := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var e error
		v, e = scanWindowsLocalRotation(tx.QueryRow(ctx, "SELECT "+windowsLocalRotationColumns+" FROM windows_local_account_rotations WHERE tenant_id=$1 AND agent_id=$2 AND account_sid=$3 ORDER BY prepared_at DESC,id DESC LIMIT 1", tenantID, agentID, sid))
		return e
	})
	return v, e
}
func (s *Store) LatestCompleteWindowsLocalAccountScan(ctx context.Context, tenantID, agentID string) (WindowsLocalAccountScan, error) {
	var v WindowsLocalAccountScan
	e := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var e error
		v, e = scanWindowsLocalAccountScan(tx.QueryRow(ctx, "SELECT "+windowsLocalScanColumns+" FROM windows_local_account_scans WHERE tenant_id=$1 AND agent_id=$2 AND status='complete' ORDER BY queued_at DESC,id DESC LIMIT 1", tenantID, agentID))
		return e
	})
	return v, e
}
func WindowsLocalRotationOutboxKey(epoch, id string) string {
	return hostaccounts.RotationDestination + ":" + epoch + ":" + id
}

// ApplyWindowsLocalRotationPreparedTx is called in the prepared phase's exact
// transaction. The sealed values remain on the static command; the host queue
// contains only public authority and is pinned to its one host role/identity.
func (s *Store) ApplyWindowsLocalRotationPreparedTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, i hostaccounts.RotationIntent, at time.Time) error {
	if i.Validate() != nil || i.TenantID != tenantID || eventID == "" || at.IsZero() {
		return ErrIdempotencyConflict
	}
	cmd, e := scanSecretStaticRotationCommand(tx.QueryRow(ctx, "SELECT "+secretStaticRotationColumns+" FROM secret_static_rotation_commands WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenantID, i.RotationID))
	if e != nil {
		return e
	}
	if len(cmd.SealedPreparation) == 0 || len(cmd.SealedOld) == 0 || len(cmd.ProviderBinding) != 64 || !cmd.SinglePhaseAcknowledged || cmd.DependentChangeID != "" || cmd.CloudChangeID != "" {
		return errors.New("store: native local rotation has no sealed prepared authority")
	}
	// Serialize authority for the SID across provider aliases and secret roles.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "native-local-account:"+tenantID+":"+i.AgentID+":"+i.Native.Account.SID); e != nil {
		return e
	}
	previous, e := scanWindowsLocalRotation(tx.QueryRow(ctx, "SELECT "+windowsLocalRotationColumns+" FROM windows_local_account_rotations WHERE tenant_id=$1 AND agent_id=$2 AND account_sid=$3 ORDER BY prepared_at DESC,id DESC LIMIT 1 FOR UPDATE", tenantID, i.AgentID, i.Native.Account.SID))
	if e == nil && previous.Intent.RotationID != i.RotationID {
		var phase string
		if e = tx.QueryRow(ctx, `SELECT phase FROM secret_static_rotation_commands WHERE tenant_id=$1 AND id=$2`, tenantID, previous.Intent.RotationID).Scan(&phase); e != nil {
			return e
		}
		if previous.Observation == nil || previous.Observation.Report.Status != "succeeded" || phase != SecretStaticRotationCompleted || i.PredecessorGenerationID != previous.Intent.RotationID {
			return errors.New("store: another native local generation is unresolved or its predecessor differs")
		}
	} else if errors.Is(e, ErrWindowsLocalRotationNotFound) {
		if i.PredecessorGenerationID != "" {
			return errors.New("store: native local predecessor is absent")
		}
	} else if e != nil {
		return e
	}
	raw, e := json.Marshal(i)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO windows_local_account_rotations(tenant_id,id,agent_id,account_sid,intent,prepared_event_id,prepared_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7) ON CONFLICT(tenant_id,id) DO NOTHING`, tenantID, i.RotationID, i.AgentID, i.Native.Account.SID, raw, eventID, at)
	if e != nil {
		return e
	}
	saved, e := scanWindowsLocalRotation(tx.QueryRow(ctx, "SELECT "+windowsLocalRotationColumns+" FROM windows_local_account_rotations WHERE tenant_id=$1 AND id=$2", tenantID, i.RotationID))
	if e != nil {
		return e
	}
	if saved.Intent != i || saved.PreparedEventID != eventID || !saved.PreparedAt.Equal(at) {
		return ErrIdempotencyConflict
	}
	if saved.Observation != nil && saved.Observation.Report.Status == "succeeded" || cmd.Phase != SecretStaticRotationPrepared {
		return nil
	}
	id, e := ensureSecretIntegrationOutboxTx(ctx, tx, tenantID, hostaccounts.RotationDestination, "windows-local-host:"+i.AgentID, WindowsLocalRotationOutboxKey(cmd.TenantEpoch, i.RotationID), raw)
	if e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE outbox SET required_agent_role='host',required_agent_id=$3 WHERE tenant_id=$1 AND id=$2 AND (required_agent_role IS NULL OR required_agent_role='' OR required_agent_role='host') AND (required_agent_id IS NULL OR required_agent_id=$3)`, tenantID, id, i.AgentID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	_, e = tx.Exec(ctx, `UPDATE windows_local_account_rotations SET outbox_id=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, i.RotationID, id)
	return e
}
func (s *Store) ApplyWindowsLocalRotationObservedTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, o WindowsLocalRotationObservation) error {
	v, e := scanWindowsLocalRotation(tx.QueryRow(ctx, "SELECT "+windowsLocalRotationColumns+" FROM windows_local_account_rotations WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenantID, o.Report.RotationID))
	if e != nil {
		return e
	}
	if o.Report.Validate(v.Intent) != nil || o.JobID <= 0 || o.Attempt <= 0 || o.At.IsZero() {
		return ErrIdempotencyConflict
	}
	if v.ObservedEventID == eventID {
		return nil
	}
	// A later refusal proves no new effect in that attempt. It cannot erase an
	// earlier unknown effect or a completed generation's authentication proof.
	if v.Observation != nil && (v.Observation.Report.Status == "succeeded" || v.Observation.Report.Status == "uncertain" && o.Report.Status == "refused") {
		return nil
	}
	// Receipt job IDs are historical signed facts. Rebuilding the projection
	// may allocate a new operational delivery ID; the live ingestion gate
	// already checked exact holdership before this immutable event was appended.
	raw, e := json.Marshal(o)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE windows_local_account_rotations SET observed_event_id=$3,observation=$4::jsonb WHERE tenant_id=$1 AND id=$2`, tenantID, o.Report.RotationID, eventID, raw)
	if e != nil {
		return e
	}
	if v.OutboxID != nil {
		// A recreated, unclaimed operational row needs no new native execution.
		// Never steal a live host lease while applying retained receipt evidence.
		if _, e = tx.Exec(ctx, `UPDATE outbox SET status='delivered',delivered_at=COALESCE(delivered_at,$3),worker_id=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2 AND status='pending' AND delivered_at IS NULL AND claimed_by_agent_id IS NULL`, tenantID, *v.OutboxID, o.At); e != nil {
			return e
		}
	}
	detail := ""
	if o.Report.Status != "succeeded" {
		detail = "native host " + o.Report.Status + ": " + o.Report.Failure + "; sealed generation retained; recovery required"
	}
	_, e = tx.Exec(ctx, `UPDATE secret_static_rotation_commands SET error=$3 WHERE tenant_id=$1 AND id=$2 AND phase='prepared'`, tenantID, o.Report.RotationID, detail)
	if e != nil || o.Report.Status != "succeeded" {
		return e
	}
	// The existing static worker resumes promptly from its budget-neutral wait.
	_, e = tx.Exec(ctx, `UPDATE outbox o SET next_attempt_at=LEAST(o.next_attempt_at,$3) FROM secret_static_rotation_commands c WHERE c.tenant_id=$1 AND c.id=$2 AND o.tenant_id=$1 AND o.id=c.outbox_id AND o.destination='secret.static-rotation' AND o.status='pending'`, tenantID, o.Report.RotationID, o.At)
	return e
}
